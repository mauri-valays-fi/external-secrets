/*
Implement the ESO Provider.
*/
package privx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/SSHcom/privx-sdk-go/v2/api/vault"
	"github.com/SSHcom/privx-sdk-go/v2/oauth"
	privxapi "github.com/SSHcom/privx-sdk-go/v2/restapi"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	v1 "github.com/external-secrets/external-secrets/apis/meta/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	ErrNotImplemented             = errors.New("not implemented")
	ErrInvalidJson                = errors.New("invalid JSON")
	ErrInvalidJWT                 = errors.New("failed to decode JWT")
	ErrEmptyAudience              = errors.New("audience is empty")
	ErrReadNamespace              = errors.New("failed to read namespace")
	ErrReadServiceAccount         = errors.New("failed to read serviceaccount name")
	ErrInClusterConfig            = errors.New("failed to create in-cluster config")
	ErrKubernetesClient           = errors.New("failed to create kubernetes client")
	ErrCreateToken                = errors.New("failed to create serviceaccount token")
	ErrEmptyReturnedToken         = errors.New("empty token returned")
	ErrInvalidJWTFormat           = errors.New("invalid jwt format")
	ErrDecodeJWTPayload           = errors.New("failed to decode jwt payload")
	ErrParseJWTPayload            = errors.New("failed to parse jwt payload json")
	ErrServiceAccountNameNotFound = errors.New("serviceaccount name not found in jwt claims")
)

type ErrNoStoreAuth struct {
	Field string
}

func (e ErrNoStoreAuth) Error() string {
	if e.Field == "" {
		return "no PrivX authorisation from SecretStore definition"
	}
	return fmt.Sprintf("no PrivX authorisation from SecretStore definition (missing %s)", e.Field)
}

// Check during compile that we implement the interface.
var _ esv1.Provider = (*Provider)(nil)

// Provider implements the ESO Provider interface for PrivX.
type Provider struct {
}

// readSecretValue gets a Kubernetes Secret as a string.
func readSecretValue(
	ctx context.Context,
	client kclient.Client,
	namespace string,
	ref v1.SecretKeySelector,
) (string, error) {

	var secret corev1.Secret
	if err := client.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      ref.Name,
	}, &secret); err != nil {
		return "", err
	}

	b, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s missing key %q", namespace, ref.Name, ref.Key)
	}

	// logger := log.FromContext(ctx)
	// logger.Info("Secret value for debugging", "key", ref.Key, "value", string(b))

	return string(b), nil
}

// privxAuth creates authentication from information in the Store specification.
func privxAuth(
	ctx context.Context,
	kube kclient.Client,
	namespace string,
	privxSpec *esv1.PrivxProvider,
) (privxapi.Authorizer, error) {

	auth := privxapi.New(
		privxapi.BaseURL(privxSpec.Host),
	)

	if privxSpec.Auth != nil &&
		privxSpec.Auth.OAuth != nil {
		// OAuth tokens given, use them

		// apiClientIdRef:
		// privx_api_client_id

		clientID, err := readSecretValue(
			ctx,
			kube,
			namespace,
			privxSpec.Auth.OAuth.ApiClientIDRef,
		)
		if err != nil {
			return nil, err
		}

		// apiClientSecretRef:
		// privx_api_client_secret
		clientSecret, err := readSecretValue(
			ctx,
			kube,
			namespace,
			privxSpec.Auth.OAuth.ApiClientSecretRef,
		)
		if err != nil {
			return nil, err
		}

		// clientIdRef:
		// privx_api_oauth_client_id
		oAuthAccess, err := readSecretValue(
			ctx,
			kube,
			namespace,
			privxSpec.Auth.OAuth.ClientIDRef,
		)
		if err != nil {
			return nil, err
		}

		// clientSecretRef:
		// privx_api_oauth_client_secret
		oAuthSecret, err := readSecretValue(
			ctx,
			kube,
			namespace,
			privxSpec.Auth.OAuth.ClientSecretRef,
		)
		if err != nil {
			return nil, err
		}

		return oauth.With(
			auth,
			oauth.Access(clientID),
			oauth.Secret(clientSecret),
			oauth.Digest(oAuthAccess, oAuthSecret),
		), nil
	}

	// No OAuth tokens, use JWT
	// "may not specify a duration less than 10 minutes"
	token, err := getAudienceJWTFromPod(ctx, privxSpec.Host, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	logger := log.FromContext(ctx)
	decoded, err := decodeJWT(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJWT, err)
	}

	logger.Info("JWT payload", "claims", decoded)

	return oauth.WithToken("Bearer " + token), nil
}

// privxAPI creates a working PrivX API connection from information in the Store specification.
func privxAPI(
	ctx context.Context,
	kube kclient.Client,
	namespace string,
	privxSpec *esv1.PrivxProvider,
) (privxapi.Connector, error) {

	auth, err := privxAuth(ctx, kube, namespace, privxSpec)
	if err != nil {
		return nil, err
	}

	return privxapi.New(
		privxapi.BaseURL(privxSpec.Host),
		privxapi.Auth(auth),
	), nil
}

// NewClient returns a new PrivX Client.
func (p *Provider) NewClient(
	ctx context.Context,
	store esv1.GenericStore,
	kube kclient.Client,
	namespace string,
) (esv1.SecretsClient, error) {

	config := store.GetSpec().Provider.PrivX
	conn, err := privxAPI(ctx, kube, namespace, config)
	if err != nil {
		return nil, err
	}

	client := SecretsClient{
		conn:              conn,
		vault:             vault.New(conn),
		store:             store,
		kube:              kube,
		namespace:         namespace,
		defaultReadRoles:  config.DefaultReadRoles,
		defaultWriteRoles: config.DefaultWriteRoles,
	}
	return &client, nil
}

func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {

	if store.GetSpec().Provider == nil {
		return nil, ErrNoStoreAuth{Field: "spec.provider"}
	}
	provider := store.GetSpec().Provider
	if provider.PrivX == nil {
		return nil, ErrNoStoreAuth{Field: "spec.provider.privx"}
	}

	privx := provider.PrivX

	// with JWT, no auth fields necessary
	// if privx.Auth == nil {
	// 	return nil, ErrNoStoreAuth{Field: "spec.provider.privx.auth"}
	// }

	if privx.Host == "" {
		return nil, ErrNoStoreAuth{Field: "spec.provider.privx.host"}
	}

	return nil, nil
}

func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// NewProvider creates a new Provider instance.
func NewProvider() esv1.Provider {
	return &Provider{}
}

// ProviderSpec returns the provider specification for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		PrivX: &esv1.PrivxProvider{},
	}
}

// MaintenanceStatus returns the maintenance status of the provider.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}

// getJWTFromPod reads the ServiceAccount JWT mounted into every pod by Kubernetes.
func getJWTFromPod() (string, error) {

	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("read serviceaccount token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// getServiceAccountNameFromJWT extracts the ServiceAccount name from a Kubernetes SA JWT.
func getServiceAccountNameFromJWT(jwtStr string) (string, error) {
	jwtStr = strings.TrimSpace(jwtStr)

	parts := strings.Split(jwtStr, ".")
	if len(parts) < 2 {
		return "", ErrInvalidJWTFormat
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDecodeJWTPayload, err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return "", fmt.Errorf("%w: %w", ErrParseJWTPayload, err)
	}

	// Preferred claim in Kubernetes projected service account tokens.
	if v, ok := claims["kubernetes.io/serviceaccount/service-account.name"].(string); ok && v != "" {
		return v, nil
	}

	// Fallback: sub = system:serviceaccount:<namespace>:<name>
	if sub, ok := claims["sub"].(string); ok && strings.HasPrefix(sub, "system:serviceaccount:") {
		// Format: system:serviceaccount:ns:name
		subParts := strings.Split(sub, ":")
		if len(subParts) >= 4 && subParts[3] != "" {
			return subParts[3], nil
		}
	}

	return "", ErrServiceAccountNameNotFound
}

// getAudienceJWTFromPod requests a bound ServiceAccount token with a custom audience.
func getAudienceJWTFromPod(ctx context.Context, audience string, expiration time.Duration) (string, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return "", ErrEmptyAudience
	}

	nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrReadNamespace, err)
	}
	namespace := strings.TrimSpace(string(nsBytes))

	// Get a token (wrong aud field though)
	jwtStr, err := getJWTFromPod()
	if err != nil {
		return "", err
	}

	// Extract the service account name from that generic token
	saName, err := getServiceAccountNameFromJWT(jwtStr)
	if err != nil {
		return "", err
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInClusterConfig, err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrKubernetesClient, err)
	}

	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: ptr.To(int64(expiration.Seconds())),
		},
	}

	tr, err := clientset.CoreV1().
		ServiceAccounts(namespace).
		CreateToken(ctx, saName, req, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCreateToken, err)
	}

	token := strings.TrimSpace(tr.Status.Token)
	if token == "" {
		return "", ErrEmptyReturnedToken
	}

	return token, nil
}

// decodeJWT returns the decoded JWT payload as pretty JSON.
func decodeJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}

	var obj any
	if err := json.Unmarshal(payloadBytes, &obj); err != nil {
		return "", fmt.Errorf("unmarshal payload: %w", err)
	}

	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal indent: %w", err)
	}

	return string(pretty), nil
}
