/*
Implement the ESO Provider.
*/
package privx

import (
	"context"
	"errors"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/api/vault"
	"github.com/SSHcom/privx-sdk-go/oauth"
	privxapi "github.com/SSHcom/privx-sdk-go/restapi"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	v1 "github.com/external-secrets/external-secrets/apis/meta/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var ErrNotImplemented = errors.New("not implemented")
var ErrInvalidJson = errors.New("invalid JSON")

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
	if privx.Auth == nil {
		return nil, ErrNoStoreAuth{Field: "spec.provider.privx.auth"}
	}
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
