package privx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	v1 "github.com/external-secrets/external-secrets/apis/meta/v1"
	jwt "github.com/golang-jwt/jwt/v5"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// CreateSignedJWT_RS256 creates a JWT signed with an RSA private key read from a Kubernetes Secret.
// - privateKeyRef must point to a PEM-encoded RSA key (PKCS#1 or PKCS#8) stored in Secret.Data[ref.Key].
// - aud is written as a JSON string (not an array) by using MapClaims.
// - extraClaims are merged into the token claims (cannot overwrite reserved keys unless you do it explicitly).
func createSignedJWT_RS256(
	ctx context.Context,
	client kclient.Client,
	namespace string,
	privateKeyRef v1.SecretKeySelector,
	issuer string,
	subject string,
	audience string,
	ttl time.Duration,
	extraClaims map[string]any,
) (string, error) {
	// Read PEM from Kubernetes Secret
	pemStr, err := readSecretValue(ctx, client, namespace, privateKeyRef)
	if err != nil {
		return "", fmt.Errorf("read private key from secret: %w", err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemStr))
	if err != nil {
		return "", fmt.Errorf("parse RSA private key: %w", err)
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"aud": audience, // IMPORTANT: string (not []string)
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}

	// Merge extra claims (skip reserved keys by default).
	for k, v := range extraClaims {
		if _, reserved := claims[k]; reserved {
			continue
		}
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
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
