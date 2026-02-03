/*
Implement the ESO SecretsClient
*/

package privx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/SSHcom/privx-sdk-go/api/vault"
	privxapi "github.com/SSHcom/privx-sdk-go/restapi"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	corev1 "k8s.io/api/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrNoName = errors.New("No name provided for secret")

// Check during compile that we implement the interface
var _ esv1.SecretsClient = (*SecretsClient)(nil)

// SecretsClient provides access to PrivX secrets.
type SecretsClient struct {
	conn      privxapi.Connector
	vault     *vault.Vault // PrivX Vault instance
	store     esv1.GenericStore
	kube      kclient.Client
	namespace string
}

// GetSecret returns a single secret from the provider.
func (c *SecretsClient) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {

	secret, error := c.vault.Secret(ref.Key)
	if error != nil {
		return nil, error
	} else {
		data := secret.Data
		if !json.Valid(data) {
			return nil, ErrInvalidJson
		}
		return data, nil
	}
}

// PushSecret will write a single secret into PrivX.
func (c *SecretsClient) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {

	// Secret fields:
	// 	metav1.TypeMeta `json:",inline"`
	// 	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// 	Immutable *bool `json:"immutable,omitempty" protobuf:"varint,5,opt,name=immutable"`
	// 	Data map[string][]byte `json:"data,omitempty" protobuf:"bytes,2,rep,name=data"`
	// 	StringData map[string]string `json:"stringData,omitempty" protobuf:"bytes,4,rep,name=stringData"`
	// 	Type SecretType `json:"type,omitempty" protobuf:"bytes,3,opt,name=type,casttype=SecretType"`

	if secret.Name == "" {
		return ErrNoName
	}

	// TODO:
	//	- when given string values, do I need to convert them to base64 before writing to PrivX ? Or is that done on reading?
	// PrivX

	//	func (vault *Vault) CreateSecret(
	//	name string,
	//	allowReadBy []string,
	//	allowWriteBy []string,
	//	secret interface{},
	//
	// ) error
	return c.vault.CreateSecret(secret.Name, []string{}, []string{}, secret.Data)

}

// DeleteSecret will delete the secret from PrivX.
func (c *SecretsClient) DeleteSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) error {
	err := c.vault.DeleteSecret(ref.Key)
	if err == nil {
		return nil
	}
	if isNotFound(err) {
		return nil
	}
	return err
}

// SecretExists checks if a secret is already present in PrivX at the given location.
func (c *SecretsClient) SecretExists(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (bool, error) {
	_, err := c.GetSecret(context.TODO(), ref)
	if err == nil {
		return true, nil
	}

	if isNotFound(err) {
		return false, nil
	}

	// Other error than just "not found"
	return false, err
}

// isNotFound return whether the error is a 404 - Not Found.
func isNotFound(err error) bool {
	// PrivX loses the HTTP code so we need to test the error message
	return strings.Contains(strings.ToLower(err.Error()), "secret not found")
}

// Validate checks if the client is configured correctly
// and is able to retrieve secrets from the provider.
// If the validation result is unknown it will be ignored.
func (c *SecretsClient) Validate() (esv1.ValidationResult, error) {

	_, err := c.GetSecret(context.TODO(), esv1.ExternalSecretDataRemoteRef{Key: "2F0vZqCe0Z3XU5"})

	if isNotFound(err) {
		// We requested a non-existing secret and this is the proper response from PrivX -- all ok.
		return esv1.ValidationResultReady, nil
	}

	return esv1.ValidationResultError, err
}

// GetSecretMap returns multiple k/v pairs from PrivX.
func (c *SecretsClient) GetSecretMap(
	ctx context.Context,
	ref esv1.ExternalSecretDataRemoteRef,
) (map[string][]byte, error) {

	// 1) Hae sama payload kuin GetSecret tekee
	secret, err := c.vault.Secret(ref.Key)
	if err != nil {
		return nil, err
	}

	data := secret.Data
	if !json.Valid(data) {
		return nil, ErrInvalidJson
	}

	// Helper: tee RawMessage -> []byte sopivassa muodossa
	rawToBytes := func(raw json.RawMessage) ([]byte, error) {
		// Jos se on JSON-string, palautetaan unquote'tattu merkkijono (tyypillinen ESO-odotus)
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return []byte(s), nil
		}

		// Muut scalarit (numero/bool/null) voidaan palauttaa "tekstinä"
		var v any
		if err := json.Unmarshal(raw, &v); err == nil {
			switch t := v.(type) {
			case nil:
				return []byte("null"), nil
			case bool:
				if t {
					return []byte("true"), nil
				}
				return []byte("false"), nil
			case float64:
				// JSON-numero -> palautetaan alkuperäinen JSON bytes (säilyttää muodot esim 1 vs 1.0 huonosti),
				// mutta tämä on yleensä ok. Vaihtoehto: fmt.Sprintf(...).
				return []byte(raw), nil
			default:
				// array/object jne -> palautetaan JSON bytes sellaisenaan
				return []byte(raw), nil
			}
		}

		// fallback: sellaisenaan
		return []byte(raw), nil
	}

	// 2) Parse top-level objektiksi
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, ErrInvalidJson
	}

	// 3) Jos property on tyhjä: palauta kaikki top-level avaimet
	if ref.Property == "" {
		out := make(map[string][]byte, len(obj))
		for k, raw := range obj {
			b, err := rawToBytes(raw)
			if err != nil {
				return nil, err
			}
			out[k] = b
		}
		return out, nil
	}

	// 4) Property annettu: poimi se
	raw, ok := obj[ref.Property]
	if !ok {
		return nil, errors.New("property not found in secret JSON: " + ref.Property)
	}

	// Jos property on objekti, palauta sen avaimet map:na
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err == nil {
		out := make(map[string][]byte, len(nested))
		for k, v := range nested {
			b, err := rawToBytes(v)
			if err != nil {
				return nil, err
			}
			out[k] = b
		}
		return out, nil
	}

	// Muuten property on yksittäinen arvo: palautetaan yhden avaimen map
	b, err := rawToBytes(raw)
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		ref.Property: b,
	}, nil
}

// GetAllSecrets returns multiple k/v pairs from PrivX
func (c *SecretsClient) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {

	if ref.Path != nil {
		return nil, fmt.Errorf("parameter %q: %w", "ref.Path", ErrNotImplemented)
	}
	if ref.Tags != nil {
		return nil, fmt.Errorf("parameter %q: %w", "ref.Tags", ErrNotImplemented)
	}
	if ref.ConversionStrategy != "" {
		return nil, fmt.Errorf("parameter %q: %w", "ref.ConversionStrategy", ErrNotImplemented)
	}
	if ref.DecodingStrategy != "" {
		return nil, fmt.Errorf("parameter %q: %w", "ref.DecodingStrategy", ErrNotImplemented)
	}

	// Kubernetes gives a regexp. PrivX expects a partial string for the search expression.
	// We have no way of converting the Kubernetes expression into a parameter for PrivX search.
	// Therefore the only robust way to seek is to retrieve every secret name and compare it with regexp.

	ref.Name.RegExp
}

// Close closes the client and releases all resources.
func (c *SecretsClient) Close(ctx context.Context) error {
	// Nothing to close or release.
	return nil
}
