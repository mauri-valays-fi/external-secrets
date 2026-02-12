/*
Implement the ESO SecretsClient
*/

package privx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/SSHcom/privx-sdk-go/api/vault"
	privxapi "github.com/SSHcom/privx-sdk-go/restapi"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	corev1 "k8s.io/api/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var ErrNoName = errors.New("No name provided for secret")
var ErrUnsupportedDecodingStrategy = errors.New("unsupported decoding strategy")

// Check during compile that we implement the interface
var _ esv1.SecretsClient = (*SecretsClient)(nil)

// SecretsClient provides access to PrivX secrets.
type SecretsClient struct {
	conn      privxapi.Connector
	vault     *vault.Vault // PrivX Vault instance
	store     esv1.GenericStore
	kube      kclient.Client
	namespace string

	// PrivX needs roles when creating a new secret.
	defaultReadRoles  []string
	defaultWriteRoles []string
}

// GetSecret returns a single secret from the provider.
func (c *SecretsClient) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {

	secret, error := c.vault.Secret(ref.Key)
	if error != nil {
		return nil, error
	} else {
		data, err := decode(secret.Data, ref.DecodingStrategy)
		if err != nil {
			return nil, err
		}
		if !json.Valid(data) {
			return nil, ErrInvalidJson
		}
		return data, nil
	}
}

// PushSecret will write a single secret into PrivX.
//
// Access for the new secret in PrivX is defined by variables default*Roles set for the store.
func (c *SecretsClient) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	remoteKey := data.GetRemoteKey()
	name := remoteKey
	if name == "" {
		name = secret.Name
	}
	if name == "" {
		return ErrNoName
	}

	secretKey := data.GetSecretKey()
	secretValue, ok := secret.Data[secretKey]
	if !ok {
		return fmt.Errorf("missing secret data for key %q", secretKey)
	}

	return c.vault.CreateSecret(name, c.defaultReadRoles, c.defaultWriteRoles, secretValue)
}

// DeleteSecret will delete the secret from PrivX.
func (c *SecretsClient) DeleteSecret(ctx context.Context, ref esv1.PushSecretRemoteRef) error {
	err := c.vault.DeleteSecret(ref.GetRemoteKey())
	if err == nil {
		return nil
	}
	if isNotFound(err) {
		return nil
	}
	return err
}

// SecretExists checks if a secret is already present in PrivX at the given location.
func (c *SecretsClient) SecretExists(ctx context.Context, ref esv1.PushSecretRemoteRef) (bool, error) {

	remoteRef := esv1.ExternalSecretDataRemoteRef{Key: ref.GetRemoteKey()}
	_, err := c.GetSecret(context.TODO(), remoteRef)
	if err == nil {
		return true, nil
	}

	if isNotFound(err) {
		return false, nil
	}

	// Other error than just "not found"
	return false, err
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

// GetAllSecrets returns multiple secrets and their JSON values from PrivX
//
// I assume that means key is the secret name and value is the JSON contained.
// Because otherwise, several secrets can have same key in the JSON and returning all the k/v pairs from inside the
// list of secrets would create collisions.
func (c *SecretsClient) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {

	// Kubernetes gives a regexp. PrivX expects a partial string for the search expression.
	// We have no way of converting the Kubernetes expression into a parameter for PrivX search.
	// Therefore the only robust way to seek is to retrieve every secret name and compare it with regexp.

	results := make(map[string][]byte)

	if ref.Path != nil {
		return results, fmt.Errorf("parameter %q: %w", "ref.Path", ErrNotImplemented)
	}
	if ref.Tags != nil {
		return results, fmt.Errorf("parameter %q: %w", "ref.Tags", ErrNotImplemented)
	}
	if ref.ConversionStrategy != esv1.ExternalSecretConversionDefault {
		return results, fmt.Errorf("parameter %q: %w", "ref.ConversionStrategy", ErrNotImplemented)
	}

	searchString := ""
	if ref.Name != nil {
		// Missing search parameter is considered an empty string, which matches all
		searchString = ref.Name.RegExp
	}

	nameRegexp, err := regexp.Compile(searchString)
	if err != nil {
		return results, fmt.Errorf("invalid regex %q: %w", searchString, err)
	}

	// Loop through all secrets 100 at a time
	const limit = 100
	for offset := 0; ; offset += limit {
		secrets, err := c.vault.Secrets(offset, limit)
		if err != nil {
			return results, err
		}

		if len(secrets) == 0 {
			break
		}

		for _, secret := range secrets {
			if !nameRegexp.MatchString(secret.ID) {
				continue
			}

			secretDetails, err := c.vault.Secret(secret.ID)
			if err != nil {
				return results, err
			}

			results[secret.ID] = secretDetails.Data
		}

		if len(secrets) < limit {
			break
		}
	}
	return results, nil
}

// Close closes the client and releases all resources.
func (c *SecretsClient) Close(ctx context.Context) error {
	// Nothing to close or release.
	return nil
}

// Helper functions

// isNotFound return whether the error is a 404 - Not Found.
func isNotFound(err error) bool {
	// PrivX loses the HTTP code so we need to test the error message
	return strings.Contains(strings.ToLower(err.Error()), "secret not found")
}

// decode decodes a secret value according to DecodingStrategy
//
// See https://external-secrets.io/latest/guides/decoding-strategy/
func decode(value []byte, strategy esv1.ExternalSecretDecodingStrategy) ([]byte, error) {
	switch strategy {
	case esv1.ExternalSecretDecodeBase64:
		decoded, err := base64.StdEncoding.DecodeString(string(value))
		if err != nil {
			return nil, err
		}
		return decoded, nil
	case esv1.ExternalSecretDecodeBase64URL:
		decoded, err := base64.URLEncoding.DecodeString(string(value))
		if err != nil {
			return nil, err
		}
		return decoded, nil
	case esv1.ExternalSecretDecodeNone, "":
		return value, nil
	case esv1.ExternalSecretDecodeAuto:
		decoded, err := decode(value, esv1.ExternalSecretDecodeBase64)
		if err == nil {
			return decoded, nil
		}
		decoded, err = decode(value, esv1.ExternalSecretDecodeBase64URL)
		if err == nil {
			return decoded, nil
		}
		return value, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedDecodingStrategy, strategy)
	}
}

// // convertValue converts a secret value based on the conversion strategy.
// func convertValue(value []byte, strategy esv1.ExternalSecretConversionStrategy) ([]byte, error) {
// 	switch strategy {
// 	case esv1.ExternalSecretConversionDefault, "":
// 		return value, nil
// 	case esv1.ExternalSecretConversionUnicode:
// 		if !utf8.Valid(value) {
// 			return nil, fmt.Errorf("secret value is not valid UTF-8")
// 		}
// 		return []byte(string(value)), nil
// 	default:
// 		return value, nil
// 	}
// }

// // rawMessageToByteMap converts a raw JSON to a byte map. The values remain raw.
// func rawMessageToByteMap(raw json.RawMessage) (map[string][]byte, error) {
// 	var tmp map[string]json.RawMessage
// 	if err := json.Unmarshal(raw, &tmp); err != nil {
// 		return nil, err
// 	}

// 	out := make(map[string][]byte, len(tmp))
// 	for k, v := range tmp {
// 		out[k] = v // json.RawMessage == []byte
// 	}
// 	return out, nil
// }
