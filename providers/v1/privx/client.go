/*
Implement the ESO SecretsClient
*/

package privx

import (
	"context"
	"encoding/json"
	"errors"
	"log"

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

// GetSecret returns a single secret from the provider
func (c *SecretsClient) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {

	secret, error := c.vault.Secret(ref.Key)
	if error != nil {
		log.Println("Error", error, "Secret", secret)
		return nil, error
	} else {
		log.Println("Received secret", secret)
		// The secret should be a JSON value
		// Do we want to validate ?
		data := secret.Data
		if !json.Valid(data) {
			log.Println("invalid JSON")
			return nil, ErrInvalidJson
		}
		return data, nil
	}
}

// PushSecret will write a single secret into the provider
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

// DeleteSecret will delete the secret from a provider
func (c *SecretsClient) DeleteSecret(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) error {
	return ErrNotImplemented

	// func (vault *Vault) DeleteSecret(name string) error
}

// SecretExists checks if a secret is already present in the provider at the given location.
func (c *SecretsClient) SecretExists(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) (bool, error) {
	return false, ErrNotImplemented
}

// Validate checks if the client is configured correctly
// and is able to retrieve secrets from the provider.
// If the validation result is unknown it will be ignored.
func (c *SecretsClient) Validate() (esv1.ValidationResult, error) {
	return esv1.ValidationResultError, ErrNotImplemented
}

// GetSecretMap returns multiple k/v pairs from the provider
func (c *SecretsClient) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return nil, ErrNotImplemented
}

// GetAllSecrets returns multiple k/v pairs from the provider
func (c *SecretsClient) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	return nil, ErrNotImplemented

	// func (vault *Vault) Secrets(offset, limit int) ([]Secret, error) {
	// result := secretResult{}
	// filters := Params{
	// 	Offset: offset,
	// 	Limit:  limit,
	// }
}

func (c *SecretsClient) Close(ctx context.Context) error {
	return ErrNotImplemented

}
