/*
Implement the ESO Provider
*/
package privx

import (
	"context"
	"errors"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/api/vault"
	"github.com/SSHcom/privx-sdk-go/oauth"
	privxapi "github.com/SSHcom/privx-sdk-go/restapi"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
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

// Check during compile that we implement the interface
var _ esv1.Provider = (*Provider)(nil)

// Provider implements the ESO Provider interface for PrivX.
type Provider struct {
}

// authorize fetches the authorisation from config files or environment variables.
func authorize() privxapi.Authorizer {
	auth := privxapi.New(
		privxapi.UseConfigFile("config.toml"),
		privxapi.UseEnvironment(),
	)

	return oauth.With(
		auth,
		// 1. Use config file option to configure authorizer
		oauth.UseConfigFile("config.toml"),
		// 2. Use environment variables option to configure authorizer
		oauth.UseEnvironment(),
	)
}

// privx_api creates a working PrivX API connection
func privx_api() privxapi.Connector {
	return privxapi.New(
		privxapi.Verbose(),
		privxapi.Auth(authorize()),
		privxapi.UseConfigFile("config.toml"),
		privxapi.UseEnvironment(),
	)
}

// NewClient implements the Client interface.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {

	// Get details delivered in Kubernetes info
	info := store.GetSpec().Provider.PrivX
	if info == nil {
		return nil, ErrNoStoreAuth{Field: "spec.provider.privx"}
	}

	// TODO: this should use auth from the Kubernetes call ...
	conn := privx_api()
	client := SecretsClient{
		conn:      conn,
		vault:     vault.New(conn),
		store:     store,
		kube:      kube,
		namespace: namespace,
	}
	return &client, nil
}

func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	return nil, ErrNotImplemented
}

func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
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
