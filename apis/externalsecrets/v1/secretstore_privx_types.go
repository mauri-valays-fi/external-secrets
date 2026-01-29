/*
Copyright © 2026 ESO Maintainer Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// PrivxProvider configures a store to sync secrets using PrivX backend.
type PrivxProvider struct {
	// Auth configures how secret-manager authenticates with PrivX server.
	Auth *PrivXAuth `json:"auth,omitempty"`

	// Server is the connection address for the server, e.g: "https://privx.example.com:8200".
	Host string `json:"host"`
}

type PrivXAuth struct {
	Namespace *string     `json:"namespace,omitempty"`
	OAuth     *PrivXOAuth `json:"oauth,omitempty"`
}

type PrivXOAuth struct {
	ClientIdRef     esmeta.SecretKeySelector `json:"clientIdRef"`
	ClientSecretRef esmeta.SecretKeySelector `json:"clientSecretRef"`
}
