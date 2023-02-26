package main

import (
	"context"

	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
	"github.com/hashicorp/vault/sdk/logical"
)

type vaultUpstream struct {
	handleRequest func(ctx context.Context, req *logical.Request) (*logical.Response, error)
	storage       logical.Storage
}

func NewVaultUpstream() *vaultUpstream {
	configuration := setupVaultUpstreamConfig()
	backend, _ := awsauth.Backend(&logical.BackendConfig{})
	return &vaultUpstream{
		handleRequest: backend.HandleRequest,
		storage:       configuration,
	}
}

func (u *vaultUpstream) executeUpstreamLogin(ctx context.Context, requestData map[string]interface{}) UpstreamResponse {
	defer measureTime(stsBackendDuration)

	// The backend expected that the role exsists in the storage, in order to allow the login
	// and handle the role specific logic later. We need to change the role to the "generic" role
	// in order to allow the login. After the login we can check if the user has access to the
	// requested role.
	// This is a workaround for the fact that the vault aws auth backend requires a valid role.
	copyRequestData := make(map[string]interface{})
	for key, value := range requestData {
		copyRequestData[key] = value
	}
	copyRequestData["role"] = "generic"

	// Execute the upstream login request
	upstreamResponse, _ := u.handleRequest(ctx, &logical.Request{
		Storage:   u.storage,
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      copyRequestData,
	})

	if isSuccessfulLogin(upstreamResponse) {
		return UpstreamResponse{
			LoginSucceeded: true,
			Success: UpstreamResponseSuccess{
				Arn:         upstreamResponse.Auth.InternalData["canonical_arn"].(string),
				AccountId:   upstreamResponse.Auth.InternalData["account_id"].(string),
				UserId:      upstreamResponse.Auth.InternalData["client_user_id"].(string),
				DisplayName: upstreamResponse.Auth.DisplayName,
			},
		}
	} else {
		errorMessage := ""
		if upstreamResponse != nil && upstreamResponse.Data != nil {
			errorMessage = upstreamResponse.Data["error"].(string)
		}

		return UpstreamResponse{
			LoginSucceeded: false,
			Error: UpstreamResponseError{
				ErrorMessage: errorMessage,
			},
		}
	}
}

func isSuccessfulLogin(response *logical.Response) bool {
	if response == nil {
		return false
	}

	if response.IsError() {
		return false
	}

	if response.Auth == nil {
		return false
	}

	if response.Auth.InternalData == nil {
		return false
	}

	return true
}
