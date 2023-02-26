package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-openapi/runtime/middleware/header"
	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
	"github.com/hashicorp/vault/sdk/logical"
	log "github.com/sirupsen/logrus"
)

func handleFailedLogin(upstreamResponse *logical.Response, w http.ResponseWriter) {
	failedLoginsTotal.Inc()
	log.Error("Login failed")

	w.WriteHeader(http.StatusUnauthorized)

	if upstreamResponse.Data != nil && upstreamResponse.Data["error"] != nil {
		log.Infof("Error: %s", upstreamResponse.Data["error"].(string))
	}
}

func handleSuccessfulLogin(upstreamResponse *logical.Response, w http.ResponseWriter, requestData map[string]interface{}, keyMaterial *keyMaterialPrivate, claims map[string]interface{}) {
	requestedRole := requestData["role"].(string)
	successfulLoginsTotal.WithLabelValues(requestedRole).Inc()
	log.Info("Login successful")

	jwtClaims := jwt.MapClaims{
		"sub":          upstreamResponse.Auth.InternalData["canonical_arn"],
		"iss":          settings.issuer,
		"aud":          requestedRole,
		"azp":          requestedRole,
		"account_id":   upstreamResponse.Auth.InternalData["account_id"],
		"user_id":      upstreamResponse.Auth.InternalData["client_user_id"],
		"display_name": upstreamResponse.Auth.DisplayName,
		"kid":          keyMaterial.keyID,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour * time.Duration(settings.tokenExpirationHours)).Unix(),
		"nbf":          time.Now().Unix(),
	}

	log.Debugf("Claims: %v", upstreamResponse.Auth.InternalData)

	// Add custom claims
	for key, value := range claims {
		if _, exists := jwtClaims[key]; exists {
			log.Warnf("Claim %s already exists, skipping", key)
			continue
		}
		jwtClaims[key] = value
	}

	// Create the JWT token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)

	signedToken, _ := token.SignedString(keyMaterial.key)

	secret := &vault.Secret{
		Auth: &vault.SecretAuth{
			ClientToken: signedToken,
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(secret)
}

type loginHandler struct {
	keyMaterial   *keyMaterialPrivate
	vaultUpstream *vaultUpstream
	validator     *AccessValidatior
}

type vaultUpstream struct {
	handleRequest func(ctx context.Context, req *logical.Request) (*logical.Response, error)
	storage       logical.Storage
}

func NewVaultUpstream() *vaultUpstream {
	configuration := setupConfig()
	backend, _ := awsauth.Backend(&logical.BackendConfig{})
	return &vaultUpstream{
		handleRequest: backend.HandleRequest,
		storage:       configuration,
	}
}

func (u *vaultUpstream) executeUpstreamLogin(ctx context.Context, requestData map[string]interface{}) *logical.Response {
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

	return upstreamResponse
}

func (h *loginHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Received request: %s", r.URL.Path)
		loginRequestsTotal.Inc()

		// Check if the request is a PUT
		if r.Method != "PUT" {
			http.NotFound(w, r)
			return
		}

		// Check if the Content-Type is application/json
		if r.Header.Get("Content-Type") != "" {
			value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
			if value != "application/json" {
				http.NotFound(w, r)
				return
			}
		}

		// Limit the request body to 1MB
		r.Body = http.MaxBytesReader(w, r.Body, 1048576)

		// Decode the request body into a map
		var requestData map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&requestData)
		if err != nil {
			msg := "Request body could not be decoded into JSON"
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		upstreamResponse := h.vaultUpstream.executeUpstreamLogin(r.Context(), requestData)

		// In case that the login was successful to AWS STS we need to check if the user has access to receive a JWT token
		// We do this by calling the HasAccess method of the AccessValidator. The current implementation of the
		// AccessValidator is using the Open Policy Agent (OPA) to validate the access.
		if upstreamResponse.IsError() {
			handleFailedLogin(upstreamResponse, w)
		} else if validationResult := h.validator.HasAccess(requestData, upstreamResponse); validationResult.Allow {
			handleSuccessfulLogin(upstreamResponse, w, requestData, h.keyMaterial, validationResult.Claims)
		} else {
			handleFailedLogin(upstreamResponse, w)
		}
	}
}
