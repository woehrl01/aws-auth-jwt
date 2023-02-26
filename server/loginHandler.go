package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-openapi/runtime/middleware/header"
	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

type loginHandler struct {
	keyMaterial *keyMaterialPrivate
	upstream    upstream
	validator   validator
}

type upstream interface {
	executeUpstreamLogin(ctx context.Context, requestData map[string]interface{}) UpstreamResponse
}

type UpstreamResponse struct {
	LoginSucceeded bool
	Data           map[string]interface{}
	ErrorMessage   string
	DisplayName    string
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Received request: %s", r.URL.Path)
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

	upstreamResponse := h.upstream.executeUpstreamLogin(r.Context(), requestData)

	// In case that the login was successful to AWS STS we need to check if the user has access to receive a JWT token
	// We do this by calling the HasAccess method of the AccessValidator. The current implementation of the
	// AccessValidator is using the Open Policy Agent (OPA) to validate the access.
	if !upstreamResponse.LoginSucceeded {
		handleFailedLogin(upstreamResponse, w)
	} else if validationResult := h.validator.HasAccess(requestData, upstreamResponse); validationResult.Allowed {
		handleSuccessfulLogin(upstreamResponse, w, requestData, h.keyMaterial, validationResult.AdditionalClaims)
	} else {
		handleFailedLogin(upstreamResponse, w)
	}
}

func handleFailedLogin(upstreamResponse UpstreamResponse, w http.ResponseWriter) {
	failedLoginsTotal.Inc()
	log.Info("Login failed")

	w.WriteHeader(http.StatusUnauthorized)

	if upstreamResponse.ErrorMessage != "" {
		log.Infof("Error: %s", upstreamResponse.ErrorMessage)
	}
}

func handleSuccessfulLogin(upstreamResponse UpstreamResponse, w http.ResponseWriter, requestData map[string]interface{}, keyMaterial *keyMaterialPrivate, claims map[string]interface{}) {
	audience := "generic"
	if requestData["audience"] != nil {
		audience = requestData["audience"].(string)
	} else if requestData["role"] != nil {
		audience = requestData["role"].(string)
	}
	successfulLoginsTotal.WithLabelValues(audience).Inc()
	log.Info("Login successful")

	jwtClaims := jwt.MapClaims{
		"sub":          upstreamResponse.Data["canonical_arn"],
		"iss":          settings.issuer,
		"aud":          audience,
		"azp":          audience,
		"account_id":   upstreamResponse.Data["account_id"],
		"user_id":      upstreamResponse.Data["client_user_id"],
		"display_name": upstreamResponse.DisplayName,
		"kid":          keyMaterial.keyID,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour * time.Duration(settings.tokenExpirationHours)).Unix(),
		"nbf":          time.Now().Unix(),
	}

	log.Debugf("Claims: %v", upstreamResponse.Data)

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
