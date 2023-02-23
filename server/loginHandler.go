package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
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

	if upstreamResponse.Data != nil {
		if upstreamResponse.Data["error"] != nil {
			log.Infof("Error: %s", upstreamResponse.Data["error"].(string))
		}
	}
}

func handleSuccessfulLogin(upstreamResponse *logical.Response, w http.ResponseWriter, requestData map[string]interface{}, keyMaterial *keyMaterialPrivate) {
	requestedRole := requestData["role"].(string)
	successfulLoginsTotal.WithLabelValues(requestedRole).Inc()
	log.Info("Login successful")

	issuer := "aws-auth-jwt"
	if os.Getenv("ISSUER") != "" {
		issuer = os.Getenv("ISSUER")
	}

	expDurationHours := 1
	if os.Getenv("TOKEN_EXPIRATION_HOURS") != "" {
		expDurationHours, _ = strconv.Atoi(os.Getenv("TOKEN_EXPIRATION_HOURS"))
	}

	// Create the JWT token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":          upstreamResponse.Auth.InternalData["canonical_arn"],
		"iss":          issuer,
		"aud":          requestedRole,
		"azp":          requestedRole,
		"account_id":   upstreamResponse.Auth.InternalData["account_id"],
		"display_name": upstreamResponse.Auth.DisplayName,
		"kid":          "1",
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour * time.Duration(expDurationHours)).Unix(),
		"nbf":          time.Now().Unix(),
	})

	signedToken, _ := token.SignedString(keyMaterial.key)

	secret := &vault.Secret{
		Auth: &vault.SecretAuth{
			ClientToken: signedToken,
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(secret)
}

func loginHandler(keyMaterial *keyMaterialPrivate, storage logical.Storage) http.HandlerFunc {
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

		// If ALLOW_ALL is set to true, allow all requests by setting the role to "generic"
		if os.Getenv("ALLOW_ALL") == "true" {
			requestData["role"] = "generic"
		}

		// Execute the upstream login request
		backend, _ := awsauth.Backend(&logical.BackendConfig{})
		upstreamResponse, _ := backend.HandleRequest(r.Context(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login",
			Data:      requestData,
		})

		if upstreamResponse.IsError() {
			handleFailedLogin(upstreamResponse, w)
		} else {
			handleSuccessfulLogin(upstreamResponse, w, requestData, keyMaterial)
		}
	}

}
