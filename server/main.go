package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-openapi/runtime/middleware/header"
	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
	"github.com/hashicorp/vault/sdk/logical"
)

func setupConfig() *logical.InmemStorage {
	context := context.Background()
	storage := &logical.InmemStorage{}
	storage.Put(context, &logical.StorageEntry{Key: "config/client", Value: []byte("{}")});
	// Add generic role, this is needed for the login to work
	storage.Put(context, &logical.StorageEntry{Key: "role/generic", Value: []byte(`{"auth_type": "iam","version":3}`)});

	return storage
}

func startServer() {
	storage := setupConfig()
	
	http.HandleFunc("/v1/auth/aws/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Received request: %s\n", r.URL.Path)

		// Check if the request is a PUT
		if r.Method != "PUT" {
			msg := "Request method is not PUT"
			http.Error(w, msg, http.StatusMethodNotAllowed)
			return
		}

		// Check if the Content-Type is application/json
		if r.Header.Get("Content-Type") != "" {
			value, _ := header.ParseValueAndParams(r.Header, "Content-Type")
			if value != "application/json" {
				msg := "Content-Type header is not application/json"
				http.Error(w, msg, http.StatusUnsupportedMediaType)
				return
			}
		}

		// Limit the request body to 1MB
		r.Body = http.MaxBytesReader(w, r.Body, 1048576)

		// Decode the request body into a map
		var data map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			msg := "Request body could not be decoded into JSON"
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		backend,_ := awsauth.Backend(&logical.BackendConfig{})
		response, _ := backend.HandleRequest(r.Context(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login",
			Data: data,
		})

		if response.IsError() {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Println("Login failed")
		} else {
			fmt.Println("Login successful")

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"canonical_arn": response.Auth.InternalData["canonical_arn"],
				"account_id": response.Auth.InternalData["account_id"],
				"display_name": response.Auth.DisplayName,
				"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
			})

			tokenString, _ := token.SignedString([]byte("secret"))

			secret := &vault.Secret{
				Auth: &vault.SecretAuth{
					ClientToken: tokenString,
				},
				Data: map[string]interface{}{
					"canonical_arn": response.Auth.InternalData["canonical_arn"],
					"account_id": response.Auth.InternalData["account_id"],
					"display_name": response.Auth.DisplayName,
				},
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(secret)
		} 
	})

	http.ListenAndServe(":8081", nil)
}

func main() {
	startServer()
}
