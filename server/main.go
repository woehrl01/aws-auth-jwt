package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

func getPrivateKeys() ([]byte, []byte, error) {
	// Generate a new private key
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	pemDataPrivate := pem.EncodeToMemory(privateKey)

	asn1Bytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	publicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemDataPublic := pem.EncodeToMemory(publicKey)

	return pemDataPrivate, pemDataPublic, nil
}

func startServer() {
	storage := setupConfig()

	pemDataPrivate, pemDataPublic, err := getPrivateKeys()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("generated private and public key")
	
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

			requestedRole := data["role"].(string)

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub": response.Auth.InternalData["canonical_arn"],
				"iss": "http://localhost:8080", //todo: make configurable
				"aud": requestedRole, 
				"azp": requestedRole,
				"account_id": response.Auth.InternalData["account_id"],
				"display_name": response.Auth.DisplayName,
				"kid": "1", 
				"iat": time.Now().Unix(), 
				"exp": time.Now().Add(time.Hour * 24).Unix(),
				"nbf": time.Now().Unix(),
			})

			privKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemDataPrivate)
			if err != nil {
				fmt.Print("Error parsing private key")
				fmt.Println(err)
				return
			}

			tokenString, _ := token.SignedString(privKey)

			secret := &vault.Secret{
				Auth: &vault.SecretAuth{
					ClientToken: tokenString,
				},
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(secret)
		} 
	})

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Received request: %s\n", r.URL.Path)

		// Check if the request is a GET
		if r.Method != "GET" {
			msg := "Request method is not GET"
			http.Error(w, msg, http.StatusMethodNotAllowed)
			return
		}

		_, err := jwt.ParseRSAPublicKeyFromPEM(pemDataPublic)
		if err != nil {
			fmt.Print("Error parsing public key")
			fmt.Printf("%s", pemDataPublic)
			fmt.Println(err)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": "1", //should be the same as the kid in the token, and should be unique, therefore infer from the certificate
					"alg": "RS256",
					"use": "sig",
					//"n": pubkey.N.String(), //uncomment this if you want to use the modulus and exponent
					//"e": pubkey.E,
					"x5c": []string{
						base64.StdEncoding.EncodeToString(pemDataPublic),
					},
				},
			},
		})
	})

	fmt.Println("Starting server on port 8081")
	http.ListenAndServe(":8081", nil)
}

func main() {
	startServer()
}
