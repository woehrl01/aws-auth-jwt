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
	"os"
	"time"

	"github.com/go-openapi/runtime/middleware/header"
	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
	"github.com/hashicorp/vault/sdk/logical"
	log "github.com/sirupsen/logrus"
)

// copy from: github.com/hashicorp/vault/builtin/logical/aws/path_config_root.go
type rootConfig struct {
	AccessKey        string `json:"access_key"`
	SecretKey        string `json:"secret_key"`
	IAMEndpoint      string `json:"iam_endpoint"`
	STSEndpoint      string `json:"sts_endpoint"`
	Region           string `json:"region"`
	MaxRetries       int    `json:"max_retries"`
	UsernameTemplate string `json:"username_template"`
}

// copy from: github.com/hashicorp/vault/builtin/logical/aws/path_roles.go
type awsRoleEntry struct {
	Version  int    `json:"version"`   // Version number of the role format
	AuthType string `json:"auth_type"` // Type of authentication to use
}

func setupConfig() *logical.InmemStorage {
	context := context.Background()
	storage := &logical.InmemStorage{}

	// Add the root config to the storage
	rootConfig := rootConfig{}
	rootConfigEntry, _ := logical.StorageEntryJSON("config/root", rootConfig)
	storage.Put(context, rootConfigEntry)

	storage.Put(context, &logical.StorageEntry{Key: "config/client", Value: []byte("{}")})

	// Add a role to the storage
	role := awsRoleEntry{
		Version:  3, // we need to set the version to 3, because the server expects a version 3
		AuthType: "iam",
	}
	roleEntry, _ := logical.StorageEntryJSON("role/generic", role)
	storage.Put(context, roleEntry)

	return storage
}

func getPrivateKeysFromFile() ([]byte, []byte, error) {
	pemDataPrivate, err := os.ReadFile("private.pem")
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	pemDataPublic, err := os.ReadFile("public.pem")
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	log.Info("Loaded private and public key from file")
	return pemDataPrivate, pemDataPublic, nil
}

func getPrivateKeys() ([]byte, []byte, error) {
	if _, err := os.Stat("private.pem"); os.IsNotExist(err) {
		log.Info("private.pem does not exist")
		return getPrivateKeysGenerated()
	}

	if _, err := os.Stat("public.pem"); os.IsNotExist(err) {
		log.Info("public.pem does not exist")
		return getPrivateKeysGenerated()
	}
	return getPrivateKeysFromFile()
}

func getPrivateKeysGenerated() ([]byte, []byte, error) {
	// Generate a new private key
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return nil, nil, err
	}

	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	pemDataPrivate := pem.EncodeToMemory(privateKey)

	asn1Bytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("unable to marshal public key: %v", err)
		return nil, nil, err
	}

	publicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemDataPublic := pem.EncodeToMemory(publicKey)

	log.Info("generated private and public key")

	return pemDataPrivate, pemDataPublic, nil
}

func startServer() {
	storage := setupConfig()

	pemDataPrivate, pemDataPublic, err := getPrivateKeys()
	if err != nil {
		log.Fatalf("Could not get private keys: %s", err)
		return
	}

	

	http.HandleFunc("/v1/auth/aws/login", func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Received request: %s", r.URL.Path)

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

		if os.Getenv("ALLOW_ALL") == "true" {
			data["role"] = "generic"
		}

		backend, _ := awsauth.Backend(&logical.BackendConfig{})
		response, _ := backend.HandleRequest(r.Context(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login",
			Data:      data,
		})

		if response.IsError() {
			log.Error("Login failed")

			w.WriteHeader(http.StatusUnauthorized)

			if response.Data != nil {
				if response.Data["error"] != nil {
					//if you receive an upstream error, you are likely missing the correct role for the server to authenticate to AWS STS
					fmt.Printf("Error: %s", response.Data["error"].(string))
				}
			}
		} else {
			log.Info("Login successful")

			requestedRole := data["role"].(string)

			issuer := "aws-auth-jwt"
			if os.Getenv("ISSUER") != "" {
				issuer = os.Getenv("ISSUER")
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":          response.Auth.InternalData["canonical_arn"],
				"iss":          issuer,
				"aud":          requestedRole,
				"azp":          requestedRole,
				"account_id":   response.Auth.InternalData["account_id"],
				"display_name": response.Auth.DisplayName,
				"kid":          "1",
				"iat":          time.Now().Unix(),
				"exp":          time.Now().Add(time.Hour * 24).Unix(),
				"nbf":          time.Now().Unix(),
			})

			privKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemDataPrivate)
			if err != nil {
				log.Fatalf("Error parsing private key: %s", err)
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
		log.Debug("Received request: %s", r.URL.Path)

		// Check if the request is a GET
		if r.Method != "GET" {
			msg := "Request method is not GET"
			http.Error(w, msg, http.StatusMethodNotAllowed)
			return
		}

		_, err := jwt.ParseRSAPublicKeyFromPEM(pemDataPublic)
		if err != nil {
			log.Fatalf("Error parsing public key: %s", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": "1",
					"alg": "RS256",
					"use": "sig",
					"x5c": []string{
						base64.StdEncoding.EncodeToString(pemDataPublic),
					},
				},
			},
		})
	})

	log.Info("Starting server on port 8081")
	http.ListenAndServe(":8081", nil)
}


func initLogging() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.TextFormatter{})
  
	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)
  
	// Only log the warning severity or above.
	log.SetLevel(log.InfoLevel)
  }

func main() {
	initLogging()
	startServer()
}
