package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/aws"
	awsauth "github.com/hashicorp/vault/builtin/credential/aws"
	"github.com/hashicorp/vault/sdk/logical"
)

func startServer() {
	http.HandleFunc("/v1/auth/aws/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Received request: %s\n", r.URL.Path)

		var data map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			fmt.Println(err)
		}

		storage := &logical.InmemStorage{}
		storage.Put(r.Context(), &logical.StorageEntry{Key: "config/client", Value: []byte("{}")});

		//read allowed roles from file iterate over every line and add it to the storage
		file, err := os.Open("allowed_roles.txt")
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file.Close()

		// Create a scanner
		scanner := bufio.NewScanner(file)

		// Process each line
		for scanner.Scan() {
			role := scanner.Text()
			storage.Put(r.Context(), &logical.StorageEntry{Key: "role/"+strings.ToLower(role), Value: []byte(`{"auth_type": "iam","version":3}`)});
			fmt.Printf("Added role: %s\n", role)
		}

		// Check for errors
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file:", err)
		}

		backend,_ := awsauth.Backend(&logical.BackendConfig{})

		response, _ := backend.HandleRequest(r.Context(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login",
			Data: data,
		})

		if !response.IsError() {

			fmt.Println("Login successful")

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"foo": "bar",
				"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
			})

			tokenString, _ := token.SignedString([]byte("secret"))

			secret := &vault.Secret{
				Auth: &vault.SecretAuth{
					ClientToken: tokenString,
				},
				Data: map[string]interface{}{
					"cannonical_arn": response.Auth.InternalData["cannonical_arn"],
					"account_id": response.Auth.InternalData["account_id"],
					"display_name": response.Auth.DisplayName,
				},
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(secret)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	go http.ListenAndServe(":8081", nil)
	fmt.Println("Server started")
}

func doLogin(){
	config := vault.DefaultConfig() 
	config.Address = "http://localhost:8081";

    client, _ := vault.NewClient(config)
	awsAuth, _ := auth.NewAWSAuth()
	authInfo, err := awsAuth.Login(context.Background(), client)

	if err != nil {
		fmt.Println(err)
	}

	b, err := json.Marshal(authInfo)
	if err != nil {
		fmt.Println(err)
	}


	fmt.Println()
	fmt.Printf("AuthInfo: %s\n", b)
}

func main() {

	startServer()

	doLogin()
}
