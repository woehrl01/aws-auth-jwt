package main

import (
	"context"
	"encoding/json"
	"fmt"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/aws"
)

func doLogin(){
	config := vault.DefaultConfig() 
	config.Address = "http://localhost:8081";

    client, _ := vault.NewClient(config)
	awsAuth, _ := auth.NewAWSAuth(
		auth.WithRole("generic"), // we use a generic role, because we don't have a role in the storage
	)
	authInfo, err := awsAuth.Login(context.Background(), client)
	if err != nil {
		fmt.Println(err)
	}

	b, err := json.MarshalIndent(authInfo, "", "  ")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println()
	fmt.Printf("AuthInfo: %s\n", b)
}

func main() {
	doLogin()
}
