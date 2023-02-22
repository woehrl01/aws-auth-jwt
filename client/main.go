package main

import (
	"context"
	"encoding/json"
	"fmt"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/aws"
)

func doLogin() {
	config := vault.DefaultConfig()
	config.Address = "http://localhost:8081"

	client, _ := vault.NewClient(config)
	awsAuth, _ := auth.NewAWSAuth(
		auth.WithRole("generic"),
	)
	authInfo, err := awsAuth.Login(context.Background(), client)
	if err != nil {
		fmt.Println(err)
		return
	}

	b, err := json.MarshalIndent(authInfo, "", "  ")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println()
	fmt.Printf("%s", b)
}

func main() {
	doLogin()
}
