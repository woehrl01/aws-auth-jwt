package main

import (
	"context"
	"encoding/json"
	"fmt"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/aws"
)

// see: https://github.com/hashicorp/go-secure-stdlib/blob/main/awsutil/generate_credentials.go#L256-L301
// In case of not using golang you have to implement the following logic:
// - get the credentials from the environment (using the AWS SDK)
// - generate the payload for the login request
//     -  Create an STS session by using the provided credentials and region, and specifies an endpoint resolver function that resolves the STS endpoint.
//     -  Call the GetCallerIdentity method to obtain information about the caller's identity.
//     -  Call the GetSessionToken method to obtain a session token.
//     -  Generate a GetCallerIdentity request using the session token. Add any additional headers that are required by the target service.
//     -  Sign the request using the session token. (Don't execute the request)
//     -  Extract the HTTP Method, URL, Body and Headers from the signed request.
//     -  Create a JSON object with the following fields:
//         -  "iam_http_request_method": The HTTP method of the request.
//         -  "iam_request_url": The URL of the request. (Base64 encoded)
//         -  "iam_request_body": The body of the request. (Base64 encoded)
//         -  "iam_request_headers": The headers of the request. (Base64 encoded)
// - To specify the role to use, set the role parameter to the name of the role.
//   - The field "role" is optional. But it must be configured on the server side.
//   - The field "role" is used as the audience claim in the JWT token.
// - Send the request to the vault server to Login: /v1/auth/aws/login
func doLogin() {
	config := vault.DefaultConfig()
	config.Address = "https://iam.eks-0-2.plenty.rocks"

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
