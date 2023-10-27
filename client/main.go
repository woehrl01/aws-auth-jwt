package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// see: https://github.com/hashicorp/go-secure-stdlib/blob/main/awsutil/generate_credentials.go#L256-L301
// In case of not using golang you have to implement the following logic:
// - get the credentials from the environment (using the AWS SDK)
// - generate the payload for the login request
//   - Create an STS session by using the provided credentials and region, and specifies an endpoint resolver function that resolves the STS endpoint.
//   - Call the GetCallerIdentity method to obtain information about the caller's identity.
//   - Call the GetSessionToken method to obtain a session token.
//   - Generate a GetCallerIdentity request using the session token. Add any additional headers that are required by the target service.
//   - Sign the request using the session token. (Don't execute the request)
//   - Extract the HTTP Method, URL, Body and Headers from the signed request.
//   - Create a JSON object with the following fields:
//   - "iam_http_request_method": The HTTP method of the request.
//   - "iam_request_url": The URL of the request. (Base64 encoded)
//   - "iam_request_body": The body of the request. (Base64 encoded)
//   - "iam_request_headers": The headers of the request. (Base64 encoded)
//
// - To specify the role to use, set the role parameter to the name of the role.
//   - The field "role" is optional. But it must be configured on the server side.
//   - The field "role" is used as the audience claim in the JWT token.
//
// - Send the request to the vault server to Login: /v1/auth/aws/login
func doLogin(ctx context.Context, config *Config) (string, error) {
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Addr
	client, _ := vault.NewClient(vaultConfig)

	loginData, err := awsLoginPrep(ctx)
	if err != nil {
		return "", err
	}

	loginData["role"] = config.Role

	for _, claim := range config.Claims {
		splited := strings.Split(claim, "=")
		if len(splited) != 2 {
			return "", fmt.Errorf("invalid claim: %s", claim)
		}
		loginData[splited[0]] = splited[1]
	}

	authInfo, err := client.Logical().WriteWithContext(context.Background(), "auth/aws/login", loginData)
	if err != nil {
		return "", err
	}

	
	return authInfo.Auth.ClientToken, nil
}

type Config struct {
	Addr string `mapstructure:"addr"`
	Role string `mapstructure:"role"`
	Claims []string `mapstructure:"claims"`
}

func main() {
	pflag.String("addr", "http://localhost:8081", "Vault server address")
	pflag.String("role", "generic", "Vault role")
	pflag.StringSlice("claims", []string{}, "JWT claims")
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	config := &Config{}
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatal(err)
	}

	token, err := doLogin(context.Background(), config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token)
}

func awsLoginPrep(ctx context.Context) (map[string]interface{}, error) {
	logger := hclog.Default()

	const region = "us-east-1"
	creds, err := awsCredentialsFromSession(region)
	if err != nil {
		creds, err = awsCredentilasFromEnv(logger)
		if err != nil {
			return nil, err
		}
	}
	return awsutil.GenerateLoginData(creds, "", region, logger)
}

func awsCredentialsFromSession(region string) (*credentials.Credentials, error) {
	session, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			Region: aws.String(region),
		},
	})

	if err != nil {
		return nil, err
	}

	creds := session.Config.Credentials
	if creds == nil {
		return nil, fmt.Errorf("could not get credentials from session")
	}

	_, err = creds.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials from credential chain: %w", err)
	}

	return creds, nil
}

func awsCredentilasFromEnv(logger hclog.Logger) (*credentials.Credentials, error) {
	credsConfig := awsutil.CredentialsConfig{
		AccessKey:    os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey:    os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		Logger:       logger,
	}

	// the env vars above will take precedence if they are set, as
	// they will be added to the ChainProvider stack first
	var hasCredsFile bool
	credsFilePath := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if credsFilePath != "" {
		hasCredsFile = true
		credsConfig.Filename = credsFilePath
	}

	creds, err := credsConfig.GenerateCredentialChain(awsutil.WithSharedCredentials(hasCredsFile))
	if err != nil {
		return nil, err
	}

	if creds == nil {
		return nil, fmt.Errorf("could not compile valid credential providers from static config, environment, shared, or instance metadata")
	}

	_, err = creds.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials from credential chain: %w", err)
	}

	return creds, nil

}
