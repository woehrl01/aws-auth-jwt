package main

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
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
