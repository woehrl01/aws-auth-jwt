package main

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/open-policy-agent/opa/rego"
)

func TestAccessValidatior_HasAccess(t *testing.T) {
	testCases := []struct {
		name string
		// The input data for the rego query
		rule        string
		requestData map[string]interface{}
		// The expected result
		expectedResult bool
		expectedClaims map[string]interface{}
	}{
		{
			name: "Test allow with claims",
			rule: `
				allow = true
				claims = {"foo": "bar"}
			`,
			expectedResult: true,
			expectedClaims: map[string]interface{}{
				"foo": "bar",
			},
		},
		{
			name: "Test deny without claims",
			rule: `
				allow = false
				claims = {}
			`,
			expectedResult: false,
			expectedClaims: map[string]interface{}{},
		},
		{
			name: "Test deny with claims",
			rule: `
				allow = false
				claims = {"foo": "bar"}
			`,
			expectedResult: false,
			expectedClaims: map[string]interface{}{},
		},
		{
			name: "Test allow without claims",
			rule: `
				allow = true
				claims = {}
			`,
			expectedResult: true,
			expectedClaims: map[string]interface{}{},
		},
		{
			name: "Test allow with claims and input",
			rule: `
				allow = input.requested.foo == "bar"
				claims = {"foo": "bar"}
			`,
			requestData: map[string]interface{}{
				"foo": "bar",
			},
			expectedResult: true,
			expectedClaims: map[string]interface{}{
				"foo": "bar",
			},
		},
		{
			name: "Test deny without claims and input",
			rule: `
				allow = input.requested.foo == "foo"
				claims = {}
			`,
			requestData: map[string]interface{}{
				"foo": "bar",
			},
			expectedResult: false,
			expectedClaims: map[string]interface{}{},
		},
		{
			name: "Invalid rule",
			rule: `
				other = true
				claimZ = {"foo": "bar"}
			`,
			requestData:    map[string]interface{}{},
			expectedResult: false,
			expectedClaims: map[string]interface{}{},
		},
		{
			name: "Invalid claims",
			rule: `
				allow = true
				claims = "foo"
			`,
			requestData:    map[string]interface{}{},
			expectedResult: true,
			expectedClaims: map[string]interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			rule, _ := rego.New(
				rego.Query("allow = data.test.allow; claims = data.test.claims"),
				rego.Module("test.rego", "package test\n"+tc.rule+"\n"),
			).PrepareForEval(context.TODO())
			// Create a new AccessValidatior instance
			v := &AccessValidatior{
				context: context.Background(),
				rego:    &rule,
			}

			// Test with valid input
			requestData := tc.requestData
			upstreamResponse := &logical.Response{
				Auth: &logical.Auth{
					InternalData: map[string]interface{}{
						"canonical_arn":  "arn:aws:iam::123456789012:role/role-name",
						"account_id":     "123456789012",
						"client_user_id": "AIDAJQABLZS4A3QDU576Q",
					},
				},
			}
			result := v.HasAccess(requestData, upstreamResponse)
			if result.Allowed != tc.expectedResult {
				t.Errorf("Unexpected result: %v", result)
			}
			if len(result.AdditionalClaims) != len(tc.expectedClaims) {
				t.Errorf("Unexpected additional claims: %v", result.AdditionalClaims)
			}
			for k, v := range tc.expectedClaims {
				if result.AdditionalClaims[k] != v {
					t.Errorf("Unexpected additional claims: %v", result.AdditionalClaims)
				}
			}
		})
	}

}