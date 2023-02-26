package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	log "github.com/sirupsen/logrus"
)

func TestAccessValidatior_HasAccess(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)

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
		{
			name: "Invalid allow",
			rule: `
				allow = "foo"
				claims = {"foo": "bar"}
			`,
			requestData:    map[string]interface{}{},
			expectedResult: false,
			expectedClaims: map[string]interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			rule, _ := rego.New(
				rego.Query("allow = data.test.allow; claims = data.test.claims"),
				rego.Module("test.rego", "package test\n"+tc.rule+"\n"),
			).PrepareForEval(context.TODO())

			v := &AccessValidatior{
				context: context.Background(),
				rego:    &rule,
			}

			requestData := tc.requestData
			upstreamResponse := UpstreamResponseSuccess{
				Arn:       "arn:aws:sts::123456789012:assumed-role/role-name/role-session-name",
				AccountId: "123456789012",
				UserId:    "AIDAJQABLZS4A3QDU576Q",
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
