package main

import (
	"context"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/open-policy-agent/opa/rego"
)

type AccessValidatior struct {
	rego    *rego.PreparedEvalQuery
	context context.Context
}

type ValidatorResult struct {
	Allow  bool
	Claims map[string]interface{}
}

func Deny() ValidatorResult {
	return ValidatorResult{
		Allow: false,
	}
}

func Allow(claims map[string]interface{}) ValidatorResult {
	return ValidatorResult{
		Allow:  true,
		Claims: claims,
	}
}

func NewAccessValidatorInternal(module string) *AccessValidatior{
	ctx := context.Background()

	query, err := rego.New(
		rego.Query("allow = data.awsiamjwt.authz.allow; claims = data.awsiamjwt.authz.claims"),
		rego.Module("awsiamjwt.rego", module),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatalf("Failed to prepare query: %v", err)
		return nil
	}

	return &AccessValidatior{
		rego:    &query,
		context: ctx,
	}
}

func NewAccessValidator() *AccessValidatior {
	customPolicyFile := os.Getenv("OPA_POLICY_FILE")
	if customPolicyFile != "" {
		if _, err := os.Stat(customPolicyFile); os.IsNotExist(err) {
			log.Fatalf("%s does not exist", customPolicyFile)
			return nil
		}
		return NewAccessValidatorFromFile(customPolicyFile)
	} else {
		return NewAccessValidatorFromDefault()
	}
}

func NewAccessValidatorFromFile(filePath string) *AccessValidatior {
	policy, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("Failed to read policy file: %v", err)
		return nil
	}
	return NewAccessValidatorInternal(string(policy))
}

func NewAccessValidatorFromDefault() *AccessValidatior {
	return NewAccessValidatorInternal(`
	package awsiamjwt.authz

	default allow := true
	default claims := {}
	`)
}

func (v *AccessValidatior) HasAccess(input map[string]interface{}) ValidatorResult {
	results, err := v.rego.Eval(v.context, rego.EvalInput(input))
	if err != nil || len(results) == 0 {
		log.Warnf("Failed to evaluate policy: %v", err)
		return Deny()
	} else if allowResult, ok := results[0].Bindings["allow"].(bool); !ok {
		log.Warnf("allowResult is not a bool: %v", allowResult)
		return Deny()
	} else {
		if !allowResult {
			log.Info("Access denied by policy")
			return Deny()
		}

		if additionalClaimsResult, ok := results[0].Bindings["claims"].(map[string]interface{}); ok {
			log.Infof("Access allowed by policy, additional claims: %v", additionalClaimsResult)
			return Allow(additionalClaimsResult)
		}

		log.Info("Access allowed by policy. No additional claims.")
		return Allow(map[string]interface{}{})
	}
}
