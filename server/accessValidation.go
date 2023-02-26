package main

import (
	"context"
	"io/fs"

	"github.com/hashicorp/vault/sdk/logical"
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

func NewAccessValidatorInternal(moduleLoader func(r *rego.Rego)) *AccessValidatior {
	ctx := context.Background()

	query, err := rego.New(
		rego.Query(`
		allow = data.awsauthjwt.authz.allow; 
		claims = data.awsauthjwt.authz.claims;
		`),
		moduleLoader,
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
	if settings.hasCustomPolicy() {
		return NewAccessValidatorFromFile(settings.policyFolder)
	} else {
		return NewAccessValidatorFromDefault()
	}
}

func NewAccessValidatorFromFile(filePath string) *AccessValidatior {
	log.Infof("Load rego policy from file: %s", filePath)

	onlyFirstLevel := func(abspath string, info fs.FileInfo, depth int) bool {
		return depth != 0
	}

	return NewAccessValidatorInternal(rego.Load([]string{filePath}, onlyFirstLevel))
}

func NewAccessValidatorFromDefault() *AccessValidatior {
	log.Infoln("Loaded default rego policy")

	return NewAccessValidatorInternal(rego.Module("awsauthjwt.rego", `
	package awsauthjwt.authz

	default allow := true
	default claims := {}
	`))
}

func (v *AccessValidatior) HasAccess(requestData map[string]interface{}, upstreamResponse *logical.Response) ValidatorResult {
	defer measureTime(policyEvaluationDuration)

	input := buildValidationInput(requestData, upstreamResponse)

	results, err := v.rego.Eval(v.context, rego.EvalInput(input))
	
	if err != nil || len(results) == 0 {
		log.Warnf("Failed to evaluate policy: %v", err)
		return Deny()
	} else if allowResult, ok := results[0].Bindings["allow"].(bool); !ok {
		log.Warnf("allowResult is not a bool: %v", allowResult)
		return Deny()
	} else if !allowResult {
		log.Debug("Access denied by policy")
		return Deny()
	} else if additionalClaimsResult, ok := results[0].Bindings["claims"].(map[string]interface{}); ok {
		log.Debugf("Access allowed by policy, additional claims: %v", additionalClaimsResult)
		return Allow(additionalClaimsResult)
	} else {
		log.Debug("Access allowed by policy. No additional claims.")
		return Allow(map[string]interface{}{})
	}
}

func buildValidationInput(requestData map[string]interface{}, upstreamResponse *logical.Response) map[string]interface{} {
	inputRequested := map[string]interface{}{}
	for key, value := range requestData {
		switch key {
		case "iam_http_request_method", "iam_request_url", "iam_request_body", "iam_request_headers":
			continue
		default:
			inputRequested[key] = value
		}
	}

	input := map[string]interface{}{
		"requested": inputRequested,
		"sts": map[string]interface{}{
			"arn":        upstreamResponse.Auth.InternalData["canonical_arn"],
			"account_id": upstreamResponse.Auth.InternalData["account_id"],
			"user_id":    upstreamResponse.Auth.InternalData["client_user_id"],
		},
	}

	return input
}
