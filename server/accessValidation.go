package main

import (
	"context"
	"io/fs"

	log "github.com/sirupsen/logrus"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/print"
)

type AccessValidatior struct {
	rego    *rego.PreparedEvalQuery
	context context.Context
}

type validator interface {
	HasAccess(requestData map[string]interface{}, upstreamResponse UpstreamResponse) ValidatorResult
}

type ValidatorResult struct {
	Allowed          bool
	AdditionalClaims map[string]interface{}
}

func Deny() ValidatorResult {
	return ValidatorResult{
		Allowed: false,
	}
}

func Allow(claims map[string]interface{}) ValidatorResult {
	return ValidatorResult{
		Allowed:          true,
		AdditionalClaims: claims,
	}
}

type regoLogWrapper struct{}

func (l regoLogWrapper) Print(ctx print.Context, s string) error {
	log.WithFields(log.Fields{"location": ctx.Location}).Debug(s)
	return nil
}

func NewAccessValidatorInternal(moduleLoader func(r *rego.Rego)) *AccessValidatior {
	ctx := context.Background()

	query, err := rego.New(
		rego.Query(`
		allow = data.awsauthjwt.authz.allow; 
		claims = data.awsauthjwt.authz.claims
		`),
		moduleLoader,
		rego.EnablePrintStatements(settings.getLogLevel() == log.DebugLevel),
		rego.PrintHook(&regoLogWrapper{}),
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
	log.Infof("Load rego policy from: %s", filePath)

	onlyFirstLevel := func(abspath string, info fs.FileInfo, depth int) bool {
		// we only want to load the first level of the directory
		// because in a kube environment, the directory is a symlink
		// and we don't want to load the symlinked files as this would
		// cause loading the same file twice
		return depth > 1 // return true to skip the path
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

func (v *AccessValidatior) HasAccess(requestData map[string]interface{}, upstreamResponse UpstreamResponse) ValidatorResult {
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

func buildValidationInput(requestData map[string]interface{}, upstreamResponse UpstreamResponse) map[string]interface{} {
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
			"arn":        upstreamResponse.Data["canonical_arn"],
			"account_id": upstreamResponse.Data["account_id"],
			"user_id":    upstreamResponse.Data["client_user_id"],
		},
	}

	return input
}
