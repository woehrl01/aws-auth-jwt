# AWS Auth JWT

AWS Auth JWT is a service that allows you to authenticate via an IAM role and returns a signed JSON Web Token (JWT) that you can use for authorization. It provides a JWKS endpoint to verify the token.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
<!-- param::isFolding::false:: -->
<!-- param::isNotitle::true:: -->
<!-- param::isCustomMode::true:: -->

<p align="center">
<a href="#features">Features</a>
<span>|</span>
<a href="#environment-variables">Environment Variables</a>
<span>|</span>
<a href="#usage-with-opa">Usage with OPA</a>
<span>|</span>
<a href="#usage-with-cert-manager">Usage with cert-manager</a>
</p>

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Features

- Authenticate via IAM role
- Generate signed JSON Web Token (JWT)
- Provide JWKS endpoint for token verification
- Open Policy Agent (OPA) integration for authorization and additional claims
- Works great with cert-manager for automatic certificate management

## Environment Variables

- `ISSUER`: This is the name of the token issuer. The token issuer is the entity that creates and signs the token, and is typically used to identify the source of the token.
- `PUBLIC_KEY_FILE`: This is the path to the public key file used to verify the token signature. The public key file contains the public key that was used to sign the token, and is required to verify the token's authenticity.
- `PRIVATE_KEY_FILE`: This is the path to the private key file used to sign the token. The private key file contains the private key that is used to sign the token, and should be kept secret.
- `TOKEN_EXPIRATION_HOURS`: This is the number of hours that the token will be valid for, after which it will expire and a new token will need to be generated. Default, is set to "1", which means that the token will be valid for one hour.
- `OPA_POLICY_FILE`: This is the path to the Open Policy Agent (OPA) policy file. The policy file contains the authorization rules and additional claims that will be added to the token. If this is not set, then the token will only contain the IAM role and the default claims.

## Usage with OPA

The following example shows how to use OPA to authorize the token and add additional claims to the token. The package name must be `awsiamjwt.authz`. You can use the `input` variable to access the IAM role and account ID.

### Input

The input variable is a JSON object that contains the following fields:

```json
{
    "requested": {
        "role": "awesome-role"
    },
    "sts":{
        "arn":        "arn:aws:iam::123456789012:role/admin",
        "account_id": "123456789012"
    }
}
```

### Output

The output variables of the policy file are:

- `allow`: This is a boolean value that determines if the token is allowed or not. If this is set to `true`, then the token will be allowed. If this is set to `false`, then the token will be denied.
- `claims`: This is a JSON object that contains the additional claims that will be added to the token. The key is the claim name, and the value is the claim value.

### Example

An example policy file is shown below:

```rego
package awsiamjwt.authz

import future.keywords.if

default allow := false
default claims := {}

allow if {
    input.sts.account_id = ["123456789012"][_]
}

claims[name] if {
	input.sts.arn == "arn:aws:iam::123456789012:role/admin"
    name := "admin"
}	

claims[name] if {
	input.sts.arn == "arn:aws:iam::123456789012:role/admin"
    name := "superadmin"
}	

claims[name] = val {
	input.requested.role == "awesome-role"
    name := "customerid"
    val := 1234
}	
```


## Usage with cert-manager

The following example shows how to use cert-manager to automatically generate a certificate for the JWT to sign the token.

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: jwt-issuer
spec:
    ca:
        secretName: jwt-issuer
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: jwt-certificate
spec:
    secretName: jwt-certificate
    commonName: jwt
    dnsNames:
        - jwt
    issuerRef:
        name: jwt-issuer
        kind: Issuer
    keyAlgorithm: rsa
    keyEncoding: pkcs1
    keySize: 2048
    usages:
        - signing
```
