package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type wellKnownHandler struct{
	keyMaterial * keyMaterialPublic
}

func (h*wellKnownHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwksTotal.Inc()
		log.Debug("Received request: %s", r.URL.Path)

		// Check if the request is a GET
		if r.Method != "GET" {
			http.NotFound(w, r)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": h.keyMaterial.keyID,
					"alg": "RS256",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(h.keyMaterial.key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(h.keyMaterial.key.E)).Bytes()),
					"x5c": []string{
						base64.StdEncoding.EncodeToString(h.keyMaterial.pem),
					},
				},
			},
		})
	}
}
