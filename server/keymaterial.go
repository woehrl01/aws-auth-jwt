package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

func getPrivateKeysFromFile(privateKeyLocation string, publicKeyLocation string) ([]byte, []byte, error) {
	pemDataPrivate, err := os.ReadFile(privateKeyLocation)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	log.Infof("Loaded private key from %s", privateKeyLocation)

	pemDataPublic, err := os.ReadFile(publicKeyLocation)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	log.Infof("Loaded public key from %s", publicKeyLocation)
	return pemDataPrivate, pemDataPublic, nil
}

func getPrivateKeys() ([]byte, []byte, error) {
	if settings.hasCustomKeys() {
		return getPrivateKeysFromFile(settings.privateKeyFile, settings.publicKeyFile)
	} else {
		return getPrivateKeysGenerated()
	}
}

func getPrivateKeysGenerated() ([]byte, []byte, error) {
	// Generate a new private key
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return nil, nil, err
	}

	privateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	pemDataPrivate := pem.EncodeToMemory(privateKey)

	asn1Bytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("unable to marshal public key: %v", err)
		return nil, nil, err
	}

	publicKey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemDataPublic := pem.EncodeToMemory(publicKey)

	log.Info("generated private and public key")

	return pemDataPrivate, pemDataPublic, nil
}

type keyMaterial struct {
	public  keyMaterialPublic
	private keyMaterialPrivate
}

type keyMaterialPublic struct {
	pem   []byte
	key   *rsa.PublicKey
	keyID string
}

type keyMaterialPrivate struct {
	pem   []byte
	key   *rsa.PrivateKey
	keyID string
}

func getKeyMaterial() (*keyMaterial, error) {

	pemDataPrivate, pemDataPublic, err := getPrivateKeys()
	if err != nil {
		log.Fatalf("Could not get private keys: %s", err)
		return nil, err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemDataPrivate)
	if err != nil {
		log.Fatalf("Error parsing private key: %s", err)
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pemDataPublic)
	if err != nil {
		log.Fatalf("Error parsing public key: %s", err)
		return nil, err
	}

	thumbprint := sha256.Sum256(pemDataPublic)
	kid := base64.RawURLEncoding.EncodeToString(thumbprint[:])

	return &keyMaterial{
		private: keyMaterialPrivate{
			pem:   pemDataPrivate,
			key:   privateKey,
			keyID: kid,
		},
		public: keyMaterialPublic{
			pem:   pemDataPublic,
			key:   publicKey,
			keyID: kid,
		},
	}, nil
}
