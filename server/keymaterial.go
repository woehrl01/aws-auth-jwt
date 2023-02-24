package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

	pemDataPublic, err := os.ReadFile(publicKeyLocation)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}

	log.Info("Loaded private and public key from file")
	return pemDataPrivate, pemDataPublic, nil
}

func getPrivateKeys() ([]byte, []byte, error) {
	privateKeyLocation := "/certs/private.pem"
	if os.Getenv("PRIVATE_KEY_FILE") != "" {
		privateKeyLocation = os.Getenv("PRIVATE_KEY_FILE")
	}

	publicKeyLocation := "/certs/public.pem"
	if os.Getenv("PUBLIC_KEY_FILE") != "" {
		publicKeyLocation = os.Getenv("PUBLIC_KEY_FILE")
	}

	allFilesExist := true
	if _, err := os.Stat(privateKeyLocation); os.IsNotExist(err) {
		log.Info("private.pem does not exist")
		allFilesExist = false
	}

	if _, err := os.Stat(publicKeyLocation); os.IsNotExist(err) {
		log.Info("public.pem does not exist")
		allFilesExist = false
	}

	if allFilesExist {
		return getPrivateKeysFromFile(privateKeyLocation, publicKeyLocation)
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

	kid := "1"

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
