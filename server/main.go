package main

import (
	"net/http"
	"os"
	"time"

	"github.com/etherlabsio/healthcheck/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	loginRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aws_auth_jwt_login_requests_total",
		Help: "The total number of login requests",
	})
	successfulLoginsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aws_auth_jwt_successful_login_total",
		Help: "The total number of successful login requests",
	}, []string{"role"})
	failedLoginsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aws_auth_jwt_failed_login_total",
		Help: "The total number of failed login requests",
	})
	jwksTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aws_auth_jwt_jwks_total",
		Help: "The total number of jwks requests",
	})
)

func startServer() {
	configuration := setupConfig()

	keyMaterial, err := getKeyMaterial()
	if err != nil {
		log.Fatalf("Could not get key material: %s", err)
		return
	}

	loginHandler := &loginHandler{
		keyMaterial:   &keyMaterial.private,
		configuration: configuration,
		validator:     NewAccessValidator(),
	}

	wellKnownHandler := &wellKnownHandler{
		keyMaterial: &keyMaterial.public,
	}

	http.HandleFunc("/v1/auth/aws/login", loginHandler.Handler())
	http.HandleFunc("/.well-known/jwks.json", wellKnownHandler.Handler())
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/healthz", healthcheck.Handler(healthcheck.WithTimeout(5*time.Second)))

	log.Info("Starting server on port 8081")
	http.ListenAndServe(":8081", nil)
}

func initLogging() {
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {
	initLogging()
	startServer()
}
