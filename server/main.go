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
	policyEvaluationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "aws_auth_jwt_policy_evaluation_duration_seconds",
		Help:    "The duration of policy evaluation",
		Buckets: []float64{0.0, 0.1, 1.0, 5.0},
	})
	stsBackendDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "aws_auth_jwt_sts_backend_duration_seconds",
		Help:    "The duration of the STS backend call",
		Buckets: []float64{0.0, 0.1, 1.0, 5.0},
	})
)

func startServer() {
	keyMaterial, err := getKeyMaterial()
	if err != nil {
		log.Fatalf("Could not get key material: %s", err)
		return
	}

	loginHandler := &loginHandler{
		keyMaterial: &keyMaterial.private,
		upstream:    NewVaultUpstream(),
		validator:   NewAccessValidator(),
	}

	wellKnownHandler := &wellKnownHandler{
		keyMaterial: &keyMaterial.public,
	}

	http.Handle("/v1/auth/aws/login", loginHandler)
	http.Handle("/.well-known/jwks.json", wellKnownHandler)
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/healthz", healthcheck.Handler(healthcheck.WithTimeout(5*time.Second)))

	log.Info("Starting server on port 8081")
	
	http.ListenAndServe(":8081", nil)

}

func initLogging() {
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(settings.getLogLevel())
}

func main() {
	initSettings()
	initLogging()
	startServer()
}
