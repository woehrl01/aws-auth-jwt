package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func measureTime(promHistogram prometheus.Histogram) func() {
	start := time.Now()
	return func() {
		promHistogram.Observe(time.Since(start).Seconds())
	}
}
