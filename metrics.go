package metrics

import "github.com/prometheus/client_golang/prometheus"

const namespace = "caddy"

var (
	requestCount    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
	responseStatus  *prometheus.CounterVec
	responseLatency *prometheus.HistogramVec
)

func define(subsystem string) {
	if subsystem == "" {
		subsystem = "http"
	}
	requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "request_count_total",
		Help:      "Counter of HTTP(S) requests made.",
	}, []string{"host", "family", "proto"})

	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "request_duration_seconds",
		Help:      "Histogram of the time (in seconds) each request took.",
		Buckets:   append(prometheus.DefBuckets, 15, 20, 30, 60, 120, 180, 240, 480, 960),
	}, []string{"host", "family", "proto"})

	responseSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "response_size_bytes",
		Help:      "Size of the returns response in bytes.",
		Buckets:   []float64{0, 500, 1000, 2000, 3000, 4000, 5000, 10000, 20000, 30000, 50000, 1e5, 5e5, 1e6, 2e6, 3e6, 4e6, 5e6, 10e6},
	}, []string{"host"})

	responseStatus = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "response_status_count_total",
		Help:      "Counter of response status codes.",
	}, []string{"host", "status"})

	responseLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "response_latency_seconds",
		Help:      "Histogram of the time (in seconds) until the first write for each request.",
		Buckets:   append(prometheus.DefBuckets, 15, 20, 30, 60, 120, 180, 240, 480, 960),
	}, []string{"host"})
}
