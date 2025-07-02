package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	recordedSessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "recorded_sessions_active",
		Help:      "Number of currently active WebSocket sessions",
	})

	recordedSessionDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "recorded_session_duration_seconds",
		Help:      "Duration of WebSocket session in seconds",
		Buckets:   []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
	})

	recordedSessionErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "recorded_session_errors_total",
		Help:      "Total number of WebSocket sessions failures",
	}, []string{"error_type"})
)

func registerRecordedSessionMetrics(registry *prometheus.Registry) {
	registry.MustRegister(recordedSessionsActive, recordedSessionDuration)
}

func HandleRecordedSession(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordedSessionsActive.Inc()
		defer recordedSessionsActive.Dec()

		timer := prometheus.NewTimer(recordedSessionDuration)
		defer timer.ObserveDuration()

		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrHandlerTimeout { //nolint:err113,errorlint
					recordedSessionErrors.WithLabelValues("timeout").Inc()
				}

				// Re-panic to let others handle it
				panic(recovered)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
