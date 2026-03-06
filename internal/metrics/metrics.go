// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const Namespace = "twingate_gateway"

type Config struct {
	Port     int
	Registry *prometheus.Registry
}

type Server struct {
	server *http.Server
}

func NewServer(config Config) *Server {
	registerCoreMetrics(config.Registry)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(
		config.Registry,
		promhttp.HandlerFor(config.Registry, promhttp.HandlerOpts{Registry: config.Registry}),
	))

	server := &http.Server{
		// G112 - Protect against Slowloris attack
		ReadHeaderTimeout: 5 * time.Second,

		Addr:    fmt.Sprintf(":%v", config.Port),
		Handler: mux,
	}

	return &Server{server: server}
}

func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func registerCoreMetrics(reg *prometheus.Registry) {
	goCollector := collectors.NewGoCollector()

	processCollector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})

	reg.MustRegister(goCollector, processCollector)
}
