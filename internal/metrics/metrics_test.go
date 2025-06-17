package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterMetricVars(t *testing.T) {
	InitMetricsCollectors()

	testRegistry := prometheus.NewRegistry()
	RegisterMetricVars(testRegistry)

	metricFamilies, err := testRegistry.Gather()
	require.NoError(t, err)

	// Note that this list does not contain all metrics because the Go process metrics depend on the operating system.
	// Some operating systems return more metrics.
	expectedMetrics := []string{
		// Build Info Metric
		"twingate_gateway_build_info",

		// Go Metrics
		"go_gc_duration_seconds",
		"go_gc_gogc_percent",
		"go_gc_gomemlimit_bytes",
		"go_goroutines",
		"go_info",
		"go_memstats_alloc_bytes",
		"go_memstats_alloc_bytes_total",
		"go_memstats_buck_hash_sys_bytes",
		"go_memstats_frees_total",
		"go_memstats_gc_sys_bytes",
		"go_memstats_heap_alloc_bytes",
		"go_memstats_heap_idle_bytes",
		"go_memstats_heap_inuse_bytes",
		"go_memstats_heap_objects",
		"go_memstats_heap_released_bytes",
		"go_memstats_heap_sys_bytes",
		"go_memstats_last_gc_time_seconds",
		"go_memstats_mallocs_total",
		"go_memstats_mcache_inuse_bytes",
		"go_memstats_mcache_sys_bytes",
		"go_memstats_mspan_inuse_bytes",
		"go_memstats_mspan_sys_bytes",
		"go_memstats_next_gc_bytes",
		"go_memstats_other_sys_bytes",
		"go_memstats_stack_inuse_bytes",
		"go_memstats_stack_sys_bytes",
		"go_memstats_sys_bytes",
		"go_sched_gomaxprocs_threads",
		"go_threads",

		// Go Process Metrics
		"twingate_gateway_process_cpu_seconds_total",
		"twingate_gateway_process_max_fds",
		"twingate_gateway_process_open_fds",
		"twingate_gateway_process_resident_memory_bytes",
		"twingate_gateway_process_start_time_seconds",
		"twingate_gateway_process_virtual_memory_bytes",
		"twingate_gateway_process_virtual_memory_max_bytes",
	}

	registeredMetrics := make([]string, len(metricFamilies))
	for i, mf := range metricFamilies {
		registeredMetrics[i] = mf.GetName()
	}

	assert.Subset(t, registeredMetrics, expectedMetrics)
}
