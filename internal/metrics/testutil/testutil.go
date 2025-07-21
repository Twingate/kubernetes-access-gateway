// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package testutil

import dto "github.com/prometheus/client_model/go"

func ExtractLabelsFromMetrics(metricFamilies []*dto.MetricFamily) map[string]map[string]string {
	labelsByMetric := make(map[string]map[string]string, len(metricFamilies))

	for _, family := range metricFamilies {
		labels := make(map[string]string)
		for _, label := range family.GetMetric()[0].GetLabel() {
			labels[label.GetName()] = label.GetValue()
		}

		labelsByMetric[family.GetName()] = labels
	}

	return labelsByMetric
}
