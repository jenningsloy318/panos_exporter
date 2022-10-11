package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	SystemResourceUtilSubsystem = "system_top"
)

type SystemResourceUtilCollector struct {
	ctx                   context.Context
	metrics               map[string]SystemResourceUtilMetric
	panosClient           *panos.PaloAlto
	collectorScrapeStatus *prometheus.GaugeVec
}

type SystemResourceUtilMetric struct {
	desc *prometheus.Desc
}

func NewSystemResourceUtilCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *SystemResourceUtilCollector {
	return &SystemResourceUtilCollector{
		ctx:         ctx,
		panosClient: panosClient,
		collectorScrapeStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "collector_scrape_status",
				Help:      "collector_scrape_status",
			},
			[]string{"collector"},
		),
	}
}

func (d *SystemResourceUtilCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range d.metrics {
		ch <- metric.desc
	}
	d.collectorScrapeStatus.Describe(ch)

}

func (d *SystemResourceUtilCollector) Collect(ch chan<- prometheus.Metric) {
	dcontext, dCancel := context.WithCancel(d.ctx)
	defer dCancel()

	//initialize metrics map allows later assignment
	d.metrics = map[string]SystemResourceUtilMetric{}

	SystemResourceUtilData, err := d.panosClient.GetSystemsResourceUtilData(dcontext)
	if err != nil {
		log.Errorf("Error getting System resource utilization data, %s", err)
		return
	}

	cpuMetrics := make(map[string]string)
	memMetrics := make(map[string]string)
	swapMetrics := make(map[string]string)
	topList := strings.Split(SystemResourceUtilData.Result, "\n")

	for _, line := range topList {
		if strings.Contains(line, "Cpu(s):") {
			newCPUline := strings.ReplaceAll(line, "%", " ")
			for _, cpuItem := range strings.Split(strings.Split(newCPUline, ":")[1], ",") {
				valueSlice := strings.Split(strings.TrimSpace(cpuItem), " ")
				cpuMetrics[valueSlice[1]] = valueSlice[0]
			}

		}
		if strings.Contains(line, "Mem:") {
			for _, memItem := range strings.Split(strings.Split(line, ":")[1], ",") {
				valueSlice := strings.Split(strings.TrimSpace(memItem), " ")
				valueName := valueSlice[1]
				valueNumber := strings.ReplaceAll(valueSlice[0], "k", "")
				memMetrics[valueName] = valueNumber
			}

		}
		if strings.Contains(line, "Swap:") {
			for _, swapItem := range strings.Split(strings.Split(line, ":")[1], ",") {

				valueSlice := strings.Split(strings.TrimSpace(swapItem), " ")
				valueName := valueSlice[1]
				valueNumber := strings.ReplaceAll(valueSlice[0], "k", "")
				swapMetrics[valueName] = valueNumber

			}
		}
	}

	fmt.Println(cpuMetrics, memMetrics, swapMetrics)

	// data plane load  By Group

	// data plane resource utilization

	d.collectorScrapeStatus.WithLabelValues("data_processor_resource_utilization").Set(float64(1))
}
