package collector

import (
	"context"
	"fmt"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	DataProcessorResourceUtilSubsystem = "data_plane_resource_util"
)

type DataProcessorResourceUtilCollector struct {
	ctx                   context.Context
	metrics               map[string]DataProcessorResourceUtilMetric
	panosClient           *panos.PaloAlto
	collectorScrapeStatus *prometheus.GaugeVec
}

type DataProcessorResourceUtilMetric struct {
	desc *prometheus.Desc
}

func NewDataProcessorResourceUtilCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *DataProcessorResourceUtilCollector {
	return &DataProcessorResourceUtilCollector{
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

func (d *DataProcessorResourceUtilCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range d.metrics {
		ch <- metric.desc
	}
	d.collectorScrapeStatus.Describe(ch)

}

func (d *DataProcessorResourceUtilCollector) Collect(ch chan<- prometheus.Metric) {
	dcontext, dCancel := context.WithCancel(d.ctx)
	defer dCancel()

	//initialize metrics map allows later assignment
	d.metrics = map[string]DataProcessorResourceUtilMetric{}

	DataProcessorResourceUtilData, err := d.panosClient.GetDataProcessorsResourceUtilData(dcontext)
	if err != nil {
		log.Errorf("Error getting DataProcessor resource utilization data, %s", err)
		return
	}

	DataProcessorResourceUtilDataContent := DataProcessorResourceUtilData.Result.DataProcessorsResourceUtil

	// data plane load average
	cpuLoadAverageEntries := DataProcessorResourceUtilDataContent.CPULoadAverage
	for _, entry := range cpuLoadAverageEntries {
		labelNames := []string{"domain", "coreid", "dp"}
		labelValues := []string{"data_plane", entry.CoreID, "dp0"}
		metricName := "cpu_load_average"
		metricDesc := fmt.Sprintf("data plane cpu load average")
		newDataProcessorResourceUtilMetric := DataProcessorResourceUtilMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, DataProcessorResourceUtilSubsystem, metricName),
				metricDesc,
				labelNames,
				nil,
			),
		}
		d.metrics[metricName] = newDataProcessorResourceUtilMetric
		ch <- prometheus.MustNewConstMetric(newDataProcessorResourceUtilMetric.desc, prometheus.GaugeValue, entry.Value, labelValues...)
	}

	// data plane load maximum
	cpuLoadMaximumEntries := DataProcessorResourceUtilDataContent.CPULoadMaximum
	for _, entry := range cpuLoadMaximumEntries {
		labelNames := []string{"domain", "coreid", "dp"}
		labelValues := []string{"data_plane", entry.CoreID, "dp0"}
		metricName := "cpu_load_maximum"
		metricDesc := fmt.Sprintf("data plane cpu load maximum")
		newDataProcessorResourceUtilMetric := DataProcessorResourceUtilMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, DataProcessorResourceUtilSubsystem, metricName),
				metricDesc,
				labelNames,
				nil,
			),
		}
		d.metrics[metricName] = newDataProcessorResourceUtilMetric
		ch <- prometheus.MustNewConstMetric(newDataProcessorResourceUtilMetric.desc, prometheus.GaugeValue, entry.Value, labelValues...)
	}

	// data plane load  By Group

	// data plane resource utilization

	d.collectorScrapeStatus.WithLabelValues("data_processor_resource_utilization").Set(float64(1))
}
