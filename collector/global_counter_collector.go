package collector

import (
	"context"
	"fmt"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	//"net/url"
)

var (
	GlobalCounterSubsystem  = "global_counter"
	GlobalCounterLabelNames = []string{"category", "rate", "aspect", "id", "severity", "data_processor", "domain"}
)

type GlobalCounterCollector struct {
	ctx                   context.Context
	metrics               map[string]GlobalCounterMetric
	panosClient           *panos.PaloAlto
	collectorScrapeStatus *prometheus.GaugeVec
}

type GlobalCounterMetric struct {
	desc *prometheus.Desc
}

func NewGlobalCounterCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *GlobalCounterCollector {

	return &GlobalCounterCollector{
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

func (g *GlobalCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range g.metrics {
		ch <- metric.desc
	}
	g.collectorScrapeStatus.Describe(ch)

}

func (g *GlobalCounterCollector) Collect(ch chan<- prometheus.Metric) {
	gContext, gCancel := context.WithCancel(g.ctx)
	defer gCancel()

	//initialize metrics map allows later assignment
	g.metrics = map[string]GlobalCounterMetric{}

	globalCounterData, err := g.panosClient.GetGlobalCounterData(gContext)
	if err != nil {
		log.Errorf("Error getting global counter data, %s", err)
		return
	}
	dp := globalCounterData.Result.DP
	globalCounterDataEntries := globalCounterData.Result.GlobalCounter.GlobalCountersData.GlobalCounterEntriesData

	for _, entry := range globalCounterDataEntries {
		labelValues := []string{entry.Category, entry.Rate, entry.Aspect, entry.ID, entry.Severity, dp, "global_counter"}
		metricName := entry.Name

		metricDesc := fmt.Sprintf("global counter for %s", entry.Desc)
		newGlobalCounterMetric := GlobalCounterMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, GlobalCounterSubsystem, metricName),
				metricDesc,
				GlobalCounterLabelNames,
				nil,
			),
		}

		g.metrics[metricName] = newGlobalCounterMetric

		ch <- prometheus.MustNewConstMetric(newGlobalCounterMetric.desc, prometheus.GaugeValue, entry.Value, labelValues...)
	}
	g.collectorScrapeStatus.WithLabelValues("global_counter").Set(float64(1))
}
