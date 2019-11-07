package collector

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"context"
	"github.com/jenningsloy318/panos_exporter/panos"
	"github.com/prometheus/common/log"
	//"net/url"
)

var (
	GlobalCounterSubsystem  = "global_counter"
	GlobalCounterLabelNames = []string{"category", "rate", "aspect", "id", "severity","data-processors"}
)

type GlobalCounterCollector struct {
	ctx                     context.Context
	panosClient             *panos.PaloAlto
	collectorScrapeStatus   *prometheus.GaugeVec
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
	_, gCancel := context.WithCancel(g.ctx)
	defer gCancel()

	globalCounterData, err := g.panosClient.GetGlobalCounterData()
	if err != nil {
		log.Infof("Error getting global counter data, %s", err)
		return
	}
	dp := globalCounterData.Result.DP
	globalCounterDataEntries := globalCounterData.Result.GlobalCounter.GlobalCountersData.GlobalCounterEntriesData

	for _, entry := range globalCounterDataEntries {
		labelValues := []string{entry.Category, entry.Rate, entry.Aspect, entry.ID, entry.Severity,dp}
		metricName := entry.Name
		metricDesc := fmt.Sprintf("global counter for %s", entry.Desc)
		desc := prometheus.NewDesc(
			prometheus.BuildFQName(namespace, GlobalCounterSubsystem, metricName),
			metricDesc,
			GlobalCounterLabelNames,
			nil,
		)
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, entry.Value, labelValues...)
	}
	g.collectorScrapeStatus.WithLabelValues("global_counter").Set(float64(1))
}
