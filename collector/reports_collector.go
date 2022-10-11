package collector

import (
	"context"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	ReportSubsystem = "report"
)

type ReportCollector struct {
	ctx                   context.Context
	panosClient           *panos.PaloAlto
	metrics               map[string]ReportMetric
	collectorScrapeStatus *prometheus.GaugeVec
}

type ReportMetric struct {
	desc *prometheus.Desc
}

func NewReportCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *ReportCollector {

	return &ReportCollector{
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

func (i *ReportCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range i.metrics {
		ch <- metric.desc
	}
	i.collectorScrapeStatus.Describe(ch)
}

func (i *ReportCollector) Collect(ch chan<- prometheus.Metric) {
	iContext, iCancel := context.WithCancel(i.ctx)
	defer iCancel()
	i.metrics = map[string]ReportMetric{}

	i.collectTopBlockedWebsites(ch, iContext)
	i.collectTopSources(ch, iContext)
	i.collectTopDestinations(ch, iContext)

	i.collectorScrapeStatus.WithLabelValues("Report").Set(float64(1))
}

func (i *ReportCollector) collectTopBlockedWebsites(ch chan<- prometheus.Metric, iContext context.Context) {
	ReportResponse, err := i.panosClient.GetTopBlockedWebsites(iContext)
	if err != nil {
		log.Errorf("Error getting report, %s", err)
		return
	}

	topBlockedWebsites := ReportResponse.Result.BlockedWebsites
	labelNames := []string{"domain", "category", "destination", "resolvedDestination"}

	for _, website := range topBlockedWebsites[0:15] {
		topBlockedWebsitesMetric := ReportMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, ReportSubsystem, "topblockedwebsites"),
				"Report: top blocked websites - blocked counter",
				labelNames,
				nil,
			),
		}
		i.metrics["top-blocked-website"] = topBlockedWebsitesMetric
		labelValues := []string{"report", "predefined", website.Destination, website.ResolvedDestination}
		ch <- prometheus.MustNewConstMetric(topBlockedWebsitesMetric.desc, prometheus.GaugeValue, float64(website.RepeatCount), labelValues...)
	}
}

func (i *ReportCollector) collectTopSources(ch chan<- prometheus.Metric, iContext context.Context) {
	ReportResponse, err := i.panosClient.GetTopSources(iContext)
	if err != nil {
		log.Errorf("Error getting report, %s", err)
		return
	}

	topSources := ReportResponse.Result.Sources
	labelNames := []string{"domain", "category", "source", "resolvedSource"}

	for _, source := range topSources[0:10] {
		topSourcesMetric := ReportMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, ReportSubsystem, "topsources"),
				"Report: top sources - session count",
				labelNames,
				nil,
			),
		}
		i.metrics["top-sources"] = topSourcesMetric
		labelValues := []string{"report", "predefined", source.Source, source.ResolvedSource}
		ch <- prometheus.MustNewConstMetric(topSourcesMetric.desc, prometheus.GaugeValue, float64(source.Sessions), labelValues...)
	}
}

func (i *ReportCollector) collectTopDestinations(ch chan<- prometheus.Metric, iContext context.Context) {
	ReportResponse, err := i.panosClient.GetTopDestinations(iContext)
	if err != nil {
		log.Errorf("Error getting report, %s", err)
		return
	}

	topDestinations := ReportResponse.Result.Destinations
	labelNames := []string{"domain", "category", "destination", "resolvedDestination"}

	for _, destination := range topDestinations[0:10] {
		topDestinationsMetric := ReportMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, ReportSubsystem, "topdestinations"),
				"Report: top destinations - session count",
				labelNames,
				nil,
			),
		}
		i.metrics["top-destinations"] = topDestinationsMetric
		labelValues := []string{"report", "predefined", destination.Destination, destination.ResolvedDestination}
		ch <- prometheus.MustNewConstMetric(topDestinationsMetric.desc, prometheus.GaugeValue, float64(destination.Sessions), labelValues...)
	}
}
