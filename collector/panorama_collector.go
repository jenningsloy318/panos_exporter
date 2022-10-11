package collector

import (
	"context"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

type PanoramaCollector struct {
	ctx                   context.Context
	panosClient           *panos.PaloAlto
	metrics               map[string]PanoramaMetric
	collectorScrapeStatus *prometheus.GaugeVec
}

type PanoramaMetric struct {
	desc *prometheus.Desc
}

func NewPanoramaCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *PanoramaCollector {

	return &PanoramaCollector{
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

func (i *PanoramaCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range i.metrics {
		ch <- metric.desc
	}
	i.collectorScrapeStatus.Describe(ch)

}

func (i *PanoramaCollector) Collect(ch chan<- prometheus.Metric) {
	iContext, iCancel := context.WithCancel(i.ctx)
	defer iCancel()
	i.metrics = map[string]PanoramaMetric{}

	DeviceGroups, err := i.panosClient.GetDeviceGroupNames(i.ctx)
	if err != nil {
		log.Errorf("Error getting rule usage for devicegroup %s", err)
		return
	}

	for _, deviceGroup := range DeviceGroups {
		// TODO: allow to configure which rulebase to retrieve
		for _, rulebaseName := range []string{"security", "nat"} {
			i.collectRuleUsage(ch, iContext, deviceGroup, rulebaseName)
		}
	}

	i.collectorScrapeStatus.WithLabelValues("RuleUsage").Set(float64(1))
}

func (i *PanoramaCollector) collectRuleUsage(ch chan<- prometheus.Metric, iContext context.Context, deviceGroup string, rulebaseName string) {

	RuleHitCountResponse, err := i.panosClient.GetRuleUsage(iContext, deviceGroup, rulebaseName)
	if err != nil {
		log.Errorf("Error getting rule usage for devicegroup %s", err)
		return
	}

	rulesUsage := RuleHitCountResponse.Rules.Rules
	labelNames := []string{"domain", "category", "deviceGroup", "rulebaseName", "ruleName"}

	for _, ruleUsage := range rulesUsage {
		ruleUsageMetric := PanoramaMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, ReportSubsystem, rulebaseName+"RuleUsage"),
				rulebaseName+" rules usage",
				labelNames,
				nil,
			),
		}
		i.metrics["ruleUsage"+rulebaseName] = ruleUsageMetric
		labelValues := []string{"panorama", "rules", deviceGroup, rulebaseName, ruleUsage.Name}

		ruleIsUsed := 0
		if ruleUsage.State == "Used" {
			ruleIsUsed = 1
		} else {
			ruleIsUsed = 0
		}
		ch <- prometheus.MustNewConstMetric(ruleUsageMetric.desc, prometheus.GaugeValue, float64(ruleIsUsed), labelValues...)
	}
}
