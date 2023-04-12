package collector

import (
	"context"

	"github.com/jenningsloy318/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	NetworkSubsystem  = "network"
	NetworkLabelNames = []string{"domain", "category", "interface", "type", "group", "class"}
)

type NetworkCollector struct {
	ctx                   context.Context
	panosClient           *panos.PaloAlto
	metrics               map[string]NetworkMetric
	collectorScrapeStatus *prometheus.GaugeVec
}

type NetworkMetric struct {
	desc *prometheus.Desc
}

func NewNetworkCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *NetworkCollector {

	return &NetworkCollector{
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

func (i *NetworkCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range i.metrics {
		ch <- metric.desc
	}
	i.collectorScrapeStatus.Describe(ch)

}

func (i *NetworkCollector) Collect(ch chan<- prometheus.Metric) {
	iContext, iCancel := context.WithCancel(i.ctx)
	defer iCancel()
	i.metrics = map[string]NetworkMetric{}

	networkQosInterfaceList, err := i.panosClient.GetNetworkTunnelTrafic(iContext)
	if err != nil {
		log.Errorf("Error getting Network info, %s", err)
		return
	}

	for _, networkQosInterface := range networkQosInterfaceList {
		for _, class := range networkQosInterface.ClassList {

			labelValues := []string{"network", "statistics", networkQosInterface.InterfaceName, networkQosInterface.Type, networkQosInterface.Group, class.Name}

			activeNetworksMetric := NetworkMetric{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(namespace, NetworkSubsystem, "qos_statistics_kbps"),
					"Network info: number of active networks",
					NetworkLabelNames,
					nil,
				),
			}
			i.metrics["qos"] = activeNetworksMetric
			ch <- prometheus.MustNewConstMetric(activeNetworksMetric.desc, prometheus.GaugeValue, float64(class.Value), labelValues...)

			i.collectorScrapeStatus.WithLabelValues("Network").Set(float64(1))
		}
	}

}
