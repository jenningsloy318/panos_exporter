package collector

import (
	"context"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	InterfaceSubsystem  = "interface"
	InterfaceLabelNames = []string{"name", "domain", "category"}
)

type InterfaceCollector struct {
	ctx                   context.Context
	panosClient           *panos.PaloAlto
	metrics               map[string]InterfaceMetric
	collectorScrapeStatus *prometheus.GaugeVec
}

type InterfaceMetric struct {
	desc *prometheus.Desc
}

func NewInterfaceCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *InterfaceCollector {

	return &InterfaceCollector{
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

func (i *InterfaceCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range i.metrics {
		ch <- metric.desc
	}
	i.collectorScrapeStatus.Describe(ch)

}

func (i *InterfaceCollector) Collect(ch chan<- prometheus.Metric) {
	iContext, iCancel := context.WithCancel(i.ctx)
	defer iCancel()
	i.metrics = map[string]InterfaceMetric{}

	InterfaceResponse, err := i.panosClient.GetInterfaceData(iContext)
	if err != nil {
		log.Errorf("Error getting standard interfaces data, %s", err)
	} else {
		// Add status for standard (non-management) hardware interfaces
		HWEntries := InterfaceResponse.Result.Hw.HwEntries
		for _, entry := range HWEntries {
			labelValues := []string{entry.Name, "interface", "hw"}

			// HW interface state
			stateInterfaceMetric := InterfaceMetric{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(namespace, InterfaceSubsystem, "state"),
					"Status of hw interface",
					InterfaceLabelNames,
					nil,
				),
			}
			i.metrics["state"] = stateInterfaceMetric

			stateValue := 0
			if entry.State == "up" {
				stateValue = 1
			}
			ch <- prometheus.MustNewConstMetric(stateInterfaceMetric.desc, prometheus.GaugeValue, float64(stateValue), labelValues...)
		}
	}

	ManagementInterfaceResponse, err := i.panosClient.GetManagementInterfaceInfo(iContext)
	if err != nil {
		log.Errorf("Error getting management interfaces data, %s", err)
	} else {
		// Add status for management interface
		managementLabelValues := []string{"management", "interface", "hw"}
		stateManagementInterfaceMetric := InterfaceMetric{
			desc: prometheus.NewDesc(
				prometheus.BuildFQName(namespace, InterfaceSubsystem, "state"),
				"Status of hw interface",
				InterfaceLabelNames,
				nil,
			),
		}

		managementStateValue := 0
		if ManagementInterfaceResponse.Result.Info.State == "up" {
			managementStateValue = 1
		}
		ch <- prometheus.MustNewConstMetric(stateManagementInterfaceMetric.desc, prometheus.GaugeValue, float64(managementStateValue), managementLabelValues...)
	}

	i.collectorScrapeStatus.WithLabelValues("interface").Set(float64(1))
}
