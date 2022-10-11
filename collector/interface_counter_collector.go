package collector

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	InterfaceCounterSubsystem  = "interface_counter"
	InterfaceCounterLabelNames = []string{"name", "domain", "category"}
)

type InterfaceCounterCollector struct {
	ctx                   context.Context
	panosClient           *panos.PaloAlto
	metrics               map[string]InterfaceCounterMetric
	collectorScrapeStatus *prometheus.GaugeVec
}

type InterfaceCounterMetric struct {
	desc *prometheus.Desc
}

func NewInterfaceCounterCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *InterfaceCounterCollector {

	return &InterfaceCounterCollector{
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

func (i *InterfaceCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range i.metrics {
		ch <- metric.desc
	}
	i.collectorScrapeStatus.Describe(ch)

}

func (i *InterfaceCounterCollector) Collect(ch chan<- prometheus.Metric) {
	iContext, iCancel := context.WithCancel(i.ctx)
	defer iCancel()
	i.metrics = map[string]InterfaceCounterMetric{}
	interfaceCounterData, err := i.panosClient.GetInterfaceCounterData(iContext)

	if err != nil {
		log.Errorf("Error getting Interface counter data, %s", err)
		return
	}

	// parse interface ifnet counters
	IfnetCounterDataEntries := interfaceCounterData.Result.IfnetCounter.IfnetCountersData

	for _, entry := range IfnetCounterDataEntries {
		labelValues := []string{entry.Name, "interface", "ifnet"}

		valueOfEntry := reflect.ValueOf(&entry).Elem()
		typeOfEntry := valueOfEntry.Type()

		for index := 0; index < valueOfEntry.NumField(); index++ {
			var floatType = reflect.TypeOf(float64(0))

			metricName := fmt.Sprintf("ifnet_%s", strings.ToLower(typeOfEntry.Field(index).Name))
			metricValue := valueOfEntry.Field(index)
			if !metricValue.Type().ConvertibleTo(floatType) {
				fmt.Errorf("cannot convert %v to float64", metricValue.Type())
				continue
			}
			metricDesc := fmt.Sprintf("Interface counter for interface ifnet  %s", metricName)
			newInterfaceCounterMetric := InterfaceCounterMetric{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(namespace, InterfaceCounterSubsystem, metricName),
					metricDesc,
					InterfaceCounterLabelNames,
					nil,
				),
			}
			i.metrics[metricName] = newInterfaceCounterMetric
			ch <- prometheus.MustNewConstMetric(newInterfaceCounterMetric.desc, prometheus.GaugeValue, metricValue.Convert(floatType).Float(), labelValues...)
		}
	}
	// parse interface hw counters
	HWCounterDataEntries := interfaceCounterData.Result.HwCounter.HwCountersData
	for _, entry := range HWCounterDataEntries {
		labelValues := []string{entry.Name, "interface_counter", "hw"}

		valueOfEntry := reflect.ValueOf(&entry).Elem()
		typeOfEntry := valueOfEntry.Type()

		for index := 0; index < valueOfEntry.NumField(); index++ {
			var floatType = reflect.TypeOf(float64(0))

			metricName := fmt.Sprintf("hw_%s", strings.ToLower(typeOfEntry.Field(index).Name))
			metricValue := valueOfEntry.Field(index)
			if !metricValue.Type().ConvertibleTo(floatType) {
				fmt.Errorf("cannot convert %v to float64", metricValue.Type())
				continue
			}
			metricDesc := fmt.Sprintf("Interface counter for interface hw  %s", metricName)
			newInterfaceCounterMetric := InterfaceCounterMetric{
				desc: prometheus.NewDesc(
					prometheus.BuildFQName(namespace, InterfaceCounterSubsystem, metricName),
					metricDesc,
					InterfaceCounterLabelNames,
					nil,
				),
			}
			i.metrics[metricName] = newInterfaceCounterMetric
			ch <- prometheus.MustNewConstMetric(newInterfaceCounterMetric.desc, prometheus.GaugeValue, metricValue.Convert(floatType).Float(), labelValues...)
		}
	}

	i.collectorScrapeStatus.WithLabelValues("interface_counter").Set(float64(1))

}
