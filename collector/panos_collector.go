package collector

import (
	"context"
	"sync"
	"time"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

// Metric name parts.
const (
	// Exporter namespace.
	namespace = "panos"
	// Subsystem(s).
	exporter = "exporter"
	// Math constant for picoseconds to seconds.
	picoSeconds = 1e12
)

// Metric descriptors.
var (
	totalScrapeDurationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, exporter, "collector_duration_seconds"),
		"Collector time duration.",
		nil, nil,
	)
)

// Exporter collects panos metrics. It implements prometheus.Collector.
type PanosCollector struct {
	ctx         context.Context
	panosClient *panos.PaloAlto
	collectors  map[string]prometheus.Collector
	panosUp     prometheus.Gauge
}

func NewPanosCollector(ctx context.Context, host string, username string, password string) *PanosCollector {
	panosCreds := &panos.AuthMethod{
		Credentials: []string{username, password},
	}

	panosClient, err := panos.NewPanosClient(host, panosCreds)
	if err != nil {
		log.Error(err)
	}

	globalCounterCollector := NewGlobalCounterCollector(ctx, namespace, panosClient)
	sessionCollector := NewSessionCollector(ctx, namespace, panosClient)
	interfaceCollector := NewInterfaceCollector(ctx, namespace, panosClient)
	interfaceCounterCollector := NewInterfaceCounterCollector(ctx, namespace, panosClient)
	dataProcessorResourceUtilCollector := NewDataProcessorResourceUtilCollector(ctx, namespace, panosClient)
	//reportCollector := NewReportCollector(ctx, namespace, panosClient)
	panoramaCollector := NewPanoramaCollector(ctx, namespace, panosClient)
	systemResourceUtilCollector := NewSystemResourceUtilCollector(ctx, namespace, panosClient)

	return &PanosCollector{
		ctx:         ctx,
		panosClient: panosClient,
		collectors: map[string]prometheus.Collector{
			"GlobalCounter":                      globalCounterCollector,
			"SessionCollector":                   sessionCollector,
			"InterfaceCollector":                 interfaceCollector,
			"InterfaceCounterCollector":          interfaceCounterCollector,
			"DataProcessorResourceUtilCollector": dataProcessorResourceUtilCollector,
			//"ReportCollector":                    reportCollector,
			"PanoramaCollector":                  panoramaCollector,
			"systemResourceUtilCollector":        systemResourceUtilCollector,
		},
		panosUp: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: "",
				Name:      "up",
				Help:      "panos up",
			},
		),
	}
}

// Describe implements prometheus.Collector.
func (p *PanosCollector) Describe(ch chan<- *prometheus.Desc) {
	//for _, collector := range r.collectors {
	//	collector.Describe(ch)
	//}

}

// Collect implements prometheus.Collector.
func (p *PanosCollector) Collect(ch chan<- prometheus.Metric) {
	scrapeTime := time.Now()

	if p.panosClient != nil {
		defer p.ctx.Done()
		p.panosUp.Set(1)
		wg := &sync.WaitGroup{}
		wg.Add(len(p.collectors))

		defer wg.Wait()
		for _, collector := range p.collectors {
			go func(collector prometheus.Collector) {
				defer wg.Done()
				collector.Collect(ch)
			}(collector)
		}
	} else {
		p.panosUp.Set(0)
	}

	ch <- p.panosUp
	ch <- prometheus.MustNewConstMetric(totalScrapeDurationDesc, prometheus.GaugeValue, time.Since(scrapeTime).Seconds())
}
