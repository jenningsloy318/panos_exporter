package collector

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"time"
	//	"github.com/prometheus/common/log"
	"context"
	"github.com/jenningsloy318/panos_exporter/panos"
	//"net/url"
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
	ctx        context.Context
	panSession *panos.PaloAlto
	collectors map[string]prometheus.Collector
	panosUp    prometheus.Gauge
}

func NewPanosCollector(ctx context.Context, host string, username string, password string) *PanosCollector {
	panosCreds := &panos.AuthMethod{
		Credentials: []string{username, password},
	}

	panSession, err := panos.NewSession(host, panosCreds)
	if err != nil {
		fmt.Println(err)
	}
	return &PanosCollector{
		ctx:        ctx,
		panSession: panSession,
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
	retrivePanCounterData(p.panSession)
	scrapeTime := time.Now()

	if p.panSession != nil {
		defer p.ctx.Done()
		p.panosUp.Set(1)
	} else {
		p.panosUp.Set(0)
	}

	ch <- p.panosUp
	ch <- prometheus.MustNewConstMetric(totalScrapeDurationDesc, prometheus.GaugeValue, time.Since(scrapeTime).Seconds())
}

func retrivePanCounterData(panSession *panos.PaloAlto) {
	CounterData, err := panSession.GetCounterData()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(CounterData.Result.InterfaceCounter.HwCounterData.HwEntriesData[0])
}