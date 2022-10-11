package collector

import (
	"context"

	"github.com/Alfredo-Moreira/panos_exporter/panos"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

var (
	SessionSubsystem  = "session"
	SessionLabelNames = []string{"domain", "category"}
)

type SessionCollector struct {
	ctx                   context.Context
	panosClient           *panos.PaloAlto
	metrics               map[string]SessionMetric
	collectorScrapeStatus *prometheus.GaugeVec
}

type SessionMetric struct {
	desc *prometheus.Desc
}

func NewSessionCollector(ctx context.Context, namespace string, panosClient *panos.PaloAlto) *SessionCollector {

	return &SessionCollector{
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

func (i *SessionCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, metric := range i.metrics {
		ch <- metric.desc
	}
	i.collectorScrapeStatus.Describe(ch)

}

func (i *SessionCollector) Collect(ch chan<- prometheus.Metric) {
	iContext, iCancel := context.WithCancel(i.ctx)
	defer iCancel()
	i.metrics = map[string]SessionMetric{}
	SessionResponse, err := i.panosClient.GetSessionInfo(iContext)

	if err != nil {
		log.Errorf("Error getting Session info, %s", err)
		return
	}

	sessionInfo := SessionResponse.SessionInfo
	labelValues := []string{"statistics", "session"}

	// Number of active sessions (xml: num-active)
	activeSessionsMetric := SessionMetric{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, SessionSubsystem, "session_num_active"),
			"Session info: number of active sessions",
			SessionLabelNames,
			nil,
		),
	}
	i.metrics["num_active"] = activeSessionsMetric
	ch <- prometheus.MustNewConstMetric(activeSessionsMetric.desc, prometheus.GaugeValue, float64(sessionInfo.NumActive), labelValues...)

	// Packets per second (xml: pps)
	ppsSessionsMetric := SessionMetric{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, SessionSubsystem, "session_pps"),
			"Session info: packets per second",
			SessionLabelNames,
			nil,
		),
	}
	i.metrics["pps"] = ppsSessionsMetric
	ch <- prometheus.MustNewConstMetric(ppsSessionsMetric.desc, prometheus.GaugeValue, float64(sessionInfo.Pps), labelValues...)

	// Kilobits per second (xml: kbps)
	kbpsSessionsMetric := SessionMetric{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, SessionSubsystem, "session_kbps"),
			"Session info: kilobits per second",
			SessionLabelNames,
			nil,
		),
	}
	i.metrics["pps"] = kbpsSessionsMetric
	ch <- prometheus.MustNewConstMetric(kbpsSessionsMetric.desc, prometheus.GaugeValue, float64(sessionInfo.Kbps), labelValues...)

	i.collectorScrapeStatus.WithLabelValues("Session").Set(float64(1))

}
