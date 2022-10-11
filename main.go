package main

import (
	"net/http"

	"github.com/Alfredo-Moreira/panos_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	configFile = kingpin.Flag(
		"config.file",
		"Path to configuration file.",
	).String()
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address to listen on for web interface and telemetry.",
	).Default(":9654").String()
	sc = &SafeConfig{
		C: &Config{},
	}
	reloadCh chan chan error
)

// define new http handleer
func metricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()
		ctx := r.Context()
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "'target' parameter must be specified", 400)
			return
		}
		log.Infof("Scraping target %s", target)

		var deviceConfig *DeviceConfig
		var err error
		if deviceConfig, err = sc.DeviceConfigForTarget(target); err != nil {
			log.Errorf("Error getting credentialfor target %s, error: %s", target, err)
			return
		}

		collector := collector.NewPanosCollector(ctx, target, deviceConfig.Username, deviceConfig.Password)
		registry.MustRegister(collector)
		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)

	}
}

var Version string
var BuildRevision string
var BuildBranch string
var BuildTime string
var BuildHost string

func init() {
	log.Infof("panos_exporter version %s, build reversion %s, build branch %s, build at %s on host %s", Version, BuildRevision, BuildBranch, BuildTime, BuildHost)
}

func main() {
	log.AddFlags(kingpin.CommandLine)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	log.Infoln("Starting panos_exporter")

	if err := sc.ReloadConfig(*configFile); err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	http.Handle("/panos", metricsHandler())     // Regular metrics endpoint for  panos metrics.
	http.Handle("/metrics", promhttp.Handler()) // for metrics endpoint for itself metrics

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head>
            <title>Panos Exporter</title>
            </head>
						<body>
            <h1>Panos Exporter</h1>
            <form action="/panos">
            <label>Target:</label> <input type="text" name="target" placeholder="X.X.X.X" value="1.2.3.4"><br>
            <input type="submit" value="Submit">
						</form>
						<p><a href="/metrics">Local metrics</a></p>
            </body>
            </html>`))
	})

	log.Infof("Listening on %s", *listenAddress)
	err := http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}
