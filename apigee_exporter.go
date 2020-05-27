// Copyright 2020 DHL, Digital Lab
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"encoding/json"
	// "sort"
	// "strconv"
	// "strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/version"
)

const (
	namespace = "apigee" // For Prometheus metrics.
	apigeeMonitoringApiURI = "https://apimonitoring.enterprise.apigee.com"
	listenAddress = ":9101"
	metricsPath = "/metrics"
)

type ApigeeTraffic struct {
	Results []struct {
		Series []struct {
			Name string `json:"name"`
			Tags struct {
				Env             string `json:"env"`
				IntervalSeconds string `json:"intervalSeconds"`
				Org             string `json:"org"`
				Proxy           string `json:"proxy"`
				Region          string `json:"region"`
			} `json:"tags"`
			Columns []string        `json:"columns"`
			Values  [][]interface{} `json:"values"`
		} `json:"series"`
	} `json:"results"`
}

var (
	trafficLabelNames   = []string{"org", "proxy","region"}
)

func newServerMetric(metricName string, docString string, constLabels prometheus.Labels) *prometheus.Desc {
	return prometheus.NewDesc(prometheus.BuildFQName(namespace, "traffic", metricName), docString, trafficLabelNames, constLabels)
}

type metrics map[string]*prometheus.Desc

var (
	trafficMetrics = metrics{
		"tps": newServerMetric("tps", "Transactions per second as experienced in last minute.", nil),
	}

	apigeeUp   = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "up"), "Was the last scrape of Apigee successful.", nil, nil)
)

// Exporter collects Apigee stats from the given URI and exports them using
// the prometheus metrics package.
type Exporter struct {
	URI       string
	fetchStat func() (io.ReadCloser, error)
	up                       prometheus.Gauge
	totalScrapes             prometheus.Counter
	trafficMetrics            map[string]*prometheus.Desc
	logger                   log.Logger
}

// NewExporter returns an initialized Exporter.
func NewExporter(uri string, sslVerify bool, serverMetrics map[string]*prometheus.Desc, timeout time.Duration, logger log.Logger) (*Exporter, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	var fetchStat func() (io.ReadCloser, error)

	switch u.Scheme {
	case "http", "https":
		fetchStat = fetchHTTP(uri, sslVerify, timeout, os.Getenv("ORG"), os.Getenv("ENV"), os.Getenv("PROXY"))
	default:
		return nil, fmt.Errorf("unsupported scheme: %q", u.Scheme)
	}

	return &Exporter{
		URI:       uri,
		fetchStat: fetchStat,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "up",
			Help:      "Was the last scrape of Apigee successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_total_scrapes",
			Help:      "Current total Apigee scrapes.",
		}),
		trafficMetrics: trafficMetrics,
		logger:        logger,
	}, nil
}

// Describe describes all the metrics ever exported by the Apigee exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.trafficMetrics {
		ch <- m
	}
	ch <- apigeeUp
	ch <- e.totalScrapes.Desc()
}

// Collect fetches the stats from configured Apigee location and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	up := e.scrape(ch)

	ch <- prometheus.MustNewConstMetric(apigeeUp, prometheus.GaugeValue, up)
	ch <- e.totalScrapes
}

func fetchHTTP(uri string, sslVerify bool, timeout time.Duration, org string, env string, proxy string) func() (io.ReadCloser, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !sslVerify},
		Proxy: http.ProxyFromEnvironment,
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}


	return func() (io.ReadCloser, error) {
		uri := fmt.Sprintf("%s/metrics/traffic?org=%s&env=%s&proxy=%s&from=-1h&to=now&select=tps&interval=1m", apigeeMonitoringApiURI, org, env, proxy)
		req, err := http.NewRequest("GET", uri, nil)
		req.Header.Add("accept", "application/json")
		req.Header.Add("Authorization", "Bearer " + os.Getenv("ACCESS_TOKEN"))
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {
	e.totalScrapes.Inc()

	body, err := e.fetchStat()
	if err != nil {
		level.Error(e.logger).Log("HTTP", "Can't scrape Apigee API", "err", err)
		return 0
	}
	defer body.Close()

	bodyBytes, err := ioutil.ReadAll(body)
	traffic := ApigeeTraffic{}
	jsonErr := json.Unmarshal(bodyBytes, &traffic)
	if jsonErr != nil {
		level.Error(e.logger).Log("HTTP", "Can't parse json response", "err", jsonErr)
	}
	e.parseTraffic(traffic, ch)
	return 1
}

func (e *Exporter) parseTraffic(data ApigeeTraffic, ch chan<- prometheus.Metric) {
	
	series := data.Results[0].Series

	for _, serie := range series {
		level.Info(e.logger).Log("RESP", "reg", serie.Values[0][1])
		col := 1
		metricId := serie.Columns[col]
		value := serie.Values[0][col].(float64)
		ch <- prometheus.MustNewConstMetric(e.trafficMetrics[metricId], prometheus.GaugeValue, value, serie.Tags.Org, serie.Tags.Proxy, serie.Tags.Region)
	}
}

type versionInfo struct {
	ReleaseDate string
	Version     string
}

func main() {


	promlogConfig := &promlog.Config{}
	logger := promlog.New(promlogConfig)

	

	level.Info(logger).Log("msg", "Starting apigee_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	accessToken := os.Getenv("ACCESS_TOKEN")
	if accessToken == "" {
		level.Error(logger).Log("msg", "Env var validation", "token not present in ACCESS_TOKEN env var")
		os.Exit(1)
	}

	if os.Getenv("ORG") == "" {
		level.Error(logger).Log("msg", "Env var validation", "Empty ORG")
		os.Exit(1)
	}

	if os.Getenv("ENV") == "" {
		level.Error(logger).Log("msg", "Env var validation", "Empty ENV")
		os.Exit(1)
	}

	if os.Getenv("PROXY") == "" {
		level.Error(logger).Log("msg", "Env var validation", "Empty PROXY")
		os.Exit(1)
	}

	req, err := http.NewRequest("GET", apigeeMonitoringApiURI, nil)
	prox, err := http.ProxyFromEnvironment(req)
	level.Info(logger).Log("msg", "Proxy servers", "HTTPS_PROXY", prox)

	timeout, err := time.ParseDuration("10s")
	if err != nil {
		level.Error(logger).Log("msg", "Error parsing timeout", "err", err)
		os.Exit(1)
	}

	exporter, err := NewExporter(apigeeMonitoringApiURI, true, trafficMetrics, timeout, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating an exporter", "err", err)
		os.Exit(1)
	}

	prometheus.MustRegister(exporter)
	prometheus.MustRegister(version.NewCollector("apigee_exporter"))

	level.Info(logger).Log("msg", "Listening on address", "address", listenAddress)
	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Apigee Exporter</title></head>
             <body>
             <h1>Apigee Exporter</h1>
             <p><a href='` + metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
