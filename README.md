# Apigee Exporter for Prometheus

This is a simple server that uses Apigee Edge monitoring API and exports them via HTTP for
Prometheus consumption.

## Getting Started

### Usage

```bash
apigee-exporter
```

### Docker

To run the haproxy exporter as a Docker container, run:

```bash
docker run -p 9101:9101 prometheus/apigee-exporter:v0.1.0 -e ACCESS_TOKEN= -e "ORG= " -e "ENV=  " -e "PROXY= "
```

### Building

```bash
make build
```

## License

Apache License 2.0, see [LICENSE](https://github.com/slesinger/apigee-exporter/blob/master/LICENSE).

