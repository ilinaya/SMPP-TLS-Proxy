# SMPP TLS Proxy

A high-performance SMPP TLS proxy that securely forwards SMPP traffic to upstream SMPP servers. Built with Rust for maximum performance and reliability.

## Features

- TLS termination for SMPP traffic
- Transparent forwarding to upstream SMPP servers
- High performance and low latency
- Prometheus metrics for monitoring
- Configurable via environment variables
- Docker and Kubernetes ready
- Handles high load and many simultaneous connections

## Configuration

The proxy is configured using environment variables:

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `TLS_CERT` | TLS certificate in PEM format (base64 encoded) | Required |
| `TLS_KEY` | TLS private key in PEM format (base64 encoded) | Required |
| `LISTEN_PORT` | SMPP TLS listen port | 3550 |
| `METRICS_PORT` | Prometheus metrics listen port | 9090 |
| `UPSTREAM_HOSTS` | Comma-separated list of upstream SMPP hosts in format `host:port` | Required |
| `RUST_LOG` | Log level (error, warn, info, debug, trace) | info |

### Encoding Certificate and Key Files to Base64

To properly encode your certificate and key files for use with the SMPP TLS Proxy, use the following commands:

#### Linux/macOS

```bash
# Encode certificate (removes newlines)
cat path/to/certificate.pem | base64 -w 0

# Encode private key (removes newlines)
cat path/to/private_key.pem | base64 -w 0
```

#### Windows (PowerShell)

```powershell
# Encode certificate
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("path\to\certificate.pem")) -replace "`r`n", ""

# Encode private key
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("path\to\private_key.pem")) -replace "`r`n", ""
```

The `-w 0` option (Linux/macOS) and the `-replace` command (Windows) ensure that the base64 output doesn't contain newlines, which is required for proper environment variable handling.

## Building and Running Locally

### Prerequisites

- Rust 1.70 or later
- OpenSSL development libraries

### Build

```bash
cargo build --release
```

### Run

```bash
export TLS_CERT=$(cat cert.pem | base64 -w 0)
export TLS_KEY=$(cat key.pem | base64 -w 0)
export UPSTREAM_HOSTS="10.0.0.1:2775,10.0.0.2:2775"
export RUST_LOG=info

./target/release/smpp-tls-proxy
```

## Docker

### Build Docker Image

```bash
docker build -t smpp-tls-proxy:latest .
```

### Run Docker Container

```bash
docker run -d \
  --name smpp-tls-proxy \
  -p 3550:3550 \
  -p 9090:9090 \
  -e TLS_CERT=$(cat cert.pem | base64 -w 0) \
  -e TLS_KEY=$(cat key.pem | base64 -w 0) \
  -e UPSTREAM_HOSTS="10.0.0.1:2775,10.0.0.2:2775" \
  -e RUST_LOG=info \
  smpp-tls-proxy:latest
```

## Kubernetes Deployment

Create a Kubernetes deployment using the following example:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: smpp-tls-proxy-certs
type: Opaque
data:
  tls.crt: <base64-encoded-cert>
  tls.key: <base64-encoded-key>
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: smpp-tls-proxy
  labels:
    app: smpp-tls-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: smpp-tls-proxy
  template:
    metadata:
      labels:
        app: smpp-tls-proxy
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: smpp-tls-proxy
        image: smpp-tls-proxy:latest
        ports:
        - containerPort: 3550
          name: smpp
        - containerPort: 9090
          name: metrics
        env:
        - name: TLS_CERT
          valueFrom:
            secretKeyRef:
              name: smpp-tls-proxy-certs
              key: tls.crt
        - name: TLS_KEY
          valueFrom:
            secretKeyRef:
              name: smpp-tls-proxy-certs
              key: tls.key
        - name: UPSTREAM_HOSTS
          value: "10.0.0.1:2775,10.0.0.2:2775"
        - name: RUST_LOG
          value: "info"
        resources:
          requests:
            cpu: "100m"
            memory: "128Mi"
          limits:
            cpu: "1000m"
            memory: "512Mi"
        livenessProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: smpp-tls-proxy
spec:
  selector:
    app: smpp-tls-proxy
  ports:
  - port: 3550
    targetPort: 3550
    name: smpp
  - port: 9090
    targetPort: 9090
    name: metrics
  type: LoadBalancer
```

## Metrics

The proxy exposes Prometheus metrics on the configured metrics port (default: 9090). The following metrics are available:

- `smpp_proxy_active_connections`: Gauge of currently active connections
- `smpp_proxy_connections_total`: Counter of total connections by status (accepted, closed, tls_failed)
- `smpp_proxy_bytes_transferred`: Counter of bytes transferred by direction (to_client, to_upstream)
- `smpp_proxy_connection_duration_seconds`: Histogram of connection durations

Access metrics at: `http://<host>:<metrics_port>/metrics`

## Health Check

A health check endpoint is available at: `http://<host>:<metrics_port>/health`

## Performance Tuning

For high-load environments, consider:

1. Increasing system file descriptor limits
2. Tuning TCP parameters (keepalive, backlog, etc.)
3. Allocating sufficient CPU and memory resources
4. Using Kubernetes HPA (Horizontal Pod Autoscaler) based on CPU or custom metrics

## License

MIT
