use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use dotenv::dotenv;
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use prometheus::{register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Gauge, HistogramVec};
use rustls::{ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::{
    io::{self},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, lookup_host},
    task,
};
use tokio_rustls::TlsAcceptor;
use warp::Filter;

// Prometheus metrics
static METRICS: Lazy<Metrics> = Lazy::new(|| {
    let active_connections = register_gauge!("smpp_proxy_active_connections", "Number of active connections").unwrap();

    let connection_counter = register_counter_vec!(
        "smpp_proxy_connections_total",
        "Total number of connections",
        &["status"]
    ).unwrap();

    let bytes_transferred = register_counter_vec!(
        "smpp_proxy_bytes_transferred",
        "Total bytes transferred",
        &["direction"]
    ).unwrap();

    let connection_duration = register_histogram_vec!(
        "smpp_proxy_connection_duration_seconds",
        "Connection duration in seconds",
        &["status"],
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0]
    ).unwrap();

    Metrics {
        active_connections,
        connection_counter,
        bytes_transferred,
        connection_duration,
    }
});

struct Metrics {
    active_connections: Gauge,
    connection_counter: CounterVec,
    bytes_transferred: CounterVec,
    connection_duration: HistogramVec,
}

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Config {
    /// TLS certificate in PEM format (base64 encoded)
    #[clap(env = "TLS_CERT", long)]
    tls_cert: String,

    /// TLS private key in PEM format (base64 encoded)
    #[clap(env = "TLS_KEY", long)]
    tls_key: String,

    /// SMPP TLS listen port
    #[clap(env = "LISTEN_PORT", long, default_value = "3550")]
    listen_port: u16,

    /// Metrics listen port
    #[clap(env = "METRICS_PORT", long, default_value = "9090")]
    metrics_port: u16,

    /// Upstream SMPP hosts in format host:port,host:port
    #[clap(env = "UPSTREAM_HOSTS", long)]
    upstream_hosts: String,
}

#[derive(Debug, Deserialize)]
struct UpstreamHost {
    host: String,
    port: u16,
}

impl Config {
    async fn get_upstream_hosts(&self) -> Vec<SocketAddr> {
        let mut result = Vec::new();

        for host_port in self.upstream_hosts.split(',') {
            let parts: Vec<&str> = host_port.trim().split(':').collect();
            if parts.len() == 2 {
                let host = parts[0];
                if let Ok(port) = parts[1].parse::<u16>() {
                    // Try to parse as an IP address first
                    if let Ok(ip) = host.parse::<IpAddr>() {
                        result.push(SocketAddr::new(ip, port));
                    } else {
                        // If not an IP, assume it's a hostname and resolve it
                        let socket_addr = format!("{}:{}", host, port);
                        match lookup_host(&socket_addr).await {
                            Ok(addrs) => {
                                // Get the first resolved address
                                let addr = addrs.into_iter().next();
                                if let Some(addr) = addr {
                                    info!("Resolved hostname {} to {:?}", host, addr);
                                    result.push(addr);
                                } else {
                                    warn!("Could not resolve hostname: {}", host);
                                }
                            }
                            Err(e) => {
                                warn!("Failed to resolve hostname {}: {}", host, e);
                            }
                        }
                    }
                } else {
                    warn!("Invalid port in host:port format: {}", host_port);
                }
            } else {
                warn!("Invalid host:port format: {}", host_port);
            }
        }

        result
    }
}

fn load_certs_from_base64(cert_base64: &str) -> Result<Vec<CertificateDer<'static>>> {
    let cert_data = BASE64.decode(cert_base64)
        .context("Failed to decode certificate from base64")?;

    let mut cursor = io::Cursor::new(cert_data);
    let certs = match rustls_pemfile::certs(&mut cursor).collect::<Result<Vec<_>, _>>() {
        Ok(certs) => certs,
        Err(e) => {
            // Provide more detailed error information
            return Err(anyhow::anyhow!("Failed to parse certificates: {}. This may be due to invalid characters or malformed certificate data. Please check your certificate format.", e));
        }
    };

    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in the provided data. Please check your certificate format."));
    }

    Ok(certs.into_iter().map(|cert| cert.to_owned()).collect())
}

fn load_key_from_base64(key_base64: &str) -> Result<PrivateKeyDer<'static>> {
    let key_data = BASE64.decode(key_base64)
        .context("Failed to decode key from base64")?;

    let mut cursor = io::Cursor::new(key_data.clone());
    let keys = match rustls_pemfile::pkcs8_private_keys(&mut cursor).collect::<Result<Vec<_>, _>>() {
        Ok(keys) => keys,
        Err(e) => {
            // Provide more detailed error information
            return Err(anyhow::anyhow!("Failed to parse PKCS8 private key: {}. This may be due to invalid characters or malformed key data. Please check your key format.", e));
        }
    };

    if keys.is_empty() {
        // Try RSA key format
        let mut cursor = io::Cursor::new(key_data);
        let rsa_keys = match rustls_pemfile::rsa_private_keys(&mut cursor).collect::<Result<Vec<_>, _>>() {
            Ok(keys) => keys,
            Err(e) => {
                // Provide more detailed error information
                return Err(anyhow::anyhow!("Failed to parse RSA private key: {}. This may be due to invalid characters or malformed key data. Please check your key format.", e));
            }
        };

        if rsa_keys.is_empty() {
            return Err(anyhow::anyhow!("No private keys found in the provided data. Please check your key format."));
        }

        // Convert to owned by copying the bytes
        let key_bytes = rsa_keys[0].secret_pkcs1_der().to_vec();
        Ok(PrivateKeyDer::Pkcs1(key_bytes.into()))
    } else {
        // Convert to owned by copying the bytes
        let key_bytes = keys[0].secret_pkcs8_der().to_vec();
        Ok(PrivateKeyDer::Pkcs8(key_bytes.into()))
    }
}

fn create_tls_config(config: &Config) -> Result<ServerConfig> {
    let certs = load_certs_from_base64(&config.tls_cert)?;
    let key = load_key_from_base64(&config.tls_key)?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create TLS config with certificate and key")?;

    Ok(server_config)
}

async fn handle_client(
    client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    upstream_hosts: Vec<SocketAddr>,
) -> Result<()> {
    let start_time = Instant::now();
    METRICS.active_connections.inc();
    METRICS.connection_counter.with_label_values(&["accepted"]).inc();

    let (mut client_reader, mut client_writer) = tokio::io::split(client_stream);

    // Connect to upstream (simple round-robin for now)
    // In a production environment, you might want to implement more sophisticated load balancing
    let upstream_addr = &upstream_hosts[0]; // For simplicity, just use the first one

    let upstream_stream = TcpStream::connect(upstream_addr)
        .await
        .context("Failed to connect to upstream SMPP server")?;

    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_stream);

    // Forward data in both directions
    let client_to_upstream = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0;

        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client closed connection");
                    break;
                }
                Ok(n) => {
                    if let Err(e) = upstream_writer.write_all(&buffer[..n]).await {
                        error!("Failed to write to upstream: {}", e);
                        break;
                    }
                    total_bytes += n;
                    METRICS.bytes_transferred.with_label_values(&["to_upstream"]).inc_by(n as f64);
                }
                Err(e) => {
                    error!("Failed to read from client: {}", e);
                    break;
                }
            }
        }

        debug!("Client to upstream forwarded {} bytes", total_bytes);
        upstream_writer.shutdown().await.ok();
        total_bytes
    };

    let upstream_to_client = async {
        let mut buffer = [0u8; 8192];
        let mut total_bytes = 0;

        loop {
            match upstream_reader.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Upstream closed connection");
                    break;
                }
                Ok(n) => {
                    if let Err(e) = client_writer.write_all(&buffer[..n]).await {
                        error!("Failed to write to client: {}", e);
                        break;
                    }
                    total_bytes += n;
                    METRICS.bytes_transferred.with_label_values(&["to_client"]).inc_by(n as f64);
                }
                Err(e) => {
                    error!("Failed to read from upstream: {}", e);
                    break;
                }
            }
        }

        debug!("Upstream to client forwarded {} bytes", total_bytes);
        client_writer.shutdown().await.ok();
        total_bytes
    };

    // Run both forwarding tasks concurrently
    let (client_bytes, upstream_bytes) = tokio::join!(client_to_upstream, upstream_to_client);

    let duration = start_time.elapsed().as_secs_f64();
    METRICS.active_connections.dec();
    METRICS.connection_counter.with_label_values(&["closed"]).inc();
    METRICS.connection_duration.with_label_values(&["completed"]).observe(duration);

    info!(
        "Connection closed. Duration: {:.2}s, Client→Upstream: {} bytes, Upstream→Client: {} bytes",
        duration, client_bytes, upstream_bytes
    );

    Ok(())
}

async fn run_metrics_server(port: u16) -> Result<()> {
    let metrics_route = warp::path("metrics").map(|| {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        prometheus::Encoder::encode(&encoder, &metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    });

    let health_route = warp::path("health").map(|| "OK");

    let routes = metrics_route.or(health_route);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting metrics server on {}", addr);

    warp::serve(routes).run(addr).await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if it exists
    dotenv().ok();

    // Initialize logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Parse configuration
    let config = Config::parse();
    info!("Starting SMPP TLS Proxy");

    // Get upstream hosts
    let upstream_hosts = config.get_upstream_hosts().await;
    if upstream_hosts.is_empty() {
        anyhow::bail!("No valid upstream hosts configured");
    }
    info!("Configured upstream hosts: {:?}", upstream_hosts);

    // Create TLS config
    let tls_config = match create_tls_config(&config) {
        Ok(config) => config,
        Err(e) => {
            // Log the error with detailed information
            error!("Failed to create TLS configuration: {}", e);

            // Check if it's a certificate or key parsing error
            if e.to_string().contains("Failed to parse certificates") || 
               e.to_string().contains("InvalidCharacter") {
                error!("Certificate parsing error detected. Please check your certificate format and ensure it's properly encoded.");
                error!("The application will now shut down gracefully.");
            } else if e.to_string().contains("Failed to parse PKCS8 private key") || 
                      e.to_string().contains("Failed to parse RSA private key") {
                error!("Private key parsing error detected. Please check your key format and ensure it's properly encoded.");
                error!("The application will now shut down gracefully.");
            } else {
                error!("TLS configuration error. The application will now shut down gracefully.");
            }

            // Return from main with the error
            return Err(e);
        }
    };
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Start metrics server in a separate task
    let metrics_port = config.metrics_port;
    task::spawn(async move {
        if let Err(e) = run_metrics_server(metrics_port).await {
            error!("Metrics server error: {}", e);
        }
    });

    // Start TLS server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.listen_port));
    let listener = TcpListener::bind(addr).await?;
    info!("Listening for SMPP TLS connections on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("Accepted connection from {}", addr);

                // Clone necessary data for the new task
                let tls_acceptor = tls_acceptor.clone();
                let upstream_hosts = upstream_hosts.clone();

                // Handle each client in a separate task
                task::spawn(async move {
                    match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = handle_client(tls_stream, upstream_hosts).await {
                                error!("Error handling client: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("TLS handshake failed: {}", e);
                            METRICS.connection_counter.with_label_values(&["tls_failed"]).inc();
                        }
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
