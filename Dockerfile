FROM rustlang/rust:nightly-slim AS builder

WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files first to leverage Docker caching
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main.rs to build dependencies
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy the actual source code
COPY src ./src

# Build the application
RUN cargo build --release

# Create a minimal runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Install necessary runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/Ilinaya-SMPP-TLS-Proxy /app/Ilinaya-SMPP-TLS-Proxy

# Expose the SMPP TLS port and metrics port
EXPOSE 3550 9090

# Set the entrypoint
ENTRYPOINT ["/app/Ilinaya-SMPP-TLS-Proxy"]