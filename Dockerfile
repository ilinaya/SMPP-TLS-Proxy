FROM rustlang/rust:nightly-slim AS builder

WORKDIR /app

# Copy the entire project first
COPY . .

# Build the application directly without the dummy file approach
RUN cargo build --release

# Create a minimal runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Install necessary runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/Ilinaya-SMPP-TLS-Proxy /app/Ilinaya-SMPP-TLS-Proxy

# Set proper permissions
RUN chmod +x /app/Ilinaya-SMPP-TLS-Proxy

# Expose the SMPP TLS port and metrics port
EXPOSE 3550 9090

# Set environment variables
ENV CONTAINER=true
ENV RUST_LOG=debug

# Ensure logs are not buffered
ENV RUST_LOG_STYLE=always

# Set the entrypoint
ENTRYPOINT ["/app/Ilinaya-SMPP-TLS-Proxy"]