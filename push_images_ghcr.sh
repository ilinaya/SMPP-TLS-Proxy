#!/bin/bash

docker buildx version
docker buildx create --use

docker buildx build . \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/ilinaya/smpp-tls-proxy:latest \
  -t ghcr.io/ilinaya/smpp-tls-proxy:v1.0.0 \
  --push