#!/bin/bash
# Docker Build & Push Script for Xiaojin Pro services
# Usage: ./scripts/docker-build-push.sh [service-name] [registry-prefix]

set -e

SERVICE_NAME=${1:-$(basename $(pwd))}
REGISTRY_PREFIX=${2:-"ghcr.io/rickyjim626"}
SHORT_HASH=$(git rev-parse --short HEAD)
FULL_IMAGE="${REGISTRY_PREFIX}/${SERVICE_NAME}:${SHORT_HASH}"
LATEST_IMAGE="${REGISTRY_PREFIX}/${SERVICE_NAME}:latest"

echo "🔨 Building Docker image for service: ${SERVICE_NAME}"
echo "📦 Image: ${FULL_IMAGE}"
echo "🏷️  Hash: ${SHORT_HASH}"

# Build image with short hash
docker build -t "${FULL_IMAGE}" .

# Tag as latest
docker tag "${FULL_IMAGE}" "${LATEST_IMAGE}"

echo "🚀 Pushing to registry..."

# Push both tags
docker push "${FULL_IMAGE}"
docker push "${LATEST_IMAGE}"

echo "✅ Successfully pushed:"
echo "  - ${FULL_IMAGE}"
echo "  - ${LATEST_IMAGE}"
echo ""
echo "💡 Update your docker-compose.yml with:"
echo "    image: ${FULL_IMAGE}"