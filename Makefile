# Xiaojin Pro Services - Docker Build & Deploy Makefile
# Usage: make docker-push SERVICE_NAME=your-service

SERVICE_NAME ?= $(shell basename $(CURDIR))
REGISTRY_PREFIX ?= ghcr.io/rickyjim626
SHORT_HASH = $(shell git rev-parse --short HEAD)
FULL_IMAGE = $(REGISTRY_PREFIX)/$(SERVICE_NAME):$(SHORT_HASH)
LATEST_IMAGE = $(REGISTRY_PREFIX)/$(SERVICE_NAME):latest

.PHONY: help docker-build docker-push docker-clean info

help: ## Show this help message
	@echo "Xiaojin Pro Docker Build & Deploy"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

info: ## Show build information
	@echo "🏷️  Service: $(SERVICE_NAME)"
	@echo "📦 Full image: $(FULL_IMAGE)"
	@echo "🔖 Latest: $(LATEST_IMAGE)"
	@echo "🏷️  Git hash: $(SHORT_HASH)"

docker-build: ## Build Docker image
	@echo "🔨 Building $(FULL_IMAGE)..."
	docker build -t $(FULL_IMAGE) .
	docker tag $(FULL_IMAGE) $(LATEST_IMAGE)
	@echo "✅ Build complete!"

docker-push: docker-build ## Build and push Docker image
	@echo "🚀 Pushing $(FULL_IMAGE)..."
	docker push $(FULL_IMAGE)
	docker push $(LATEST_IMAGE)
	@echo "✅ Successfully pushed:"
	@echo "  - $(FULL_IMAGE)"
	@echo "  - $(LATEST_IMAGE)"
	@echo ""
	@echo "💡 Update your docker-compose.yml with:"
	@echo "    image: $(FULL_IMAGE)"

docker-clean: ## Clean up local Docker images
	@echo "🧹 Cleaning up local images..."
	-docker rmi $(FULL_IMAGE)
	-docker rmi $(LATEST_IMAGE)

# Quick aliases
build: docker-build
push: docker-push
deploy: docker-push