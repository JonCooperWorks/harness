# Makefile for Harness cross-compilation build system

# Build configuration
BIN_DIR := bin
CMD_DIR := cmd

# All command binaries to build
CMDS := encrypt genkeys harness listkeys sign store verify

# Target platforms
PLATFORMS := linux/amd64 linux/arm64 darwin/arm64 windows/amd64

# Default target: build for current platform (local dev)
.PHONY: build
build:
	@echo "Building binaries for current platform..."
	@mkdir -p $(BIN_DIR)
	@for cmd in $(CMDS); do \
		go build -o $(BIN_DIR)/$$cmd ./$(CMD_DIR)/$$cmd; \
	done
	@echo "Build complete. Binaries in $(BIN_DIR)/"

# Build release binaries for all target platforms
.PHONY: build-release
build-release: clean
	@echo "Building release binaries for all platforms..."
	@mkdir -p $(BIN_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} $(MAKE) build-platform PLATFORM=$$platform; \
	done
	@echo "Release build complete. Binaries in $(BIN_DIR)/"

# Build for a specific platform
.PHONY: build-platform
build-platform:
	@if [ -z "$(PLATFORM)" ]; then \
		echo "Error: PLATFORM not set"; \
		exit 1; \
	fi
	@PLATFORM_OS=$${PLATFORM%/*}; \
	PLATFORM_ARCH=$${PLATFORM#*/}; \
	SUFFIX=""; \
	if [ "$$PLATFORM_OS" = "windows" ]; then \
		SUFFIX=".exe"; \
	fi; \
	echo "Building for $$PLATFORM_OS/$$PLATFORM_ARCH..."; \
	for cmd in $(CMDS); do \
		BINARY_NAME=$$cmd-$$PLATFORM_OS-$$PLATFORM_ARCH$$SUFFIX; \
		GOOS=$$PLATFORM_OS GOARCH=$$PLATFORM_ARCH go build -o $(BIN_DIR)/$$BINARY_NAME ./$(CMD_DIR)/$$cmd; \
	done

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@echo "Clean complete."

# Help target
.PHONY: help
help:
	@echo "Harness Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build         - Build all binaries for current platform (local dev)"
	@echo "  build-release - Build all binaries for all target platforms"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Target platforms:"
	@echo "  - linux/amd64"
	@echo "  - linux/arm64"
	@echo "  - darwin/arm64"
	@echo "  - windows/amd64"
	@echo ""
	@echo "Example:"
	@echo "  make build-release"

