# Use Ubuntu as base image
FROM ubuntu:24.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
	# Build essentials
	build-essential \
	curl \
	git \
	pkg-config \
	# Go dependencies
	ca-certificates \
	# Linux keystore support (libsecret for Linux keyring)
	libsecret-1-dev \
	libdbus-1-dev \
	# SSH client for git operations
	openssh-client \
	# Other useful tools
	sudo \
	wget \
	&& rm -rf /var/lib/apt/lists/*

# Install Go
# Try to get the version from go.mod, but fallback to latest if not available
ARG GO_VERSION=1.24.4
RUN set -eux; \
	GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"; \
	if curl -f -s -S -L "https://go.dev/dl/${GO_TARBALL}" -o "/tmp/${GO_TARBALL}" 2>/dev/null; then \
		tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"; \
		rm "/tmp/${GO_TARBALL}"; \
		echo "Installed Go ${GO_VERSION}"; \
	else \
		echo "Go ${GO_VERSION} not found, installing latest stable..."; \
		LATEST_GO=$(curl -s https://go.dev/VERSION?m=text); \
		echo "Installing ${LATEST_GO}"; \
		curl -f -s -S -L "https://go.dev/dl/${LATEST_GO}.linux-amd64.tar.gz" -o /tmp/go.tar.gz; \
		tar -C /usr/local -xzf /tmp/go.tar.gz; \
		rm /tmp/go.tar.gz; \
		echo "Installed ${LATEST_GO}"; \
	fi

# Create or modify vscode user (Ubuntu 24.04 has 'ubuntu' user at UID 1000)
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000
RUN if id -u ubuntu > /dev/null 2>&1; then \
		usermod -l ${USERNAME} -d /home/${USERNAME} -m ubuntu; \
	fi || \
	if ! id -u ${USERNAME} > /dev/null 2>&1; then \
		useradd --uid ${USER_UID} --gid ${USER_GID} --shell /bin/bash --create-home ${USERNAME}; \
	fi; \
	mkdir -p /home/${USERNAME} && \
	chown -R ${USER_UID}:${USER_GID} /home/${USERNAME}; \
	echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install Rust as vscode user (so permissions are correct)
USER ${USERNAME}
ENV RUSTUP_HOME=/home/vscode/.rustup \
	CARGO_HOME=/home/vscode/.cargo \
	PATH=/home/vscode/.cargo/bin:/usr/local/go/bin:${PATH} \
	HOME=/home/vscode

# Install rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile default

# Install wasm32-wasip1 target for WASM plugin compilation
RUN /home/vscode/.cargo/bin/rustup target add wasm32-wasip1

# Set up Go workspace and ensure workspace directory exists with correct permissions
RUN mkdir -p /home/vscode/go && \
	sudo mkdir -p /workspace && \
	sudo chown -R ${USER_UID}:${USER_GID} /workspace

# Verify installations
RUN /usr/local/go/bin/go version && \
	/home/vscode/.cargo/bin/rustc --version && \
	/home/vscode/.cargo/bin/cargo --version

# Set working directory
WORKDIR /workspace
