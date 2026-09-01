BINARY_NAME=tuxdnshole
BUILD_DIR=bin
CONFIG_DIR=/etc/tuxdnshole
INSTALL_PATH=/usr/local/bin/$(BINARY_NAME)
SERVICE_PATH=/etc/systemd/system/tuxdnshole.service

.PHONY: all build test clean run install service uninstall harden setup-resolv

all: build

build:
	@echo "==> Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tuxdnshole

test:
	@echo "==> Running tests..."
	go test -v -race ./...

harden:
	@echo "==> Installing network security sysctl settings..."
	install -m 644 configs/99-tuxdns-security.conf /etc/sysctl.d/99-tuxdns-security.conf
	sysctl --system

setup-resolv:
	@echo "==> Configuring and locking /etc/resolv.conf..."
	./scripts/setup-resolvconf.sh

run: build
	@echo "==> Running $(BINARY_NAME) in local debug mode..."
	./$(BUILD_DIR)/$(BINARY_NAME) -config configs/config.example.yaml -debug

install: build
	@echo "==> Installing binary to $(INSTALL_PATH)..."
	install -d /usr/local/bin
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PATH)
	@echo "==> Installing systemd unit to $(SERVICE_PATH)..."
	install -d /etc/systemd/system
	install -m 644 systemd/tuxdnshole.service $(SERVICE_PATH)
	@echo "==> Installing sysctl security config..."
	install -m 644 configs/99-tuxdns-security.conf /etc/sysctl.d/99-tuxdns-security.conf 2>/dev/null || true
	@echo "==> Setting up config directory $(CONFIG_DIR)..."
	install -d $(CONFIG_DIR)
	install -d $(CONFIG_DIR)/blocklists
	@if [ -d blocklists ]; then \
		install -m 644 blocklists/* $(CONFIG_DIR)/blocklists/; \
	fi
	@if [ ! -f $(CONFIG_DIR)/config.yaml ]; then \
		echo "Installing default configuration to $(CONFIG_DIR)/config.yaml..."; \
		install -m 644 configs/config.example.yaml $(CONFIG_DIR)/config.yaml; \
	fi
	systemctl daemon-reload

service: install
	@echo "==> Installing systemd service..."
	install -m 644 systemd/tuxdnshole.service $(SERVICE_PATH)
	systemctl daemon-reload
	systemctl enable --now tuxdnshole
	@echo "==> TuxDNS-Hole service started! Check status with: systemctl status tuxdnshole"

uninstall:
	@echo "==> Stopping and disabling service..."
	-systemctl stop tuxdnshole
	-systemctl disable tuxdnshole
	rm -f $(SERVICE_PATH)
	rm -f /etc/sysctl.d/99-tuxdns-security.conf
	systemctl daemon-reload
	@echo "==> Removing binary..."
	rm -f $(INSTALL_PATH)
	@echo "==> Binary removed. (Config in $(CONFIG_DIR) preserved)"

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

