# Corrode Makefile
# Simple commands for building and installing

.PHONY: help build release install uninstall clean test

help:
	@echo "🦀 Corrode - Available Commands"
	@echo ""
	@echo "  make build      - Build debug binary"
	@echo "  make release    - Build optimized release binary"
	@echo "  make install    - Install corrode to /usr/local/bin"
	@echo "  make uninstall  - Remove corrode from /usr/local/bin"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make test       - Run tests"
	@echo ""

build:
	@echo "🔨 Building debug binary..."
	cargo build

release:
	@echo "🚀 Building release binary..."
	cargo build --release
	@echo "✓ Binary at: ./target/release/corrode"

install: release
	@echo "📦 Installing corrode..."
	@if [ ! -w /usr/local/bin ]; then \
		echo "🔐 Requesting sudo for installation..."; \
		sudo cp target/release/corrode /usr/local/bin/corrode; \
		sudo chmod +x /usr/local/bin/corrode; \
	else \
		cp target/release/corrode /usr/local/bin/corrode; \
		chmod +x /usr/local/bin/corrode; \
	fi
	@echo "✓ Corrode installed to /usr/local/bin/corrode"
	@echo "✓ You can now run: corrode"

uninstall:
	@echo "🗑️  Uninstalling corrode..."
	@if [ -f /usr/local/bin/corrode ]; then \
		if [ ! -w /usr/local/bin ]; then \
			sudo rm /usr/local/bin/corrode; \
		else \
			rm /usr/local/bin/corrode; \
		fi; \
		echo "✓ Corrode uninstalled"; \
	else \
		echo "⚠️  Corrode not found in /usr/local/bin"; \
	fi

clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	@echo "✓ Clean complete"

test:
	@echo "🧪 Running tests..."
	cargo test
