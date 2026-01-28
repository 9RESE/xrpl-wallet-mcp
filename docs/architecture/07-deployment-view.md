# 07 - Deployment View

**Arc42 Section**: Deployment View
**Version**: 1.0.0
**Date**: 2026-01-28
**Status**: Complete

---

## Table of Contents

1. [Overview](#1-overview)
2. [Infrastructure Requirements](#2-infrastructure-requirements)
3. [Local Development Environment](#3-local-development-environment)
4. [Production Environment (Single Server)](#4-production-environment-single-server)
5. [Docker Deployment](#5-docker-deployment)
6. [Kubernetes Deployment](#6-kubernetes-deployment)
7. [Future: Cloud KMS Integration (Phase 2)](#7-future-cloud-kms-integration-phase-2)
8. [Future: TEE Deployment (Phase 3)](#8-future-tee-deployment-phase-3)
9. [Network Architecture](#9-network-architecture)
10. [Operational Considerations](#10-operational-considerations)
11. [Environment Configuration Reference](#11-environment-configuration-reference)
12. [Deployment Checklist](#12-deployment-checklist)

---

## 1. Overview

This document describes the deployment architecture for the XRPL Agent Wallet MCP server across different environments. The deployment model follows these principles:

**Deployment Principles:**
- **Security-first**: Encryption at rest, minimal attack surface, principle of least privilege
- **Environment isolation**: Strict separation between testnet/devnet and mainnet
- **Operational simplicity**: MCP servers are stdio-based, requiring no inbound ports
- **Progressive complexity**: Start simple (local), scale to cloud-native as needed

### 1.1 Deployment Topology Overview

```
+------------------------------------------------------------------+
|                    Deployment Environments                        |
+------------------------------------------------------------------+
|                                                                   |
|  +----------------+    +----------------+    +------------------+ |
|  |    Local       |    |   Production   |    |    Cloud-Native  | |
|  |  Development   |    | (Single Server)|    |   (Future)       | |
|  +----------------+    +----------------+    +------------------+ |
|  | - Developer    |    | - Systemd      |    | - Kubernetes     | |
|  |   machine      |    |   service      |    | - Cloud KMS      | |
|  | - Testnet      |    | - TLS nginx    |    | - TEE (Nitro)    | |
|  | - Debug mode   |    | - Mainnet      |    | - Auto-scaling   | |
|  +----------------+    +----------------+    +------------------+ |
|         |                      |                      |           |
|         v                      v                      v           |
|  +------------------------------------------------------------------+
|  |                   XRPL Networks                                  |
|  |  +----------+  +----------+  +----------+                        |
|  |  | Testnet  |  | Devnet   |  | Mainnet  |                        |
|  |  +----------+  +----------+  +----------+                        |
|  +------------------------------------------------------------------+
+------------------------------------------------------------------+
```

### 1.2 MCP Transport Model

The MCP server uses **stdio-based communication**, which simplifies deployment:

```
+-------------------+          +------------------------+
|                   |  stdin   |                        |
|   MCP Client      |--------->|   XRPL Agent Wallet    |
|   (Claude Desktop |  stdout  |   MCP Server           |
|    or IDE)        |<---------|                        |
|                   |          |                        |
+-------------------+          +------------------------+
                                         |
                                         | WebSocket (outbound only)
                                         v
                               +------------------------+
                               |   XRPL Network         |
                               |   (rippled nodes)      |
                               +------------------------+
```

**Key Points:**
- No inbound network ports required
- Communication via process stdin/stdout
- Outbound WebSocket to XRPL nodes only
- Firewall-friendly deployment model

---

## 2. Infrastructure Requirements

### 2.1 Minimum Hardware Requirements

| Environment | CPU | Memory | Storage | Network |
|-------------|-----|--------|---------|---------|
| Development | 2 cores | 4 GB | 1 GB | 10 Mbps |
| Production | 4 cores | 8 GB | 10 GB SSD | 100 Mbps |
| High-Availability | 8 cores | 16 GB | 50 GB SSD | 1 Gbps |

**Memory Note (SC-01)**: Argon2id key derivation requires minimum 64 MB per concurrent authentication. Plan memory accordingly for concurrent wallet unlock operations.

### 2.2 Software Requirements

| Component | Version | Purpose |
|-----------|---------|---------|
| Node.js | 20.x LTS | Runtime (TC-01) |
| npm/pnpm | Latest | Package management |
| OpenSSL | 3.0+ | TLS and cryptography |
| systemd | 245+ | Service management (Linux) |
| Docker | 24.0+ | Container deployment |
| nginx | 1.24+ | TLS termination (optional) |

### 2.3 Operating System Support

| OS | Version | Support Level |
|----|---------|---------------|
| Ubuntu | 22.04 LTS, 24.04 LTS | Primary |
| Debian | 12 (Bookworm) | Primary |
| RHEL/Rocky | 9.x | Secondary |
| macOS | 14+ (Sonoma) | Development |
| Windows | Server 2022, WSL2 | Development |
| Alpine Linux | 3.19+ | Container only |

---

## 3. Local Development Environment

### 3.1 Architecture Diagram

```
+------------------------------------------------------------------+
|                    Developer Machine                              |
|                                                                   |
|  +----------------------------+   +----------------------------+  |
|  |  Claude Desktop / IDE      |   |   Development Tools        |  |
|  |  +----------------------+  |   |  +----------------------+  |  |
|  |  | MCP Client           |  |   |  | Code Editor          |  |  |
|  |  | (stdio transport)    |  |   |  | Terminal             |  |  |
|  |  +----------------------+  |   |  | Git                  |  |  |
|  +-------------|-------------+   |  +----------------------+  |  |
|                |                  +----------------------------+  |
|                | stdin/stdout                                     |
|                v                                                  |
|  +-----------------------------------------------------------+   |
|  |              XRPL Agent Wallet MCP Server                  |   |
|  |  +------------------+  +------------------+                |   |
|  |  | Node.js 20+      |  | TypeScript       |                |   |
|  |  | Runtime          |  | Source           |                |   |
|  |  +------------------+  +------------------+                |   |
|  +-----------------------------------------------------------+   |
|                |                                                  |
|  +-------------|----------------------------------------------+  |
|  |   Local File System                                        |  |
|  |  +------------------+  +------------------+  +------------+ |  |
|  |  | ./keystore/      |  | ./policies/      |  | ./logs/    | |  |
|  |  |   testnet/       |  |   testnet-       |  |  audit-    | |  |
|  |  |     *.enc        |  |   permissive.json|  |  *.jsonl   | |  |
|  |  +------------------+  +------------------+  +------------+ |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                |
                | WebSocket (wss://)
                v
+------------------------------------------------------------------+
|                    XRPL Testnet                                   |
|              wss://s.altnet.rippletest.net:51233                  |
+------------------------------------------------------------------+
```

### 3.2 Directory Structure

```
xrpl-wallet-mcp/
|-- .env.development            # Environment variables (gitignored)
|-- keystore/
|   |-- testnet/
|   |   |-- agent-wallet-001.enc
|   |   `-- agent-wallet-002.enc
|   `-- devnet/
|       `-- test-wallet.enc
|-- policies/
|   |-- testnet-permissive.json  # Relaxed limits for testing
|   |-- testnet-standard.json    # Standard tiered approval
|   `-- devnet-testing.json      # Very permissive for dev
|-- logs/
|   |-- audit-2026-01-28.jsonl
|   `-- audit-hmac.key           # HMAC key for log verification
|-- src/                         # Source code
|-- dist/                        # Compiled output
`-- package.json
```

### 3.3 Configuration

**Environment Variables (.env.development):**
```bash
# Network Configuration
XRPL_NETWORK=testnet
XRPL_WEBSOCKET_URL=wss://s.altnet.rippletest.net:51233

# Storage Paths
XRPL_WALLET_KEYSTORE_PATH=./keystore/testnet
XRPL_WALLET_POLICY_PATH=./policies/testnet-permissive.json
XRPL_WALLET_LOG_PATH=./logs

# Logging
LOG_LEVEL=debug
LOG_FORMAT=pretty

# Security (relaxed for development)
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MULTIPLIER=10        # 10x normal limits for testing

# Development flags
NODE_ENV=development
DEBUG=xrpl-wallet:*
```

**Claude Desktop Configuration (claude_desktop_config.json):**
```json
{
  "mcpServers": {
    "xrpl-wallet": {
      "command": "node",
      "args": ["/path/to/xrpl-wallet-mcp/dist/index.js"],
      "env": {
        "XRPL_NETWORK": "testnet",
        "XRPL_WALLET_KEYSTORE_PATH": "/path/to/xrpl-wallet-mcp/keystore/testnet",
        "XRPL_WALLET_POLICY_PATH": "/path/to/xrpl-wallet-mcp/policies/testnet-permissive.json",
        "LOG_LEVEL": "debug"
      }
    }
  }
}
```

### 3.4 Quick Start

```bash
# Clone and setup
git clone https://github.com/your-org/xrpl-wallet-mcp.git
cd xrpl-wallet-mcp
npm install

# Create directories
mkdir -p keystore/testnet policies logs

# Copy sample policy
cp policies/samples/testnet-permissive.json policies/

# Build
npm run build

# Run in development mode
npm run dev

# Or run directly with environment
XRPL_NETWORK=testnet \
XRPL_WALLET_KEYSTORE_PATH=./keystore/testnet \
LOG_LEVEL=debug \
node dist/index.js
```

### 3.5 Development Policy (testnet-permissive.json)

```json
{
  "version": "1.0",
  "name": "testnet-permissive",
  "description": "Permissive policy for testnet development",
  "network": "testnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 1000,
      "daily_limit_xrp": 10000,
      "hourly_transaction_limit": 100
    },
    "delayed": {
      "max_amount_xrp": 10000,
      "delay_seconds": 60
    },
    "cosign": {
      "min_amount_xrp": 10000,
      "signer_quorum": 2
    }
  },
  "allowlist": {
    "addresses": [],
    "trust_new_destinations": true
  },
  "blocklist": {
    "addresses": [],
    "memo_patterns": []
  },
  "rate_limits": {
    "sign_transaction": { "requests": 50, "window_seconds": 60 },
    "create_wallet": { "requests": 10, "window_seconds": 60 }
  }
}
```

---

## 4. Production Environment (Single Server)

### 4.1 Architecture Diagram

```
+------------------------------------------------------------------+
|                 Production Server (Ubuntu 22.04)                  |
|                                                                   |
|  +-----------------------------------------------------------+   |
|  |                    nginx (TLS Termination)                 |   |
|  |              (Optional - for SSE transport only)           |   |
|  +-----------------------------------------------------------+   |
|                             |                                     |
|  +-----------------------------------------------------------+   |
|  |              XRPL Agent Wallet MCP Server                  |   |
|  |                    (systemd service)                       |   |
|  |  +------------------+  +------------------+                |   |
|  |  | User: xrpl-wallet|  | WorkingDirectory:|                |   |
|  |  | (non-root)       |  | /opt/xrpl-wallet |                |   |
|  |  +------------------+  +------------------+                |   |
|  +-----------------------------------------------------------+   |
|                             |                                     |
|  +-----------------------------------------------------------+   |
|  |                   Secure File System                       |   |
|  |                                                            |   |
|  |  /var/lib/xrpl-wallet/        /etc/xrpl-wallet/           |   |
|  |  |-- keystore/                |-- policies/               |   |
|  |  |   `-- mainnet/             |   `-- production.json     |   |
|  |  |       `-- *.enc (0600)     `-- server.json             |   |
|  |  `-- limits/                                               |   |
|  |      `-- rate-state.json      /var/log/xrpl-wallet/       |   |
|  |                               |-- audit/                   |   |
|  |                               |   `-- audit-*.jsonl (0600)|   |
|  |                               `-- server.log              |   |
|  +-----------------------------------------------------------+   |
+------------------------------------------------------------------+
                             |
                             | WebSocket (wss://)
                             v
+------------------------------------------------------------------+
|                      XRPL Mainnet                                 |
|           wss://xrplcluster.com (primary)                         |
|           wss://s1.ripple.com (fallback)                          |
|           wss://s2.ripple.com (fallback)                          |
+------------------------------------------------------------------+
```

### 4.2 System User and Permissions

```bash
# Create dedicated system user (no login shell)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin xrpl-wallet

# Create directory structure
sudo mkdir -p /opt/xrpl-wallet
sudo mkdir -p /var/lib/xrpl-wallet/keystore/mainnet
sudo mkdir -p /var/lib/xrpl-wallet/limits
sudo mkdir -p /etc/xrpl-wallet/policies
sudo mkdir -p /var/log/xrpl-wallet/audit

# Set ownership
sudo chown -R xrpl-wallet:xrpl-wallet /opt/xrpl-wallet
sudo chown -R xrpl-wallet:xrpl-wallet /var/lib/xrpl-wallet
sudo chown -R xrpl-wallet:xrpl-wallet /var/log/xrpl-wallet

# Set secure permissions
# Keystore: owner read/write only
sudo chmod 700 /var/lib/xrpl-wallet/keystore
sudo chmod 700 /var/lib/xrpl-wallet/keystore/mainnet
# Files inside will be 0600

# Config: owner read only
sudo chmod 755 /etc/xrpl-wallet
sudo chmod 644 /etc/xrpl-wallet/policies/*.json

# Logs: owner read/write, group read (for log aggregation)
sudo chmod 750 /var/log/xrpl-wallet
sudo chmod 750 /var/log/xrpl-wallet/audit
```

### 4.3 Systemd Service Configuration

**/etc/systemd/system/xrpl-wallet-mcp.service:**
```ini
[Unit]
Description=XRPL Agent Wallet MCP Server
Documentation=https://github.com/your-org/xrpl-wallet-mcp
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=xrpl-wallet
Group=xrpl-wallet
WorkingDirectory=/opt/xrpl-wallet

# Environment
Environment=NODE_ENV=production
Environment=XRPL_NETWORK=mainnet
Environment=XRPL_WALLET_KEYSTORE_PATH=/var/lib/xrpl-wallet/keystore/mainnet
Environment=XRPL_WALLET_POLICY_PATH=/etc/xrpl-wallet/policies/production.json
Environment=XRPL_WALLET_LOG_PATH=/var/log/xrpl-wallet/audit
Environment=LOG_LEVEL=info
Environment=LOG_FORMAT=json

# Process execution
ExecStart=/usr/bin/node /opt/xrpl-wallet/dist/index.js
ExecReload=/bin/kill -HUP $MAINPID

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitIntervalSec=60
StartLimitBurst=3

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true

# Allow only necessary paths
ReadWritePaths=/var/lib/xrpl-wallet /var/log/xrpl-wallet
ReadOnlyPaths=/etc/xrpl-wallet /opt/xrpl-wallet

# Resource limits
MemoryMax=1G
CPUQuota=200%
TasksMax=50

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xrpl-wallet-mcp

[Install]
WantedBy=multi-user.target
```

### 4.4 Service Management

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable xrpl-wallet-mcp
sudo systemctl start xrpl-wallet-mcp

# Check status
sudo systemctl status xrpl-wallet-mcp

# View logs
sudo journalctl -u xrpl-wallet-mcp -f

# Reload configuration (HUP signal)
sudo systemctl reload xrpl-wallet-mcp

# Restart
sudo systemctl restart xrpl-wallet-mcp
```

### 4.5 Production Policy Configuration

**/etc/xrpl-wallet/policies/production.json:**
```json
{
  "version": "1.0",
  "name": "production-standard",
  "description": "Production policy with tiered approval",
  "network": "mainnet",
  "tiers": {
    "autonomous": {
      "max_amount_xrp": 100,
      "daily_limit_xrp": 1000,
      "hourly_transaction_limit": 20
    },
    "delayed": {
      "max_amount_xrp": 1000,
      "delay_seconds": 300,
      "notification_webhook": "https://alerts.example.com/xrpl-wallet"
    },
    "cosign": {
      "min_amount_xrp": 1000,
      "signer_quorum": 2,
      "required_signers": ["rSigner1...", "rSigner2..."]
    }
  },
  "allowlist": {
    "addresses": [],
    "trust_new_destinations": false
  },
  "blocklist": {
    "addresses": [],
    "memo_patterns": [
      "(?i)(urgent|emergency|immediate)",
      "(?i)(override|bypass|ignore.*policy)"
    ]
  },
  "rate_limits": {
    "sign_transaction": { "requests": 5, "window_seconds": 300 },
    "create_wallet": { "requests": 1, "window_seconds": 3600 },
    "import_wallet": { "requests": 1, "window_seconds": 3600 }
  }
}
```

### 4.6 TLS Configuration (nginx - Optional for SSE)

**/etc/nginx/sites-available/xrpl-wallet:**
```nginx
# Only needed if using SSE transport instead of stdio
upstream xrpl_wallet {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name wallet.example.com;

    # TLS Configuration
    ssl_certificate /etc/letsencrypt/live/wallet.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wallet.example.com/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern TLS only
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Security headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;

    # SSE endpoint
    location /sse {
        proxy_pass http://xrpl_wallet;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE specific
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        chunked_transfer_encoding off;
    }

    # Health check
    location /health {
        proxy_pass http://xrpl_wallet/health;
        proxy_http_version 1.1;
    }

    # Deny all other paths
    location / {
        return 404;
    }
}
```

---

## 5. Docker Deployment

### 5.1 Architecture Diagram

```
+------------------------------------------------------------------+
|                    Docker Host                                    |
|                                                                   |
|  +-----------------------------------------------------------+   |
|  |                 docker-compose stack                       |   |
|  |                                                            |   |
|  |  +----------------------------+                            |   |
|  |  |   xrpl-wallet container    |                            |   |
|  |  |   (node:20-alpine)         |                            |   |
|  |  |   User: wallet (1000)      |                            |   |
|  |  |   no-new-privileges        |                            |   |
|  |  +-------------|--------------+                            |   |
|  |                |                                           |   |
|  |  +-------------v--------------+                            |   |
|  |  |         Volumes            |                            |   |
|  |  | +--------+ +--------+ +--------+                        |   |
|  |  | |keystore| |policies| | logs   |                        |   |
|  |  | | (rw)   | | (ro)   | | (rw)   |                        |   |
|  |  | +--------+ +--------+ +--------+                        |   |
|  |  +----------------------------+                            |   |
|  +-----------------------------------------------------------+   |
|                                                                   |
|  Host volumes:                                                    |
|  ./data/keystore -> /data/keystore                               |
|  ./config/policies -> /data/policies                             |
|  ./logs -> /data/logs                                            |
+------------------------------------------------------------------+
```

### 5.2 Dockerfile

```dockerfile
# syntax=docker/dockerfile:1.7

# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci --ignore-scripts

# Copy source and build
COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# Production stage
FROM node:20-alpine AS production

# Security: Create non-root user
RUN addgroup -g 1000 wallet && \
    adduser -u 1000 -G wallet -s /bin/sh -D wallet

# Install production dependencies only
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev && \
    npm cache clean --force

# Copy built artifacts
COPY --from=builder /app/dist ./dist

# Create data directories
RUN mkdir -p /data/keystore /data/policies /data/logs && \
    chown -R wallet:wallet /data

# Security: Drop all capabilities
USER wallet

# Environment defaults
ENV NODE_ENV=production \
    XRPL_NETWORK=mainnet \
    XRPL_WALLET_KEYSTORE_PATH=/data/keystore \
    XRPL_WALLET_POLICY_PATH=/data/policies/policy.json \
    XRPL_WALLET_LOG_PATH=/data/logs \
    LOG_LEVEL=info \
    LOG_FORMAT=json

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Volumes for persistent data
VOLUME ["/data/keystore", "/data/policies", "/data/logs"]

# Entry point
ENTRYPOINT ["node", "dist/index.js"]
```

### 5.3 Docker Compose Configuration

**docker-compose.yml:**
```yaml
version: '3.9'

services:
  xrpl-wallet:
    build:
      context: .
      dockerfile: Dockerfile
      target: production
    image: xrpl-wallet-mcp:latest
    container_name: xrpl-wallet-mcp
    restart: unless-stopped

    # Security options
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M

    # Environment
    environment:
      - XRPL_NETWORK=${XRPL_NETWORK:-mainnet}
      - XRPL_WEBSOCKET_URL=${XRPL_WEBSOCKET_URL:-wss://xrplcluster.com}
      - LOG_LEVEL=${LOG_LEVEL:-info}
      - LOG_FORMAT=json

    # Volumes
    volumes:
      - ./data/keystore:/data/keystore:rw
      - ./config/policies:/data/policies:ro
      - ./logs:/data/logs:rw
      - /tmp  # Required for read_only with tmpfs

    # Tmpfs for temporary files
    tmpfs:
      - /tmp:noexec,nosuid,size=64m

    # Network
    networks:
      - xrpl-wallet-net

    # Logging
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

networks:
  xrpl-wallet-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### 5.4 Docker Compose for Development

**docker-compose.dev.yml:**
```yaml
version: '3.9'

services:
  xrpl-wallet-dev:
    build:
      context: .
      dockerfile: Dockerfile
      target: builder
    image: xrpl-wallet-mcp:dev
    container_name: xrpl-wallet-mcp-dev

    environment:
      - XRPL_NETWORK=testnet
      - XRPL_WEBSOCKET_URL=wss://s.altnet.rippletest.net:51233
      - LOG_LEVEL=debug
      - LOG_FORMAT=pretty
      - NODE_ENV=development

    volumes:
      - ./src:/app/src:ro
      - ./data/keystore/testnet:/data/keystore:rw
      - ./config/policies:/data/policies:ro
      - ./logs:/data/logs:rw

    command: npm run dev

    # Less restrictive for development
    security_opt:
      - no-new-privileges:true
```

### 5.5 Docker Commands

```bash
# Build image
docker compose build

# Run production
docker compose up -d

# Run development
docker compose -f docker-compose.yml -f docker-compose.dev.yml up

# View logs
docker compose logs -f xrpl-wallet

# Execute commands in container
docker compose exec xrpl-wallet sh

# Stop and remove
docker compose down

# Clean rebuild
docker compose build --no-cache
```

---

## 6. Kubernetes Deployment

### 6.1 Architecture Diagram

```
+------------------------------------------------------------------+
|                    Kubernetes Cluster                             |
|                                                                   |
|  +-----------------------------------------------------------+   |
|  |                     Namespace: xrpl-wallet                 |   |
|  |                                                            |   |
|  |  +------------------+     +------------------+             |   |
|  |  | ConfigMap        |     | Secret           |             |   |
|  |  | - policies       |     | - hmac-key       |             |   |
|  |  | - server.json    |     | - encryption-key |             |   |
|  |  +------------------+     +------------------+             |   |
|  |           |                       |                        |   |
|  |           v                       v                        |   |
|  |  +----------------------------------------------------+   |   |
|  |  |              Deployment: xrpl-wallet                |   |   |
|  |  |  +----------------------------------------------+  |   |   |
|  |  |  |              Pod                              |  |   |   |
|  |  |  |  +------------------+  +------------------+   |  |   |   |
|  |  |  |  | Container:       |  | Volume Mounts:   |   |  |   |   |
|  |  |  |  | xrpl-wallet-mcp  |  | - /data/keystore |   |  |   |   |
|  |  |  |  | securityContext: |  | - /data/policies |   |  |   |   |
|  |  |  |  |   runAsNonRoot   |  | - /data/logs     |   |  |   |   |
|  |  |  |  |   readOnlyRoot   |  +------------------+   |  |   |   |
|  |  |  |  +------------------+                         |  |   |   |
|  |  |  +----------------------------------------------+  |   |   |
|  |  +----------------------------------------------------+   |   |
|  |           |                                                |   |
|  |           v                                                |   |
|  |  +------------------+                                      |   |
|  |  | PersistentVolume |                                      |   |
|  |  | Claim: keystore  |                                      |   |
|  |  | (encrypted)      |                                      |   |
|  |  +------------------+                                      |   |
|  +-----------------------------------------------------------+   |
+------------------------------------------------------------------+
```

### 6.2 Namespace and RBAC

**namespace.yaml:**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: xrpl-wallet
  labels:
    app.kubernetes.io/name: xrpl-wallet-mcp
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

**rbac.yaml:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: xrpl-wallet
  namespace: xrpl-wallet
  labels:
    app.kubernetes.io/name: xrpl-wallet-mcp
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: xrpl-wallet-role
  namespace: xrpl-wallet
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["xrpl-wallet-config"]
    verbs: ["get", "watch"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["xrpl-wallet-secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: xrpl-wallet-binding
  namespace: xrpl-wallet
subjects:
  - kind: ServiceAccount
    name: xrpl-wallet
    namespace: xrpl-wallet
roleRef:
  kind: Role
  name: xrpl-wallet-role
  apiGroup: rbac.authorization.k8s.io
```

### 6.3 ConfigMap and Secrets

**configmap.yaml:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: xrpl-wallet-config
  namespace: xrpl-wallet
data:
  policy.json: |
    {
      "version": "1.0",
      "name": "kubernetes-production",
      "network": "mainnet",
      "tiers": {
        "autonomous": {
          "max_amount_xrp": 100,
          "daily_limit_xrp": 1000
        },
        "delayed": {
          "max_amount_xrp": 1000,
          "delay_seconds": 300
        },
        "cosign": {
          "min_amount_xrp": 1000,
          "signer_quorum": 2
        }
      }
    }
  server.json: |
    {
      "transport": "stdio",
      "metrics_enabled": true,
      "metrics_port": 9090
    }
```

**secrets.yaml (sealed-secrets recommended):**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: xrpl-wallet-secrets
  namespace: xrpl-wallet
type: Opaque
stringData:
  AUDIT_HMAC_KEY: "<base64-encoded-key>"
  # Note: Wallet encryption keys should use External Secrets Operator
  # or cloud KMS integration, not static secrets
```

### 6.4 Deployment

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: xrpl-wallet
  namespace: xrpl-wallet
  labels:
    app.kubernetes.io/name: xrpl-wallet-mcp
    app.kubernetes.io/version: "1.0.0"
spec:
  replicas: 1  # Single replica for key consistency
  selector:
    matchLabels:
      app.kubernetes.io/name: xrpl-wallet-mcp
  strategy:
    type: Recreate  # Ensure only one instance at a time
  template:
    metadata:
      labels:
        app.kubernetes.io/name: xrpl-wallet-mcp
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: xrpl-wallet
      automountServiceAccountToken: false

      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: xrpl-wallet-mcp
          image: xrpl-wallet-mcp:1.0.0
          imagePullPolicy: IfNotPresent

          # Container security
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL

          # Environment
          env:
            - name: NODE_ENV
              value: "production"
            - name: XRPL_NETWORK
              value: "mainnet"
            - name: XRPL_WEBSOCKET_URL
              value: "wss://xrplcluster.com"
            - name: XRPL_WALLET_KEYSTORE_PATH
              value: "/data/keystore"
            - name: XRPL_WALLET_POLICY_PATH
              value: "/config/policy.json"
            - name: XRPL_WALLET_LOG_PATH
              value: "/data/logs"
            - name: LOG_LEVEL
              value: "info"
            - name: LOG_FORMAT
              value: "json"
            - name: AUDIT_HMAC_KEY
              valueFrom:
                secretKeyRef:
                  name: xrpl-wallet-secrets
                  key: AUDIT_HMAC_KEY

          # Resource limits
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "1Gi"
              cpu: "2000m"

          # Volume mounts
          volumeMounts:
            - name: keystore
              mountPath: /data/keystore
            - name: logs
              mountPath: /data/logs
            - name: config
              mountPath: /config
              readOnly: true
            - name: tmp
              mountPath: /tmp

          # Probes
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3

          readinessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3

          # Ports
          ports:
            - name: metrics
              containerPort: 9090
              protocol: TCP

      volumes:
        - name: keystore
          persistentVolumeClaim:
            claimName: xrpl-wallet-keystore
        - name: logs
          persistentVolumeClaim:
            claimName: xrpl-wallet-logs
        - name: config
          configMap:
            name: xrpl-wallet-config
        - name: tmp
          emptyDir:
            sizeLimit: 64Mi
```

### 6.5 Persistent Volume Claims

**pvc.yaml:**
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: xrpl-wallet-keystore
  namespace: xrpl-wallet
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: encrypted-ssd  # Use encrypted storage class
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: xrpl-wallet-logs
  namespace: xrpl-wallet
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 10Gi
```

### 6.6 Network Policy

**network-policy.yaml:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: xrpl-wallet-network-policy
  namespace: xrpl-wallet
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: xrpl-wallet-mcp
  policyTypes:
    - Ingress
    - Egress

  # Allow no ingress (MCP is stdio-based)
  # Only metrics scraping if needed
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 9090

  # Allow egress only to XRPL nodes
  egress:
    # DNS resolution
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # XRPL WebSocket (outbound only)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 51233
```

---

## 7. Future: Cloud KMS Integration (Phase 2)

### 7.1 Architecture Diagram

```
+------------------------------------------------------------------+
|                    Cloud Infrastructure                           |
|                                                                   |
|  +------------------------+    +------------------------+        |
|  |   Compute Instance     |    |    Cloud KMS           |        |
|  |                        |    |                        |        |
|  |  +------------------+  |    |  +------------------+  |        |
|  |  | XRPL Agent       |  |    |  | Master Key       |  |        |
|  |  | Wallet MCP       |--|----|--> (HSM-backed)     |  |        |
|  |  +------------------+  |    |  +------------------+  |        |
|  |           |            |    |           |           |        |
|  +-----------|------------+    +-----------|------------+        |
|              |                             |                      |
|              v                             v                      |
|  +------------------------+    +------------------------+        |
|  |   Secret Manager       |    |   Cloud Monitoring     |        |
|  |                        |    |                        |        |
|  |  - Wallet encryption   |    |  - Key usage metrics   |        |
|  |    key (wrapped)       |    |  - Access logs         |        |
|  |  - HMAC keys           |    |  - Alerts              |        |
|  +------------------------+    +------------------------+        |
+------------------------------------------------------------------+
```

### 7.2 AWS KMS Configuration

```typescript
// AWS KMS integration example
import { KMSClient, DecryptCommand, GenerateDataKeyCommand } from '@aws-sdk/client-kms';

interface AWSKMSConfig {
  region: string;
  keyId: string;  // ARN of the CMK
  encryptionContext: Record<string, string>;
}

class AWSKMSKeyProvider implements KeyProvider {
  private client: KMSClient;
  private config: AWSKMSConfig;

  constructor(config: AWSKMSConfig) {
    this.config = config;
    this.client = new KMSClient({ region: config.region });
  }

  async generateDataKey(): Promise<{ plaintext: Buffer; encrypted: Buffer }> {
    const command = new GenerateDataKeyCommand({
      KeyId: this.config.keyId,
      KeySpec: 'AES_256',
      EncryptionContext: this.config.encryptionContext,
    });

    const response = await this.client.send(command);

    return {
      plaintext: Buffer.from(response.Plaintext!),
      encrypted: Buffer.from(response.CiphertextBlob!),
    };
  }

  async decryptDataKey(encryptedKey: Buffer): Promise<Buffer> {
    const command = new DecryptCommand({
      CiphertextBlob: encryptedKey,
      EncryptionContext: this.config.encryptionContext,
    });

    const response = await this.client.send(command);
    return Buffer.from(response.Plaintext!);
  }
}
```

### 7.3 GCP Cloud KMS Configuration

```typescript
// GCP Cloud KMS integration example
import { KeyManagementServiceClient } from '@google-cloud/kms';

interface GCPKMSConfig {
  projectId: string;
  locationId: string;
  keyRingId: string;
  cryptoKeyId: string;
}

class GCPKMSKeyProvider implements KeyProvider {
  private client: KeyManagementServiceClient;
  private keyName: string;

  constructor(config: GCPKMSConfig) {
    this.client = new KeyManagementServiceClient();
    this.keyName = this.client.cryptoKeyPath(
      config.projectId,
      config.locationId,
      config.keyRingId,
      config.cryptoKeyId
    );
  }

  async encrypt(plaintext: Buffer): Promise<Buffer> {
    const [response] = await this.client.encrypt({
      name: this.keyName,
      plaintext: plaintext,
    });
    return Buffer.from(response.ciphertext as Uint8Array);
  }

  async decrypt(ciphertext: Buffer): Promise<Buffer> {
    const [response] = await this.client.decrypt({
      name: this.keyName,
      ciphertext: ciphertext,
    });
    return Buffer.from(response.plaintext as Uint8Array);
  }
}
```

### 7.4 Key Hierarchy with Cloud KMS

```
+------------------------------------------------------------------+
|                    Key Hierarchy                                  |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------------+                                       |
|  | Cloud KMS Master Key   |  (HSM-backed, never exported)        |
|  | (CMK / KEK)            |                                       |
|  +------------|------------+                                       |
|               |                                                   |
|               | Wraps/Unwraps                                     |
|               v                                                   |
|  +------------------------+                                       |
|  | Data Encryption Key    |  (Generated per wallet)              |
|  | (DEK)                  |                                       |
|  +------------|------------+                                       |
|               |                                                   |
|               | Encrypts                                          |
|               v                                                   |
|  +------------------------+                                       |
|  | Wallet Private Keys    |  (Encrypted at rest)                 |
|  +------------------------+                                       |
+------------------------------------------------------------------+
```

---

## 8. Future: TEE Deployment (Phase 3)

### 8.1 AWS Nitro Enclave Architecture

```
+------------------------------------------------------------------+
|                    EC2 Instance with Nitro Enclave                |
|                                                                   |
|  +-----------------------------------------------------------+   |
|  |                    Parent Instance                         |   |
|  |                                                            |   |
|  |  +------------------+        +------------------+          |   |
|  |  | MCP Server       |        | vsock proxy      |          |   |
|  |  | (orchestrator)   |<------>| (port 5000)      |          |   |
|  |  +------------------+        +--------|---------+          |   |
|  |                                       |                    |   |
|  +-----------------------------------------------------------+   |
|                                          |                        |
|                                   vsock  |                        |
|                                          v                        |
|  +-----------------------------------------------------------+   |
|  |                    Nitro Enclave                           |   |
|  |              (Isolated memory & CPU)                       |   |
|  |                                                            |   |
|  |  +------------------+        +------------------+          |   |
|  |  | Signing Service  |        | Key Manager      |          |   |
|  |  | (inside enclave) |        | (HSM-like)       |          |   |
|  |  +------------------+        +------------------+          |   |
|  |                                                            |   |
|  |  - No persistent storage                                   |   |
|  |  - No network access                                       |   |
|  |  - Attestation-verified                                    |   |
|  +-----------------------------------------------------------+   |
|                                                                   |
|  External Attestation:                                           |
|  - PCR values verified by KMS                                    |
|  - Cryptographic proof of enclave identity                       |
+------------------------------------------------------------------+
```

### 8.2 Attestation Flow

```
+------------------------------------------------------------------+
|                    Attestation Flow                               |
+------------------------------------------------------------------+
|                                                                   |
|  1. Enclave Boot                                                  |
|     +------------------+                                          |
|     | Nitro Enclave    |                                          |
|     | boots with       |                                          |
|     | signed image     |                                          |
|     +--------|---------+                                          |
|              |                                                    |
|  2. Generate Attestation Document                                 |
|              v                                                    |
|     +------------------+                                          |
|     | PCR0: Enclave    |                                          |
|     |       image hash |                                          |
|     | PCR1: Boot mode  |                                          |
|     | PCR2: Application|                                          |
|     +--------|---------+                                          |
|              |                                                    |
|  3. Request Key from KMS                                          |
|              v                                                    |
|     +------------------+     +------------------+                  |
|     | Enclave sends    |---->| AWS KMS verifies |                  |
|     | attestation doc  |     | PCR values match |                  |
|     +------------------+     | allowed policy   |                  |
|                              +--------|---------+                  |
|                                       |                           |
|  4. KMS Releases Key                  v                           |
|                              +------------------+                  |
|                              | Encrypted DEK    |                  |
|                              | returned to      |                  |
|                              | enclave only     |                  |
|                              +------------------+                  |
+------------------------------------------------------------------+
```

### 8.3 TEE Configuration

**Enclave configuration (enclave.yaml):**
```yaml
# AWS Nitro Enclave configuration
Enclave:
  # EIF file (Enclave Image File)
  ImagePath: /opt/xrpl-wallet/signing-enclave.eif

  # Resource allocation
  MemoryMib: 1024
  CpuCount: 2

  # Debug mode (disable in production!)
  DebugMode: false

  # KMS policy for attestation
  KmsKeyArn: arn:aws:kms:us-east-1:123456789:key/abc-123
  AllowedPcrs:
    - Index: 0
      Value: "<sha384-hash-of-enclave-image>"
    - Index: 1
      Value: "<sha384-hash-of-kernel>"
    - Index: 2
      Value: "<sha384-hash-of-application>"
```

---

## 9. Network Architecture

### 9.1 Required Network Access

| Direction | Protocol | Port | Destination | Purpose |
|-----------|----------|------|-------------|---------|
| Outbound | WSS | 443 | xrplcluster.com | XRPL mainnet primary |
| Outbound | WSS | 443 | s1.ripple.com | XRPL mainnet fallback |
| Outbound | WSS | 443 | s2.ripple.com | XRPL mainnet fallback |
| Outbound | WSS | 51233 | s.altnet.rippletest.net | XRPL testnet |
| Outbound | WSS | 51233 | s.devnet.rippletest.net | XRPL devnet |
| Outbound | HTTPS | 443 | (webhook URL) | Notification webhook |

**Note**: MCP uses stdio transport - no inbound ports are required for standard MCP operation.

### 9.2 Firewall Configuration

**iptables (Linux):**
```bash
#!/bin/bash
# Outbound only firewall for XRPL wallet server

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow DNS (required for XRPL hostname resolution)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow HTTPS/WSS outbound to XRPL nodes
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 51233 -j ACCEPT

# Allow NTP (optional, for time sync)
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# Log dropped packets (for debugging)
iptables -A INPUT -j LOG --log-prefix "DROPPED INPUT: "
iptables -A OUTPUT -j LOG --log-prefix "DROPPED OUTPUT: "
```

**UFW (Simplified):**
```bash
# Reset to defaults
sudo ufw default deny incoming
sudo ufw default deny outgoing

# Allow established
sudo ufw allow out on eth0 to any port 53 proto udp  # DNS
sudo ufw allow out on eth0 to any port 443 proto tcp  # HTTPS/WSS
sudo ufw allow out on eth0 to any port 51233 proto tcp  # XRPL testnet

# Enable
sudo ufw enable
```

### 9.3 XRPL Node Connection Strategy

```typescript
// Connection configuration with failover
const XRPL_NETWORKS = {
  mainnet: {
    primary: 'wss://xrplcluster.com/',
    fallback: [
      'wss://s1.ripple.com/',
      'wss://s2.ripple.com/',
    ],
    // Health check interval
    healthCheckInterval: 30000,
    // Reconnection backoff
    reconnect: {
      initialDelay: 1000,
      maxDelay: 30000,
      factor: 2,
    },
  },
  testnet: {
    primary: 'wss://s.altnet.rippletest.net:51233/',
    fallback: [],
  },
  devnet: {
    primary: 'wss://s.devnet.rippletest.net:51233/',
    fallback: [],
  },
};
```

---

## 10. Operational Considerations

### 10.1 Backup Strategy

**Keystore Backup:**
```
+------------------------------------------------------------------+
|                    Backup Architecture                            |
+------------------------------------------------------------------+
|                                                                   |
|  Primary Storage              Backup Storage                      |
|  +------------------+         +------------------+                 |
|  | /var/lib/xrpl-   |   -->   | Encrypted S3     |                 |
|  | wallet/keystore/ |   daily | bucket with      |                 |
|  | (encrypted)      |         | versioning       |                 |
|  +------------------+         +------------------+                 |
|                                        |                          |
|                               +--------v---------+                 |
|                               | Glacier Deep     |                 |
|                               | Archive (90 day  |                 |
|                               | retention)       |                 |
|                               +------------------+                 |
+------------------------------------------------------------------+
```

**Backup Script:**
```bash
#!/bin/bash
# /opt/xrpl-wallet/scripts/backup.sh

set -euo pipefail

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
KEYSTORE_PATH="/var/lib/xrpl-wallet/keystore"
BACKUP_PATH="/backup/xrpl-wallet"
S3_BUCKET="s3://your-backup-bucket/xrpl-wallet"

# Create local backup
mkdir -p "${BACKUP_PATH}"
tar -czf "${BACKUP_PATH}/keystore-${BACKUP_DATE}.tar.gz" -C "${KEYSTORE_PATH}" .

# Encrypt backup (additional layer)
gpg --symmetric --cipher-algo AES256 \
    --output "${BACKUP_PATH}/keystore-${BACKUP_DATE}.tar.gz.gpg" \
    "${BACKUP_PATH}/keystore-${BACKUP_DATE}.tar.gz"

# Remove unencrypted backup
rm "${BACKUP_PATH}/keystore-${BACKUP_DATE}.tar.gz"

# Upload to S3
aws s3 cp "${BACKUP_PATH}/keystore-${BACKUP_DATE}.tar.gz.gpg" \
    "${S3_BUCKET}/keystore-${BACKUP_DATE}.tar.gz.gpg" \
    --storage-class STANDARD_IA

# Verify upload
aws s3api head-object \
    --bucket "your-backup-bucket" \
    --key "xrpl-wallet/keystore-${BACKUP_DATE}.tar.gz.gpg"

# Clean up old local backups (keep 7 days)
find "${BACKUP_PATH}" -name "keystore-*.tar.gz.gpg" -mtime +7 -delete

echo "Backup completed: keystore-${BACKUP_DATE}.tar.gz.gpg"
```

### 10.2 Log Rotation

**logrotate configuration (/etc/logrotate.d/xrpl-wallet):**
```
/var/log/xrpl-wallet/audit/audit-*.jsonl {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 0600 xrpl-wallet xrpl-wallet
    dateext
    dateformat -%Y%m%d
    postrotate
        # Verify hash chain integrity before rotation
        /opt/xrpl-wallet/scripts/verify-audit-chain.sh || true
    endscript
}

/var/log/xrpl-wallet/server.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 xrpl-wallet xrpl-wallet
    postrotate
        systemctl reload xrpl-wallet-mcp || true
    endscript
}
```

### 10.3 Monitoring

**Prometheus Metrics:**
```yaml
# prometheus.yml scrape config
scrape_configs:
  - job_name: 'xrpl-wallet-mcp'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

**Key Metrics to Monitor:**

| Metric | Type | Alert Threshold |
|--------|------|-----------------|
| `xrpl_wallet_transactions_total` | Counter | N/A (track rate) |
| `xrpl_wallet_transaction_errors_total` | Counter | > 5 in 5 min |
| `xrpl_wallet_policy_denials_total` | Counter | > 10 in 5 min |
| `xrpl_wallet_rate_limit_hits_total` | Counter | > 20 in 5 min |
| `xrpl_wallet_auth_failures_total` | Counter | > 3 in 5 min |
| `xrpl_wallet_xrpl_connection_status` | Gauge | != 1 |
| `xrpl_wallet_keystore_unlock_duration_seconds` | Histogram | p99 > 2s |
| `xrpl_wallet_audit_log_size_bytes` | Gauge | > 1GB |
| `xrpl_wallet_audit_chain_valid` | Gauge | != 1 |

**Grafana Dashboard (key panels):**
```json
{
  "panels": [
    {
      "title": "Transaction Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(xrpl_wallet_transactions_total[5m])"
        }
      ]
    },
    {
      "title": "Policy Decisions",
      "type": "piechart",
      "targets": [
        {
          "expr": "sum by (decision) (xrpl_wallet_policy_decisions_total)"
        }
      ]
    },
    {
      "title": "XRPL Connection Status",
      "type": "stat",
      "targets": [
        {
          "expr": "xrpl_wallet_xrpl_connection_status"
        }
      ]
    },
    {
      "title": "Audit Chain Integrity",
      "type": "stat",
      "targets": [
        {
          "expr": "xrpl_wallet_audit_chain_valid"
        }
      ],
      "thresholds": {
        "steps": [
          { "value": 0, "color": "red" },
          { "value": 1, "color": "green" }
        ]
      }
    }
  ]
}
```

### 10.4 Health Check Implementation

```typescript
// Health check endpoint implementation
interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  checks: {
    name: string;
    status: 'pass' | 'fail' | 'warn';
    message?: string;
    duration_ms?: number;
  }[];
  version: string;
  uptime_seconds: number;
}

async function healthCheck(): Promise<HealthStatus> {
  const checks = [];
  const startTime = process.uptime();

  // Check XRPL connection
  const xrplCheck = await checkXRPLConnection();
  checks.push({
    name: 'xrpl_connection',
    status: xrplCheck.connected ? 'pass' : 'fail',
    message: xrplCheck.error || 'Connected to XRPL network',
    duration_ms: xrplCheck.latency,
  });

  // Check keystore accessibility
  const keystoreCheck = await checkKeystoreAccess();
  checks.push({
    name: 'keystore_access',
    status: keystoreCheck.accessible ? 'pass' : 'fail',
    message: keystoreCheck.error || 'Keystore accessible',
  });

  // Check audit log chain integrity
  const auditCheck = await checkAuditLogIntegrity();
  checks.push({
    name: 'audit_log_integrity',
    status: auditCheck.valid ? 'pass' : 'fail',
    message: auditCheck.error || 'Audit chain valid',
  });

  // Check policy file
  const policyCheck = await checkPolicyFile();
  checks.push({
    name: 'policy_loaded',
    status: policyCheck.loaded ? 'pass' : 'fail',
    message: policyCheck.error || `Policy: ${policyCheck.name}`,
  });

  // Determine overall status
  const failedChecks = checks.filter(c => c.status === 'fail');
  const warnChecks = checks.filter(c => c.status === 'warn');

  let overallStatus: 'healthy' | 'degraded' | 'unhealthy';
  if (failedChecks.length > 0) {
    overallStatus = 'unhealthy';
  } else if (warnChecks.length > 0) {
    overallStatus = 'degraded';
  } else {
    overallStatus = 'healthy';
  }

  return {
    status: overallStatus,
    checks,
    version: process.env.npm_package_version || '1.0.0',
    uptime_seconds: Math.floor(startTime),
  };
}
```

### 10.5 Incident Response

**Runbook: Authentication Lockout Triggered**
```
Incident: AUTH_LOCKOUT_TRIGGERED
Severity: High

Symptoms:
- xrpl_wallet_auth_failures_total spikes
- xrpl_wallet_auth_lockouts_total increases
- Users report inability to unlock wallets

Investigation:
1. Check recent auth failure logs:
   journalctl -u xrpl-wallet-mcp | grep "auth_failure"

2. Identify source of failed attempts:
   - Check correlation IDs
   - Review audit logs for patterns

3. Determine if legitimate or attack:
   - User typos: Wait for lockout to expire
   - Brute force: Extend lockout, consider IP blocking

Resolution:
- If legitimate user: Wait for lockout expiry (30 min initial)
- If attack: Consider network-level blocking
- Manual lockout clear (emergency only):
  sudo -u xrpl-wallet node /opt/xrpl-wallet/scripts/clear-lockout.js <wallet-id>

Post-Incident:
- Review audit logs for full timeline
- Update blocklist if attack identified
- Consider policy adjustment if too sensitive
```

---

## 11. Environment Configuration Reference

### 11.1 Complete Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NODE_ENV` | No | `development` | Runtime environment |
| `XRPL_NETWORK` | Yes | - | Network: `mainnet`, `testnet`, `devnet` |
| `XRPL_WEBSOCKET_URL` | No | (per network) | Custom WebSocket URL |
| `XRPL_WALLET_KEYSTORE_PATH` | Yes | - | Path to keystore directory |
| `XRPL_WALLET_POLICY_PATH` | Yes | - | Path to policy JSON file |
| `XRPL_WALLET_LOG_PATH` | Yes | - | Path to audit log directory |
| `LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | No | `json` | Log format: `json`, `pretty` |
| `AUDIT_HMAC_KEY` | Yes (prod) | - | Base64-encoded HMAC key for audit chain |
| `RATE_LIMIT_ENABLED` | No | `true` | Enable rate limiting |
| `RATE_LIMIT_MULTIPLIER` | No | `1` | Multiplier for rate limits (dev only) |
| `METRICS_ENABLED` | No | `true` | Enable Prometheus metrics |
| `METRICS_PORT` | No | `9090` | Metrics server port |
| `HEALTH_PORT` | No | `3000` | Health check server port |

### 11.2 Configuration File Reference

**server.json:**
```json
{
  "server": {
    "transport": "stdio",
    "health_enabled": true,
    "health_port": 3000,
    "metrics_enabled": true,
    "metrics_port": 9090
  },
  "security": {
    "rate_limit_enabled": true,
    "max_request_size_bytes": 1048576,
    "session_timeout_seconds": 1800,
    "lockout_threshold": 5,
    "lockout_duration_seconds": 1800
  },
  "xrpl": {
    "connection_timeout_ms": 10000,
    "request_timeout_ms": 30000,
    "reconnect_delay_ms": 1000,
    "max_reconnect_delay_ms": 30000
  },
  "audit": {
    "enabled": true,
    "verify_on_startup": true,
    "verify_interval_seconds": 3600
  }
}
```

---

## 12. Deployment Checklist

### 12.1 Pre-Deployment Checklist

**Environment Preparation:**
- [ ] Node.js 20+ LTS installed
- [ ] Dedicated system user created (non-root)
- [ ] Directory structure created with correct permissions
- [ ] Firewall rules configured (outbound only)
- [ ] TLS certificates provisioned (if using SSE)

**Configuration:**
- [ ] Policy file reviewed and customized for environment
- [ ] Environment variables configured
- [ ] Audit HMAC key generated securely
- [ ] Log rotation configured
- [ ] Backup script tested

**Security Review:**
- [ ] File permissions verified (0600 for keys, 0700 for directories)
- [ ] Systemd security hardening enabled
- [ ] No secrets in environment files or logs
- [ ] Network isolation verified

### 12.2 Post-Deployment Checklist

**Verification:**
- [ ] Service starts successfully
- [ ] Health check returns healthy
- [ ] XRPL connection established
- [ ] Test transaction (testnet) succeeds
- [ ] Audit log entry created
- [ ] Metrics endpoint accessible

**Monitoring:**
- [ ] Prometheus scraping configured
- [ ] Grafana dashboard imported
- [ ] Alerts configured for critical metrics
- [ ] Log aggregation working

**Operational:**
- [ ] Backup job scheduled
- [ ] Log rotation tested
- [ ] Incident runbooks accessible
- [ ] On-call procedures documented

### 12.3 Production Go-Live Checklist

**Final Verification:**
- [ ] Policy file using production settings (conservative limits)
- [ ] Testnet keys NOT present on production
- [ ] Mainnet keys encrypted and backed up
- [ ] All debug logging disabled
- [ ] Rate limits at production values
- [ ] Audit chain HMAC key secured

**Sign-Off:**
- [ ] Security review completed
- [ ] Operations team briefed
- [ ] Rollback procedure tested
- [ ] Monitoring alerts verified

---

## Related Documents

- [05 - Building Blocks](05-building-blocks.md) - Container architecture
- [02 - Constraints](02-constraints.md) - Technical constraints
- [Security Architecture](../security/SECURITY-ARCHITECTURE.md) - Security implementation
- [Security Requirements](../security/security-requirements.md) - Security requirements

---

**Document History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-28 | QA/DevOps Engineer | Initial version |

---

*Arc42 Template - Section 07: Deployment View*
