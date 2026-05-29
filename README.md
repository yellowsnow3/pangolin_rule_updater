# Pangolin Rule Updater

[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)

A lightweight Docker container that exposes a webhook endpoint. When a client calls the endpoint with their secret token, their originating IP is automatically applied to every Pangolin firewall rule mapped to that token.

Multiple clients and tokens are supported — each token has its own set of resources/rules defined in the server-side configuration, so clients never need to know which resources they are whitelisting.

## ✨ Features

- **Push-based updates** — clients send a single HTTP GET; the server does the rest
- **Multi-client** — any number of tokens, each mapped to their own set of Pangolin rules
- **Multi-rule per client** — one push updates all rules for that client atomically
- **Per-client IP cache** — skips Pangolin API calls when the IP hasn't changed
- **Per-client Pangolin overrides** — optional `pangolin_host` / `pangolin_api_key` per client for multi-instance setups
- **YAML config** — single `config.yml` file; no env-variable sprawl
- **Docker Compose ready** — single-command deployment

## 📋 Prerequisites

- Docker and Docker Compose
- Pangolin Integration API enabled: https://docs.pangolin.net/manage/integration-api
- A Pangolin API token with:
  - `Resource Rule → Update Resource Rule`
- The Resource ID(s) and Rule ID(s) you want to keep updated
  - Visit the Swagger UI at `https://<your-pangolin>/v1/docs`, authorize with your token, and call `GET /resource/{resourceId}/rules` to list rules

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/olizimmermann/pangolin_rule_updater.git
   cd pangolin_rule_updater
   ```

2. **Create your config file**
   ```bash
   cp config.example.yml config.yml
   ```

3. **Edit `config.yml`** — set your Pangolin host, API key, and define your clients (see [Configuration](#️-configuration) below)

4. **Build and start**
   ```bash
   docker compose up -d
   ```

## ⚙️ Configuration

All configuration lives in `config.yml` (mounted into the container as a read-only volume).

```yaml
# Pangolin instance (global defaults, can be overridden per client)
pangolin_host: https://pangolin.example.com
pangolin_api_key: YOUR_PANGOLIN_API_KEY

server:
  port: 8080      # port this service listens on
  path: /update   # URL path for update requests

clients:
  - name: home_office
    secret: my-secret-token          # clients send ?token=<this value>
    rules:
      - resource_id: 1
        rule_id: 5
      - resource_id: 2
        rule_id: 9                   # both rules updated on every push

  - name: mobile
    secret: another-secret-token
    rules:
      - resource_id: 1
        rule_id: 6
        priority: 90                 # optional, default: 100
        action: ACCEPT               # optional: ACCEPT, DROP, or PASS — default: ACCEPT
        enabled: true                # optional, default: true
```

### Configuration reference

**Top-level**

| Key | Required | Description |
|-----|:--------:|-------------|
| `pangolin_host` | ✅ | Base URL of your Pangolin instance |
| `pangolin_api_key` | ✅ | Pangolin API Bearer token |
| `server.port` | ❌ | Port to listen on (default: `8080`) |
| `server.path` | ❌ | URL path for update requests (default: `/update`) |

**Per client**

| Key | Required | Description |
|-----|:--------:|-------------|
| `name` | ✅ | Human-readable label (used in logs) |
| `secret` | ✅ | Token the client sends as `?token=<secret>` |
| `rules` | ✅ | List of rules to update (at least one) |
| `pangolin_host` | ❌ | Overrides the global `pangolin_host` for this client |
| `pangolin_api_key` | ❌ | Overrides the global `pangolin_api_key` for this client |

**Per rule**

| Key | Required | Default | Description |
|-----|:--------:|---------|-------------|
| `resource_id` | ✅ | — | Resource ID in Pangolin |
| `rule_id` | ✅ | — | Rule ID to update |
| `priority` | ❌ | `100` | Rule priority |
| `action` | ❌ | `ACCEPT` | `ACCEPT` — bypass auth; `DROP` — block; `PASS` — send to auth |
| `enabled` | ❌ | `true` | Enable or disable the rule |

## 🚀 Usage

Each client sends a plain HTTP GET to the endpoint with their secret token. The server reads the originating IP from the request (supporting `Cf-Connecting-Ip`, `X-Real-Ip`, `X-Forwarded-For`, and direct TCP) and applies it to all rules configured for that token.

```
GET http://<host>:8080/update?token=my-secret-token
```

**Example — trigger from a browser bookmark or cron:**
```bash
curl "https://update.example.com/update?token=my-secret-token"
```

**Response codes**

| Code | Meaning |
|------|---------|
| `200` | All rules updated (or IP unchanged — no update needed) |
| `207` | Partial success — some rules updated, check logs |
| `401` | Bad or missing token |
| `500` | All rule updates failed |

## 🔒 Security notes

- Use a strong random value for each client's `secret` — minimum 32 characters (e.g. `openssl rand -hex 32`). The server refuses to start if any secret is shorter.
- Place the service behind a TLS-terminating reverse proxy (Pangolin itself, Traefik, nginx, etc.) so tokens are not sent in plain text
- `config.yml` contains your secrets — restrict file permissions accordingly (`chmod 600 config.yml`)

## 🚀 Common commands

```bash
# Start
docker compose up -d

# View live logs
docker compose logs -f

# Rebuild after code or config changes
docker compose build --no-cache && docker compose up -d

# Stop
docker compose down
```

## 📁 Project structure

```
pangolin_rule_updater/
├── Dockerfile              # Container definition
├── docker-compose.yml      # Service orchestration
├── update_ip.py            # Application
├── requirements.txt        # Python dependencies
├── config.example.yml      # Template — copy to config.yml
└── README.md
```

## 🔧 Pangolin API reference

### List rules for a resource
```bash
curl 'https://pangolin.example.com/v1/resource/<RESOURCE_ID>/rules' \
  -H 'Authorization: Bearer <API_KEY>'
```

### Manually update a rule
```bash
curl -X POST \
  'https://pangolin.example.com/v1/resource/<RESOURCE_ID>/rule/<RULE_ID>' \
  -H 'Authorization: Bearer <API_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"action":"ACCEPT","match":"IP","value":"1.2.3.4","priority":100,"enabled":true}'
```

## 🐛 Troubleshooting

| Symptom | Check |
|---------|-------|
| Container exits immediately | `config.yml` is mounted and valid; run `docker compose logs` for details |
| `401` on update requests | Token in the request matches the `secret` in `config.yml` |
| Rules not updating | Correct `resource_id` / `rule_id`; test with the curl commands above |
| Pangolin auth errors | `pangolin_api_key` is valid and has `Resource Rule → Update` permission |

## ⭐ Like this project?

[![Star on GitHub](https://img.shields.io/github/stars/olizimmermann/pangolin_rule_updater?style=social)](https://github.com/olizimmermann/pangolin_rule_updater)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Open a Pull Request

## 📝 License

MIT — see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Pangolin](https://github.com/fosrl/pangolin) for the great self-hosted tunnelling platform

**Found a bug or have a question? Open an [issue](https://github.com/olizimmermann/pangolin_rule_updater/issues).**
