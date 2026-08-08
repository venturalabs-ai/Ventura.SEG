# Consul Service Mesh — Ventura.SEG

## Papel no mesh

Ventura.SEG atua como **camada de segurança** e registra-se no Consul para discovery, health checks e **Consul Connect** (mTLS via sidecar).

## Intentions de rede (obrigatório em produção)

Modelo **default-deny**: só quem estiver em `allow` consegue abrir conexão mTLS com `ventura-seg`.

### Arquivos

```
consul/intentions/
├── ventura-seg.hcl      # CLI: consul config write
├── ventura-seg.json     # API / IntentionManager
└── ventura-seg-upstreams.hcl  # ventura-seg → vault
```

### Via CLI

```bash
consul config write consul/intentions/ventura-seg.hcl
```

### Via código

```python
from service_mesh import ConsulMeshClient, IntentionManager

mesh = ConsulMeshClient(audit_logger=audit)
intents = IntentionManager(mesh)

# Opção A — arquivo JSON versionado
intents.apply_json_file("consul/intentions/ventura-seg.json")

# Opção B — default deny + allow list
intents.apply_default_deny_allow(
    destination="ventura-seg",
    allow_from=["ai-agent", "ai-orchestrator", "admin-api"],
)

# Opção C — allow pontual
intents.allow(source="ai-agent", destination="ventura-seg")
intents.deny(source="untrusted-job", destination="ventura-seg")
```

### Matriz recomendada

| Source | Destination | Action |
|--------|-------------|--------|
| `ai-agent` | `ventura-seg` | allow |
| `ai-orchestrator` | `ventura-seg` | allow |
| `admin-api` | `ventura-seg` | allow |
| `*` | `ventura-seg` | **deny** |
| `ventura-seg` | `vault` | allow (se Vault no mesh) |

## Registro do serviço

```python
mesh.register_ventura_service(
    port=8080,
    tags=["security", "dlp", "gateway"],
    health_http="http://127.0.0.1:8080/health",
    enable_connect=True,
)
```

## Variáveis de ambiente

| Variável | Default |
|----------|---------|
| `CONSUL_HTTP_ADDR` | `http://127.0.0.1:8500` |
| `CONSUL_HTTP_TOKEN` | — |
| `CONSUL_SERVICE_NAME` | `ventura-seg` |
| `CONSUL_SERVICE_PORT` | `8080` |
| `CONSUL_CONNECT` | `true` |

## Vault + Consul

- **Vault + OIDC**: segredos e auth
- **Consul intentions**: quem pode falar com a camada de segurança no mesh
