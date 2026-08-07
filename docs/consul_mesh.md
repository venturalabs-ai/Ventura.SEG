# Consul Service Mesh — Ventura.SEG

## Papel no mesh

Ventura.SEG atua como **camada de segurança** (gateway / policy enforcement) e pode ser registrado no Consul para:

- discovery por outros serviços
- health checks
- participação no **Consul Connect** (sidecar Envoy + mTLS)
- resolução de upstreams healthy

O mTLS de ponta a ponta é responsabilidade do **sidecar** (Connect). O código Python registra o serviço, anuncia meta Connect e consulta o catálogo — não substitui o Envoy.

## Variáveis de ambiente

| Variável | Default | Descrição |
|----------|---------|-----------|
| `CONSUL_HTTP_ADDR` | `http://127.0.0.1:8500` | API do Consul |
| `CONSUL_HTTP_TOKEN` | — | ACL token |
| `CONSUL_SERVICE_NAME` | `ventura-seg` | Nome do serviço |
| `CONSUL_SERVICE_PORT` | `8080` | Porta da aplicação |
| `CONSUL_SERVICE_ID` | `ventura-seg-<hostname>` | ID único |
| `CONSUL_DATACENTER` | — | DC opcional |
| `CONSUL_CONNECT` | `true` | Anuncia sidecar Connect |

## Uso

```python
from service_mesh import ConsulMeshClient
from audit import AuditLogger

audit = AuditLogger()
mesh = ConsulMeshClient(audit_logger=audit)

# Registra Ventura.SEG no agent local + health check /health
sid = mesh.register_ventura_service(
    port=8080,
    tags=["security", "dlp", "gateway"],
    health_http="http://127.0.0.1:8080/health",
    enable_connect=True,
)

# Descobre backend apenas se healthy
instances = mesh.discover("payment-api", passing_only=True)
for i in instances:
    print(i.address, i.port, i.tags)

# Shutdown limpo
mesh.deregister(sid)
```

## Intentions (política de quem pode falar com quem)

No Consul Connect, defina intentions para que só serviços autorizados alcancem o Ventura.SEG:

```hcl
# allow agents -> ventura-seg
Kind = "service-intentions"
Name = "ventura-seg"
Sources = [
  {
    Name   = "ai-agent"
    Action = "allow"
  }
]
```

```bash
consul config write intention-ventura.hcl
```

## Sidecar (produção)

Em Kubernetes / Nomad, injete o sidecar Connect em vez de depender de Connect Native:

```yaml
# exemplo simplificado de anotação
annotations:
  consul.hashicorp.com/connect-inject: "true"
  consul.hashicorp.com/connect-service: "ventura-seg"
```

O proxy Envoy termina mTLS; a aplicação Ventura.SEG escuta em localhost.

## Relação com Vault

- **Vault**: segredos e auth OIDC (credenciais nunca no agente)
- **Consul**: identidade de serviço, discovery e mTLS entre serviços

Juntos formam a base HashiCorp para zero-trust em torno dos agentes de IA.
