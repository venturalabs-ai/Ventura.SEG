# Ventura.SEG — Service Intentions (Consul Connect)
# ===================================================
# Controla quem pode estabelecer conexão mTLS com o serviço ventura-seg.
# Default-deny: apenas fontes explicitamente allow passam.
#
# Aplicar:
#   consul config write consul/intentions/ventura-seg.hcl
# Ou via código:
#   mesh.apply_intention_file("consul/intentions/ventura-seg.hcl")

Kind = "service-intentions"
Name = "ventura-seg"

Sources = [
  # Agentes de IA autorizados a falar com a camada de segurança
  {
    Name        = "ai-agent"
    Action      = "allow"
    Description = "Agentes de IA internos"
  },
  {
    Name        = "ai-orchestrator"
    Action      = "allow"
    Description = "Orquestrador multi-agente"
  },
  {
    Name        = "admin-api"
    Action      = "allow"
    Description = "API administrativa / painel de políticas"
  },
  # Tudo o mais é negado
  {
    Name        = "*"
    Action      = "deny"
    Description = "Default deny"
  }
]
