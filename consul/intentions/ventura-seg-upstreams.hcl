# Intentions de SAÍDA — o que o Ventura.SEG pode chamar
# ======================================================
# Destination = serviço de destino; Source = ventura-seg

# Vault (só se Vault estiver no mesh como serviço "vault")
Kind = "service-intentions"
Name = "vault"

Sources = [
  {
    Name        = "ventura-seg"
    Action      = "allow"
    Description = "Ventura.SEG precisa ler segredos"
  },
  {
    Name   = "*"
    Action = "deny"
  }
]
