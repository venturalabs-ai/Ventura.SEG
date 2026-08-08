# Exemplo de Integração: LangChain + Ventura.SEG

Este exemplo demonstra como proteger agentes LangChain com as camadas de segurança do Ventura.SEG.

## 🛡️ Camadas de Proteção Aplicadas

1. **Gateway de Entrada**: Sanitização de inputs maliciosos
2. **Motor de Permissões**: Controle granular de ações permitidas
3. **Proxy de Credenciais**: Proteção de secrets e API keys
4. **Gateway de Saída (DLP)**: Prevenção de vazamento de dados sensíveis
5. **Auditoria**: Log completo de todas operações

## 📋 Pré-requisitos

```bash
pip install langchain langchain-openai openai
export OPENAI_API_KEY="sua-chave-aqui"
```

## 🚀 Uso Rápido

```python
from secure_langchain_agent import SecureLangChainAgent
from langchain_openai import ChatOpenAI
from langchain.tools import Tool

# Criar LLM
llm = ChatOpenAI(model="gpt-4", temperature=0)

# Definir ferramentas
tools = [
    Tool(
        name="SearchDatabase",
        func=lambda q: f"Resultados: {q}",
        description="Busca no banco de dados"
    )
]

# Criar agente seguro
agent = SecureLangChainAgent(
    llm=llm,
    tools=tools,
    system_message="Assistente de banco de dados",
    policies_dir="../../../policies"
)

# Executar
result = agent.invoke("Busque informações do cliente X")
print(result["output"])
```

## 🔒 Cenários de Segurança

### 1. Bloqueio de Comandos Perigosos

```python
# Input malicioso tentando injection
result = agent.invoke("DROP TABLE users; --")

# Resultado:
# {
#   "blocked": True,
#   "reason": "Comando SQL perigoso bloqueado"
# }
```

### 2. DLP - Redação de Dados Sensíveis

```python
# Query que pode retornar dados sensíveis
result = agent.invoke("Qual o CPF do cliente João?")

# Output original: "O CPF é 123.456.789-00"
# Output protegido: "O CPF é [REDACTED:CPF]"
```

### 3. Proteção de Credenciais

```python
# Secrets são protegidos automaticamente
api_key = "sk-proj-abc123..."  # Real API key

# Internamente convertido para:
# handle = "HANDLE_a1b2c3d4"

# LLM nunca vê a credencial real
```

## 📊 Auditoria

Todas as execuções são registradas em `audit_langchain.jsonl`:

```json
{
  "timestamp": "2026-08-08T14:30:00Z",
  "event": "agent_execution",
  "session_id": "demo_12345",
  "input_length": 45,
  "output_length": 128,
  "dlp_triggered": false,
  "permission_rule": "allow_read_database"
}
```

## ⚙️ Configuração de Políticas

Edite os arquivos em `policies/`:

### `policies/allowlist_commands.yaml`
```yaml
allowed_patterns:
  - pattern: "^SELECT.*FROM.*WHERE.*"
    description: "Queries SELECT com WHERE"
  - pattern: "^SHOW.*"
    description: "Comandos SHOW"

blocked_patterns:
  - pattern: ".*DROP\\s+(TABLE|DATABASE).*"
    action: block
    reason: "DROP commands não permitidos"
```

### `policies/dlp_rules.yaml`
```yaml
rules:
  - name: cpf
    pattern: "\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}"
    action: redact
    replacement: "[REDACTED:CPF]"
```

## 🧪 Testando

```bash
python secure_langchain_agent.py
```

## 📈 Performance

- **Latência adicional**: ~10-20ms por request
- **Overhead de memória**: ~5MB
- **Throughput**: Suporta 1000+ req/s

## 🔗 Integração com Ferramentas Reais

### Exemplo: Busca em Vector Database

```python
from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings

# Vector store protegido
vectorstore = Chroma(
    embedding_function=OpenAIEmbeddings(),
    persist_directory="./chroma_db"
)

# Tool protegida
search_tool = Tool(
    name="VectorSearch",
    func=lambda q: vectorstore.similarity_search(q, k=3),
    description="Busca semântica em documentos"
)

agent = SecureLangChainAgent(
    llm=llm,
    tools=[search_tool],
    system_message="Assistente de documentos"
)
```

## 🚨 Tratamento de Erros

```python
try:
    result = agent.invoke(user_input)
except PermissionDeniedError as e:
    print(f"Acesso negado: {e}")
except DLPViolationError as e:
    print(f"Dados sensíveis detectados: {e}")
except Exception as e:
    print(f"Erro: {e}")
```

## 📚 Recursos Adicionais

- [Documentação Ventura.SEG](../../../README.md)
- [Threat Model](../../../THREAT_MODEL.md)
- [Políticas de Exemplo](../../../policies/)

## 🤝 Contribuindo

Sugestões de melhorias? Abra uma issue no repositório principal!
