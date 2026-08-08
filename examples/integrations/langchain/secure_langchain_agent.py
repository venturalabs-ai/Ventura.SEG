"""
Exemplo de integração do Ventura.SEG com LangChain
Demonstra como proteger agentes LangChain com camadas de segurança full-time
"""
import os
import sys
from pathlib import Path

# Adicionar src ao path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from typing import Any, Dict, List, Optional
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder

# Importar módulos Ventura.SEG
from ventura_seg.gateway_in import GatewayIn
from ventura_seg.gateway_out import GatewayOut
from ventura_seg.permission_engine import PermissionEngine, Action
from ventura_seg.credential_proxy import CredentialProxy
from ventura_seg.audit import AuditLog


class SecureLangChainAgent:
    """
    Wrapper de segurança para agentes LangChain

    Aplica as camadas Ventura.SEG:
    - Gateway de Entrada: sanitização de inputs
    - Motor de Permissões: controle de ações permitidas
    - Gateway de Saída: DLP para prevenir vazamento de dados
    - Proxy de Credenciais: proteção de secrets
    - Auditoria: log completo de todas operações
    """

    def __init__(
        self,
        llm: ChatOpenAI,
        tools: List[Tool],
        system_message: str,
        policies_dir: str = "policies",
        audit_file: str = "audit.jsonl"
    ):
        self.llm = llm
        self.tools = tools
        self.system_message = system_message

        # Inicializar camadas de segurança
        self.gateway_in = GatewayIn(policies_dir=policies_dir)
        self.gateway_out = GatewayOut(policies_dir=policies_dir)
        self.permission_engine = PermissionEngine(policies_dir=policies_dir)
        self.credential_proxy = CredentialProxy()
        self.audit_log = AuditLog(audit_file)

        # Criar agente LangChain
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_message),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("user", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])

        self.agent = create_openai_functions_agent(llm, tools, prompt)
        self.executor = AgentExecutor(agent=self.agent, tools=tools, verbose=True)

    def invoke(self, user_input: str, session_id: str = "default") -> Dict[str, Any]:
        """
        Executa o agente com proteções de segurança completas

        Args:
            user_input: Input do usuário
            session_id: ID da sessão para auditoria

        Returns:
            Dict com output e metadados de segurança
        """
        try:
            # CAMADA 1: Gateway de Entrada - Sanitizar input
            sanitized_input = self.gateway_in.sanitize(user_input)
            self.audit_log.log("input_sanitized", {
                "session_id": session_id,
                "original_length": len(user_input),
                "sanitized_length": len(sanitized_input)
            })

            # CAMADA 2: Motor de Permissões - Validar ação
            permission_decision = self.permission_engine.check_permission(
                action=Action.EXECUTE,
                resource=f"agent:{self.system_message[:50]}",
                context={"input": sanitized_input}
            )

            if permission_decision.action == Action.BLOCK:
                self.audit_log.log("permission_denied", {
                    "session_id": session_id,
                    "reason": permission_decision.reason
                })
                return {
                    "output": "Operação bloqueada por política de segurança.",
                    "blocked": True,
                    "reason": permission_decision.reason
                }

            # CAMADA 3: Proteção de Credenciais
            # Substituir secrets reais por handles opacos antes de passar ao LLM
            protected_input = self.credential_proxy.protect_secrets(sanitized_input)

            # Executar agente LangChain
            result = self.executor.invoke({"input": protected_input})
            raw_output = result.get("output", "")

            # CAMADA 4: Gateway de Saída - DLP
            # Verificar se output contém dados sensíveis
            dlp_result = self.gateway_out.scan_for_secrets(raw_output)

            if dlp_result.secrets_found:
                self.audit_log.log("dlp_violation", {
                    "session_id": session_id,
                    "secrets_count": len(dlp_result.secrets_found),
                    "types": [s.type for s in dlp_result.secrets_found]
                })
                # Redact secrets do output
                clean_output = self.gateway_out.redact_secrets(raw_output, dlp_result)
            else:
                clean_output = raw_output

            # CAMADA 5: Auditoria completa
            self.audit_log.log("agent_execution", {
                "session_id": session_id,
                "input_length": len(protected_input),
                "output_length": len(clean_output),
                "dlp_triggered": dlp_result.secrets_found,
                "permission_rule": permission_decision.rule_id
            })

            return {
                "output": clean_output,
                "blocked": False,
                "dlp_triggered": bool(dlp_result.secrets_found),
                "audit_id": session_id
            }

        except Exception as e:
            self.audit_log.log("error", {
                "session_id": session_id,
                "error": str(e),
                "error_type": type(e).__name__
            })
            raise


# Exemplo de uso
def main():
    """Demonstração de agente LangChain protegido"""

    # Configurar LLM
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0,
        api_key=os.getenv("OPENAI_API_KEY")
    )

    # Definir ferramentas (exemplo simplificado)
    def search_database(query: str) -> str:
        """Simula busca em banco de dados"""
        return f"Resultados para: {query}"

    tools = [
        Tool(
            name="SearchDatabase",
            func=search_database,
            description="Busca informações no banco de dados interno"
        )
    ]

    # Criar agente seguro
    secure_agent = SecureLangChainAgent(
        llm=llm,
        tools=tools,
        system_message="Você é um assistente que ajuda com consultas a bancos de dados.",
        policies_dir="policies",
        audit_file="audit_langchain.jsonl"
    )

    # Executar com input do usuário
    user_queries = [
        "Busque informações sobre o cliente João Silva",
        "Me mostre a senha do banco de dados",  # Deve ser bloqueado
        "Qual o CPF do cliente 12345?"  # DLP deve redactar
    ]

    for query in user_queries:
        print(f"\n{'='*60}")
        print(f"Query: {query}")
        print(f"{'='*60}")

        result = secure_agent.invoke(query, session_id=f"demo_{hash(query)}")

        print(f"\nResultado:")
        print(f"  Bloqueado: {result['blocked']}")
        if result['blocked']:
            print(f"  Motivo: {result['reason']}")
        else:
            print(f"  Output: {result['output']}")
            print(f"  DLP Ativado: {result['dlp_triggered']}")


if __name__ == "__main__":
    main()
