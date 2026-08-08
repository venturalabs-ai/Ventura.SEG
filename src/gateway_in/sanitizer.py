"""
Ventura.SEG — Gateway de Entrada (Sanitizador)
==============================================
Intercepta e sanitiza todo conteúdo externo antes de entrar no contexto do agente.

Proteções:
- Remoção / neutralização de possíveis injeções de prompt
- Truncamento de conteúdo excessivamente longo
- Detecção de padrões suspeitos (instruções embutidas)
- Sumarização opcional de conteúdo grande

Princípio: Nunca confiar em conteúdo externo por padrão.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore


class SanitizationAction(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"   # conteúdo foi modificado
    BLOCK = "block"         # conteúdo rejeitado


@dataclass(frozen=True)
class SanitizationResult:
    action: SanitizationAction
    original_length: int
    sanitized_content: str
    warnings: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == SanitizationAction.BLOCK

    @property
    def was_modified(self) -> bool:
        return self.action == SanitizationAction.SANITIZE


# Padrões comuns de injeção de prompt indireta
INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I), "instrução de ignore previous"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)", re.I), "instrução de disregard"),
    (re.compile(r"you\s+are\s+now\s+.+?(DAN|jailbreak|unrestricted)", re.I), "tentativa de jailbreak"),
    (re.compile(r"system\s*:\s*you\s+are", re.I), "injeção de system prompt"),
    (re.compile(r"<\|?(system|assistant|user)\|?>", re.I), "tokens especiais de modelo"),
    (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I), "marcadores de prompt Llama"),
]


class ContentSanitizer:
    """
    Sanitizador de conteúdo de entrada.

    Uso:
        sanitizer = ContentSanitizer(audit_logger=audit, max_length=50_000)
        result = sanitizer.sanitize(raw_html_or_text)
        if result.blocked:
            ...
        safe_text = result.sanitized_content
    """

    def __init__(
        self,
        max_length: int = 100_000,
        block_on_injection: bool = False,  # se True, bloqueia; se False, neutraliza
        audit_logger: Any = None,
    ) -> None:
        self.max_length = max_length
        self.block_on_injection = block_on_injection
        self.audit = audit_logger

    def sanitize(self, content: str, source: str = "external") -> SanitizationResult:
        """
        Sanitiza conteúdo externo.

        Retorna SanitizationResult com o conteúdo limpo (ou bloqueado).
        """
        if not content:
            return SanitizationResult(
                action=SanitizationAction.ALLOW,
                original_length=0,
                sanitized_content="",
                reason="Conteúdo vazio",
            )

        original_length = len(content)
        warnings: list[str] = []
        text = content

        # 1. Truncamento de segurança
        if len(text) > self.max_length:
            text = text[: self.max_length]
            warnings.append(f"Conteúdo truncado de {original_length} para {self.max_length} caracteres")

        # 2. Detecção de injeção de prompt
        injection_found = False
        for pattern, label in INJECTION_PATTERNS:
            if pattern.search(text):
                injection_found = True
                warnings.append(f"Possível injeção detectada: {label}")

                if self.block_on_injection:
                    result = SanitizationResult(
                        action=SanitizationAction.BLOCK,
                        original_length=original_length,
                        sanitized_content="",
                        warnings=warnings,
                        reason=f"Conteúdo bloqueado por suspeita de injeção: {label}",
                    )
                    self._audit(source, result)
                    return result

                # Neutraliza o trecho suspeito
                text = pattern.sub("[CONTEUDO_NEUTRALIZADO]", text)

        # 3. Remove caracteres de controle perigosos (exceto \n \t)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        action = SanitizationAction.SANITIZE if (warnings or text != content[:len(text)]) else SanitizationAction.ALLOW

        result = SanitizationResult(
            action=action,
            original_length=original_length,
            sanitized_content=text,
            warnings=warnings,
            reason="; ".join(warnings) if warnings else "Conteúdo aceito",
        )
        self._audit(source, result)
        return result

    def _audit(self, source: str, result: SanitizationResult) -> None:
        if self.audit is None:
            return
        self.audit.log_event(
            component="gateway_in",
            action="sanitize",
            decision=result.action.value,
            reason=result.reason,
            metadata={
                "source": source,
                "original_length": result.original_length,
                "warnings": result.warnings,
            },
        )
