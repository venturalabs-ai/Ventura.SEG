"""
Ventura.SEG — Gateway de Saída (DLP)
====================================
Valida toda chamada de rede, escrita em disco e execução de comando
antes de liberar. Bloqueia padrões de exfiltração.

Princípio: Nenhuma ação sai sem checagem.
"""

from .dlp import DLPGateway, DLPDecision, DLPAction

__all__ = ["DLPGateway", "DLPDecision", "DLPAction"]
