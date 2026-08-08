"""
Ventura.SEG — Sandbox de Execução
=================================
Isola o agente em ambiente com acesso restrito a filesystem e rede.
Suporta process isolation e Docker hardenizado.

Princípio: Isolamento real, não apenas checagem em software.
"""

from .executor import SandboxExecutor, IsolationLevel, ExecutionResult

__all__ = ["SandboxExecutor", "IsolationLevel", "ExecutionResult"]
