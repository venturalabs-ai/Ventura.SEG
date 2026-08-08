"""
Ventura.SEG — Intentions de Rede (Consul Connect)
=================================================
Aplica e lista service intentions via API de config do Consul.

Intentions definem quem pode abrir conexão mTLS com quem no mesh.
Modelo: default-deny + allow explícito.

API: PUT /v1/config  |  GET /v1/config/service-intentions
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from .consul import ConsulMeshClient


class IntentionManager:
    """
    Gerencia service intentions no Consul.

    Uso:
        mesh = ConsulMeshClient(audit_logger=audit)
        intents = IntentionManager(mesh)

        intents.apply_default_deny_allow(
            destination="ventura-seg",
            allow_from=["ai-agent", "ai-orchestrator", "admin-api"],
        )

        intents.apply_json_file("consul/intentions/ventura-seg.json")
    """

    def __init__(self, client: ConsulMeshClient) -> None:
        self.client = client
        self.audit = client.audit

    def apply(self, entry: dict[str, Any]) -> None:
        """
        Escreve uma config entry de service-intentions.

        entry mínimo:
          {
            "Kind": "service-intentions",
            "Name": "ventura-seg",
            "Sources": [{"Name": "ai-agent", "Action": "allow"}, ...]
          }
        """
        if entry.get("Kind") != "service-intentions":
            raise ValueError("Kind deve ser 'service-intentions'")
        if not entry.get("Name"):
            raise ValueError("Name (serviço de destino) é obrigatório")
        if not entry.get("Sources"):
            raise ValueError("Sources não pode ser vazio")

        self.client._request("PUT", "/v1/config", body=entry)

        if self.audit:
            sources = entry.get("Sources", [])
            self.audit.log_event(
                component="service_mesh",
                action="intention_apply",
                decision="success",
                reason=f"Intention aplicada para destino '{entry['Name']}'",
                metadata={
                    "destination": entry["Name"],
                    "sources": [
                        {"name": s.get("Name"), "action": s.get("Action")}
                        for s in sources
                    ],
                },
            )

    def apply_json_file(self, path: str | Path) -> None:
        """Carrega e aplica intention a partir de arquivo JSON."""
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            entry = json.load(f)
        self.apply(entry)

    def apply_default_deny_allow(
        self,
        destination: str,
        allow_from: list[str],
        description_prefix: str = "",
    ) -> None:
        """
        Modelo padrão Ventura.SEG:
          - allow explícito para cada fonte em allow_from
          - deny para *
        """
        sources: list[dict[str, str]] = []
        for name in allow_from:
            sources.append({
                "Name": name,
                "Action": "allow",
                "Description": description_prefix or f"Allow {name} → {destination}",
            })
        sources.append({
            "Name": "*",
            "Action": "deny",
            "Description": "Default deny",
        })

        self.apply({
            "Kind": "service-intentions",
            "Name": destination,
            "Sources": sources,
        })

    def allow(
        self,
        source: str,
        destination: str,
        description: str = "",
    ) -> None:
        """
        Garante allow de source → destination.

        Lê a intention atual (se existir), faz merge e reaplica.
        """
        current = self.get(destination) or {
            "Kind": "service-intentions",
            "Name": destination,
            "Sources": [],
        }
        sources = list(current.get("Sources") or [])

        # Remove entradas prévias do mesmo source (exceto *)
        sources = [s for s in sources if s.get("Name") != source]
        sources.insert(0, {
            "Name": source,
            "Action": "allow",
            "Description": description or f"Allow {source} → {destination}",
        })

        # Garante default deny no final
        sources = [s for s in sources if s.get("Name") != "*"]
        sources.append({"Name": "*", "Action": "deny", "Description": "Default deny"})

        current["Sources"] = sources
        current["Kind"] = "service-intentions"
        current["Name"] = destination
        self.apply(current)

    def deny(self, source: str, destination: str, description: str = "") -> None:
        """Nega explicitamente source → destination."""
        current = self.get(destination) or {
            "Kind": "service-intentions",
            "Name": destination,
            "Sources": [{"Name": "*", "Action": "deny"}],
        }
        sources = [s for s in (current.get("Sources") or []) if s.get("Name") != source]
        sources.insert(0, {
            "Name": source,
            "Action": "deny",
            "Description": description or f"Deny {source} → {destination}",
        })
        current["Sources"] = sources
        self.apply(current)

    def get(self, destination: str) -> Optional[dict[str, Any]]:
        """Lê a intention do serviço de destino (None se não existir)."""
        try:
            return self.client._request(
                "GET",
                f"/v1/config/service-intentions/{destination}",
            )
        except RuntimeError as exc:
            if "404" in str(exc):
                return None
            raise

    def list_all(self) -> list[dict[str, Any]]:
        """Lista todas as service-intentions."""
        data = self.client._request("GET", "/v1/config/service-intentions") or []
        if isinstance(data, dict):
            return [data]
        return list(data)
