"""
Ventura.SEG — Gerenciamento de Upstreams (Consul Connect)
=========================================================
Define e aplica a lista de serviços upstream do sidecar Envoy.

No Connect, a aplicação fala apenas com 127.0.0.1:<local_bind_port>.
O proxy encaminha via mTLS para o destination_name no mesh.

Fluxo típico:
  1. Carregar upstreams de YAML (consul/upstreams.yaml)
  2. Registrar/atualizar o serviço com Connect.SidecarService.Proxy.Upstreams
  3. Garantir intentions allow ventura-seg → destination
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .consul import ConsulMeshClient
from .intentions import IntentionManager


@dataclass
class Upstream:
    destination_name: str
    local_bind_port: int
    local_bind_address: str = "127.0.0.1"
    description: str = ""
    datacenter: Optional[str] = None

    def to_connect_dict(self) -> dict[str, Any]:
        """Formato esperado pelo Consul Connect sidecar proxy."""
        entry: dict[str, Any] = {
            "DestinationName": self.destination_name,
            "LocalBindPort": self.local_bind_port,
            "LocalBindAddress": self.local_bind_address,
        }
        if self.datacenter:
            entry["Datacenter"] = self.datacenter
        return entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "destination_name": self.destination_name,
            "local_bind_port": self.local_bind_port,
            "local_bind_address": self.local_bind_address,
            "description": self.description,
            "datacenter": self.datacenter,
        }


@dataclass
class UpstreamConfig:
    service_name: str = "ventura-seg"
    service_port: int = 8080
    upstreams: list[Upstream] = field(default_factory=list)


class UpstreamManager:
    """
    Gerencia upstreams do Ventura.SEG no Consul Connect.

    Uso:
        mesh = ConsulMeshClient(audit_logger=audit)
        mgr = UpstreamManager(mesh)

        cfg = mgr.load_yaml("consul/upstreams.yaml")
        mgr.apply(cfg, service_id="ventura-seg-host1", address="10.0.0.10")
        mgr.ensure_intentions(cfg)  # allow ventura-seg → cada destination
    """

    def __init__(self, client: ConsulMeshClient) -> None:
        self.client = client
        self.audit = client.audit
        self.intentions = IntentionManager(client)
        self._config: Optional[UpstreamConfig] = None

    # ------------------------------------------------------------------
    # Load / save
    # ------------------------------------------------------------------

    def load_yaml(self, path: str | Path) -> UpstreamConfig:
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        upstreams = [
            Upstream(
                destination_name=u["destination_name"],
                local_bind_port=int(u["local_bind_port"]),
                local_bind_address=u.get("local_bind_address", "127.0.0.1"),
                description=u.get("description", ""),
                datacenter=u.get("datacenter"),
            )
            for u in data.get("upstreams", [])
        ]

        cfg = UpstreamConfig(
            service_name=data.get("service_name", "ventura-seg"),
            service_port=int(data.get("service_port", 8080)),
            upstreams=upstreams,
        )
        self._config = cfg

        if self.audit:
            self.audit.log_event(
                component="service_mesh",
                action="upstreams_load",
                decision="success",
                reason=f"{len(upstreams)} upstream(s) de {path}",
                metadata={"path": str(path), "destinations": [u.destination_name for u in upstreams]},
            )
        return cfg

    # ------------------------------------------------------------------
    # Apply no Consul (re-register com sidecar upstreams)
    # ------------------------------------------------------------------

    def apply(
        self,
        config: Optional[UpstreamConfig] = None,
        *,
        service_id: Optional[str] = None,
        address: Optional[str] = None,
        tags: Optional[list[str]] = None,
        health_http: Optional[str] = None,
    ) -> str:
        """
        Registra (ou atualiza) o serviço com a lista de upstreams no sidecar.

        Retorna service_id.
        """
        cfg = config or self._config
        if cfg is None:
            raise ValueError("Nenhuma config de upstream carregada. Use load_yaml() ou passe config=.")

        name = cfg.service_name
        port = cfg.service_port
        address = address or self.client._local_ip()
        service_id = service_id or f"{name}-{address.replace('.', '-')}"
        tags = tags or ["security", "ai-gateway", "ventura"]

        connect_upstreams = [u.to_connect_dict() for u in cfg.upstreams]

        payload: dict[str, Any] = {
            "ID": service_id,
            "Name": name,
            "Tags": tags,
            "Address": address,
            "Port": port,
            "Meta": {
                "project": "Ventura.SEG",
                "role": "security-layer",
                "upstreams": ",".join(u.destination_name for u in cfg.upstreams),
            },
            "Check": {
                "HTTP": health_http or f"http://{address}:{port}/health",
                "Interval": "10s",
                "Timeout": "3s",
                "DeregisterCriticalServiceAfter": "5m",
            },
            "Connect": {
                "Native": False,
                "SidecarService": {
                    "Port": port + 1,
                    "Proxy": {
                        "LocalServiceAddress": "127.0.0.1",
                        "LocalServicePort": port,
                        "Upstreams": connect_upstreams,
                    },
                },
            },
        }

        if self.client.datacenter:
            payload["Datacenter"] = self.client.datacenter

        self.client._request("PUT", "/v1/agent/service/register", body=payload)
        self.client._registered_id = service_id

        if self.audit:
            self.audit.log_event(
                component="service_mesh",
                action="upstreams_apply",
                decision="success",
                reason=f"Serviço {service_id} atualizado com {len(cfg.upstreams)} upstream(s)",
                metadata={
                    "service_id": service_id,
                    "upstreams": [u.to_dict() for u in cfg.upstreams],
                },
            )

        return service_id

    # ------------------------------------------------------------------
    # Intentions para cada upstream
    # ------------------------------------------------------------------

    def ensure_intentions(self, config: Optional[UpstreamConfig] = None) -> None:
        """
        Garante intention allow: ventura-seg → cada destination_name.

        Necessário para o sidecar conseguir conectar no mesh.
        """
        cfg = config or self._config
        if cfg is None:
            raise ValueError("Nenhuma config de upstream carregada.")

        for upstream in cfg.upstreams:
            self.intentions.allow(
                source=cfg.service_name,
                destination=upstream.destination_name,
                description=upstream.description
                or f"Ventura.SEG upstream → {upstream.destination_name}",
            )

    # ------------------------------------------------------------------
    # Consulta / utilitários
    # ------------------------------------------------------------------

    def list_upstreams(self, config: Optional[UpstreamConfig] = None) -> list[dict[str, Any]]:
        cfg = config or self._config
        if cfg is None:
            return []
        return [u.to_dict() for u in cfg.upstreams]

    def get_local_endpoint(self, destination_name: str, config: Optional[UpstreamConfig] = None) -> Optional[str]:
        """
        Retorna URL local do upstream (ex: http://127.0.0.1:8200).

        Use este endereço nos clientes (Vault, APIs) em vez do host real.
        """
        cfg = config or self._config
        if cfg is None:
            return None
        for u in cfg.upstreams:
            if u.destination_name == destination_name:
                return f"http://{u.local_bind_address}:{u.local_bind_port}"
        return None

    def add(
        self,
        destination_name: str,
        local_bind_port: int,
        description: str = "",
        local_bind_address: str = "127.0.0.1",
    ) -> None:
        """Adiciona upstream em memória (chame apply() depois)."""
        if self._config is None:
            self._config = UpstreamConfig()
        # evita duplicata de destination
        self._config.upstreams = [
            u for u in self._config.upstreams if u.destination_name != destination_name
        ]
        self._config.upstreams.append(
            Upstream(
                destination_name=destination_name,
                local_bind_port=local_bind_port,
                local_bind_address=local_bind_address,
                description=description,
            )
        )

    def remove(self, destination_name: str) -> bool:
        """Remove upstream em memória (chame apply() depois)."""
        if self._config is None:
            return False
        before = len(self._config.upstreams)
        self._config.upstreams = [
            u for u in self._config.upstreams if u.destination_name != destination_name
        ]
        return len(self._config.upstreams) < before
