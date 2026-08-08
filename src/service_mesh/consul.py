"""
Ventura.SEG — Integração Consul Service Mesh
=============================================
Registra os componentes de segurança no Consul, expõe health checks
e resolve serviços upstream de forma segura.

No Service Mesh (Consul Connect), o mTLS é tipicamente terminado no
sidecar (Envoy). Este módulo:
  - registra Ventura.SEG como serviço
  - anuncia tags/meta de segurança
  - consulta instâncias healthy
  - prepara meta Connect (sidecar / upstreams)

Requisitos opcionais:
  pip install python-consul2
  # ou usa apenas a API HTTP via urllib (fallback sem dependência extra)

Variáveis de ambiente:
  CONSUL_HTTP_ADDR     default http://127.0.0.1:8500
  CONSUL_HTTP_TOKEN    ACL token (se habilitado)
  CONSUL_SERVICE_NAME  default ventura-seg
  CONSUL_SERVICE_PORT  default 8080
  CONSUL_SERVICE_ID    default ventura-seg-<hostname>
  CONSUL_DATACENTER    opcional
  CONSUL_CONNECT       true|false — anuncia Connect native/sidecar meta
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from audit.logger import AuditLogger
except ImportError:
    AuditLogger = None  # type: ignore


@dataclass
class ServiceInstance:
    id: str
    name: str
    address: str
    port: int
    tags: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    healthy: bool = True


class ConsulMeshClient:
    """
    Cliente leve para Consul (HTTP API).

    Uso:
        mesh = ConsulMeshClient(audit_logger=audit)
        mesh.register_ventura_service(port=8080, tags=["security", "dlp"])
        upstreams = mesh.discover("payment-api", passing_only=True)
    """

    def __init__(
        self,
        addr: Optional[str] = None,
        token: Optional[str] = None,
        datacenter: Optional[str] = None,
        audit_logger: Any = None,
    ) -> None:
        self.addr = (addr or os.getenv("CONSUL_HTTP_ADDR") or "http://127.0.0.1:8500").rstrip("/")
        self.token = token or os.getenv("CONSUL_HTTP_TOKEN")
        self.datacenter = datacenter or os.getenv("CONSUL_DATACENTER")
        self.audit = audit_logger
        self._registered_id: Optional[str] = None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        params: Optional[dict[str, str]] = None,
    ) -> Any:
        query = ""
        if params:
            query = "?" + "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
        url = f"{self.addr}{path}{query}"

        data = None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["X-Consul-Token"] = self.token

        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Consul {method} {path} failed: {exc.code} {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Consul unreachable at {self.addr}: {exc}") from exc

    # ------------------------------------------------------------------
    # Registro do Ventura.SEG
    # ------------------------------------------------------------------

    def register_ventura_service(
        self,
        name: Optional[str] = None,
        service_id: Optional[str] = None,
        port: Optional[int] = None,
        address: Optional[str] = None,
        tags: Optional[list[str]] = None,
        meta: Optional[dict[str, str]] = None,
        health_http: Optional[str] = None,
        health_interval: str = "10s",
        enable_connect: Optional[bool] = None,
    ) -> str:
        """
        Registra o Ventura.SEG no catálogo Consul.

        Retorna o service_id registrado.
        """
        name = name or os.getenv("CONSUL_SERVICE_NAME", "ventura-seg")
        port = int(port or os.getenv("CONSUL_SERVICE_PORT", "8080"))
        address = address or os.getenv("CONSUL_SERVICE_ADDRESS") or self._local_ip()
        service_id = service_id or os.getenv("CONSUL_SERVICE_ID") or f"{name}-{socket.gethostname()}"

        tags = tags or ["security", "ai-gateway", "ventura"]
        meta = dict(meta or {})
        meta.setdefault("project", "Ventura.SEG")
        meta.setdefault("role", "security-layer")
        meta.setdefault("version", "0.1.0")

        connect_enabled = (
            enable_connect
            if enable_connect is not None
            else os.getenv("CONSUL_CONNECT", "true").lower() in ("1", "true", "yes")
        )

        payload: dict[str, Any] = {
            "ID": service_id,
            "Name": name,
            "Tags": tags,
            "Address": address,
            "Port": port,
            "Meta": meta,
            "EnableTagOverride": False,
        }

        if self.datacenter:
            payload["Datacenter"] = self.datacenter

        # Health check HTTP (o app deve expor /health)
        check_url = health_http or f"http://{address}:{port}/health"
        payload["Check"] = {
            "HTTP": check_url,
            "Interval": health_interval,
            "Timeout": "3s",
            "DeregisterCriticalServiceAfter": "5m",
        }

        # Meta Connect: indica intenção de participar do mesh
        # (sidecar real costuma ser injetado pelo Consul / Kubernetes CNI)
        if connect_enabled:
            payload["Connect"] = {
                "Native": False,  # preferir sidecar Envoy em produção
                "SidecarService": {
                    "Port": port + 1,
                    "Proxy": {
                        "LocalServiceAddress": "127.0.0.1",
                        "LocalServicePort": port,
                        "Upstreams": [],
                    },
                },
            }

        self._request("PUT", "/v1/agent/service/register", body=payload)
        self._registered_id = service_id

        if self.audit:
            self.audit.log_event(
                component="service_mesh",
                action="consul_register",
                decision="success",
                reason=f"Serviço registrado: {service_id}",
                metadata={
                    "name": name,
                    "id": service_id,
                    "port": port,
                    "connect": connect_enabled,
                    "tags": tags,
                },
            )

        return service_id

    def deregister(self, service_id: Optional[str] = None) -> None:
        """Remove o serviço do agent local."""
        sid = service_id or self._registered_id
        if not sid:
            return
        self._request("PUT", f"/v1/agent/service/deregister/{sid}")
        if self.audit:
            self.audit.log_event(
                component="service_mesh",
                action="consul_deregister",
                decision="success",
                reason=f"Serviço removido: {sid}",
            )
        if sid == self._registered_id:
            self._registered_id = None

    # ------------------------------------------------------------------
    # Service discovery
    # ------------------------------------------------------------------

    def discover(
        self,
        service_name: str,
        passing_only: bool = True,
        tag: Optional[str] = None,
    ) -> list[ServiceInstance]:
        """
        Resolve instâncias de um serviço no catálogo.

        passing_only=True → apenas health critical=false (checks passing).
        """
        path = f"/v1/health/service/{service_name}"
        params: dict[str, str] = {}
        if passing_only:
            params["passing"] = "true"
        if tag:
            params["tag"] = tag
        if self.datacenter:
            params["dc"] = self.datacenter

        data = self._request("GET", path, params=params) or []
        instances: list[ServiceInstance] = []

        for entry in data:
            svc = entry.get("Service", {})
            checks = entry.get("Checks", [])
            healthy = all(c.get("Status") == "passing" for c in checks if c.get("ServiceID"))
            instances.append(
                ServiceInstance(
                    id=svc.get("ID", ""),
                    name=svc.get("Service", service_name),
                    address=svc.get("Address") or entry.get("Node", {}).get("Address", ""),
                    port=int(svc.get("Port", 0)),
                    tags=list(svc.get("Tags") or []),
                    meta=dict(svc.get("Meta") or {}),
                    healthy=healthy,
                )
            )

        if self.audit:
            self.audit.log_event(
                component="service_mesh",
                action="consul_discover",
                decision="success",
                reason=f"{len(instances)} instância(s) de '{service_name}'",
                metadata={"service": service_name, "passing_only": passing_only},
            )

        return instances

    def set_upstream(
        self,
        service_id: Optional[str],
        destination_name: str,
        local_bind_port: int,
    ) -> None:
        """
        Atualiza meta de upstream Connect no serviço registrado.

        Em mesh completo, preferir declaração via sidecar proxy config /
        Kubernetes ServiceDefaults. Este helper documenta a intenção no agent.
        """
        # Consul não tem um endpoint simples para "só upstream"; tipicamente
        # re-registra-se o serviço com Connect.SidecarService.Proxy.Upstreams.
        # Aqui apenas auditamos a intenção para operação/documentação.
        if self.audit:
            self.audit.log_event(
                component="service_mesh",
                action="consul_upstream_intent",
                decision="info",
                reason=f"Upstream {destination_name} → 127.0.0.1:{local_bind_port}",
                metadata={
                    "service_id": service_id or self._registered_id,
                    "destination": destination_name,
                    "local_bind_port": local_bind_port,
                },
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def agent_self(self) -> dict[str, Any]:
        """Informações do agent Consul local."""
        return self._request("GET", "/v1/agent/self") or {}
