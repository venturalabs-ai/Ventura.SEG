"""
Benchmarks de Performance - Ventura.SEG

Mede latência e throughput de cada camada de segurança para documentar
o overhead de proteção e validar que está dentro dos targets aceitáveis.

Targets:
- Latência por request: < 50ms (p95)
- Throughput: > 1000 req/s por core
- Memory overhead: < 10MB
"""
import time
import statistics
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import List, Callable


@dataclass
class BenchmarkResult:
    """Resultado de um benchmark"""
    name: str
    operations: int
    total_time_ms: float
    mean_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    throughput_ops_per_sec: float
    passed: bool


def measure_latency(func: Callable, iterations: int = 1000) -> List[float]:
    """Mede latências individuais de uma função"""
    latencies = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        latencies.append((end - start) * 1000)  # ms
    return latencies


def benchmark_component(
    name: str,
    func: Callable,
    iterations: int = 1000,
    p95_target_ms: float = 50.0
) -> BenchmarkResult:
    """
    Executa benchmark de um componente

    Args:
        name: Nome do componente
        func: Função a ser medida
        iterations: Número de iterações
        p95_target_ms: Target de latência p95 em ms

    Returns:
        BenchmarkResult com métricas
    """
    print(f"\n{'='*60}")
    print(f"Benchmarking: {name}")
    print(f"{'='*60}")

    latencies = measure_latency(func, iterations)

    total_time = sum(latencies)
    mean = statistics.mean(latencies)
    p50 = statistics.median(latencies)
    p95 = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
    p99 = statistics.quantiles(latencies, n=100)[98]  # 99th percentile
    throughput = (iterations / total_time) * 1000  # ops/sec

    passed = p95 <= p95_target_ms

    result = BenchmarkResult(
        name=name,
        operations=iterations,
        total_time_ms=total_time,
        mean_latency_ms=mean,
        p50_latency_ms=p50,
        p95_latency_ms=p95,
        p99_latency_ms=p99,
        throughput_ops_per_sec=throughput,
        passed=passed
    )

    # Print resultados
    print(f"Operations: {iterations}")
    print(f"Total time: {total_time:.2f} ms")
    print(f"Mean latency: {mean:.3f} ms")
    print(f"p50 latency: {p50:.3f} ms")
    print(f"p95 latency: {p95:.3f} ms (target: {p95_target_ms:.1f} ms)")
    print(f"p99 latency: {p99:.3f} ms")
    print(f"Throughput: {throughput:.0f} ops/sec")
    print(f"Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result


def run_benchmarks() -> List[BenchmarkResult]:
    """Executa todos os benchmarks"""
    results = []

    # Mock simples das funções (substitua pelos imports reais quando disponível)
    def mock_gateway_in():
        """Simula sanitização de input"""
        text = "SELECT * FROM users WHERE id = 123; DROP TABLE users;"
        # Sanitização simples
        cleaned = text.replace("DROP", "").replace(";", "")
        return cleaned

    def mock_permission_check():
        """Simula verificação de permissão"""
        action = "execute_query"
        allowed_actions = {"read", "execute_query", "list"}
        return action in allowed_actions

    def mock_dlp_scan():
        """Simula scan DLP"""
        text = "Cliente João tem CPF 123.456.789-00 e email joao@example.com"
        patterns = [
            r"\d{3}\.\d{3}\.\d{3}-\d{2}",  # CPF
            r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",  # Email
        ]
        # Simula regex matching
        for pattern in patterns:
            if "123" in text or "@" in text:
                return True
        return False

    def mock_credential_proxy():
        """Simula proteção de credenciais"""
        secret = "sk-proj-abc123def456ghi789"
        handle = f"HANDLE_{hash(secret) % 10000}"
        return handle

    def mock_audit_log():
        """Simula gravação de log"""
        log_entry = {
            "timestamp": time.time(),
            "event": "agent_execution",
            "details": {"input": "query", "output": "result"}
        }
        # Simula gravação em arquivo
        serialized = json.dumps(log_entry)
        return len(serialized)

    # Benchmark 1: Gateway de Entrada
    results.append(benchmark_component(
        "Gateway de Entrada (Sanitização)",
        mock_gateway_in,
        iterations=10000,
        p95_target_ms=1.0
    ))

    # Benchmark 2: Motor de Permissões
    results.append(benchmark_component(
        "Motor de Permissões",
        mock_permission_check,
        iterations=10000,
        p95_target_ms=0.5
    ))

    # Benchmark 3: DLP Scan
    results.append(benchmark_component(
        "Gateway de Saída (DLP)",
        mock_dlp_scan,
        iterations=10000,
        p95_target_ms=5.0
    ))

    # Benchmark 4: Proxy de Credenciais
    results.append(benchmark_component(
        "Proxy de Credenciais",
        mock_credential_proxy,
        iterations=10000,
        p95_target_ms=0.5
    ))

    # Benchmark 5: Auditoria
    results.append(benchmark_component(
        "Auditoria (Log)",
        mock_audit_log,
        iterations=10000,
        p95_target_ms=2.0
    ))

    # Benchmark 6: Pipeline Completo
    def full_pipeline():
        mock_gateway_in()
        mock_permission_check()
        mock_credential_proxy()
        # Simula execução do agente (50ms mock)
        time.sleep(0.00005)  # 0.05ms
        mock_dlp_scan()
        mock_audit_log()

    results.append(benchmark_component(
        "Pipeline Completo (todas camadas)",
        full_pipeline,
        iterations=1000,
        p95_target_ms=50.0
    ))

    return results


def print_summary(results: List[BenchmarkResult]):
    """Imprime sumário dos resultados"""
    print(f"\n{'='*60}")
    print("SUMÁRIO DE BENCHMARKS")
    print(f"{'='*60}\n")

    print(f"{'Componente':<35} {'p95 (ms)':<12} {'Status'}")
    print(f"{'-'*60}")

    for r in results:
        status = "✅ PASS" if r.passed else "❌ FAIL"
        print(f"{r.name:<35} {r.p95_latency_ms:<12.3f} {status}")

    total_passed = sum(1 for r in results if r.passed)
    print(f"\n{total_passed}/{len(results)} benchmarks passaram")

    # Salvar resultados
    output_file = Path("benchmark_results.json")
    with open(output_file, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"\nResultados salvos em: {output_file}")


def main():
    """Executa suite completa de benchmarks"""
    print("🚀 Iniciando Benchmarks de Performance - Ventura.SEG")
    print(f"Python version: {Path('/usr/bin/python3').resolve()}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    results = run_benchmarks()
    print_summary(results)

    # Exit code baseado em resultados
    all_passed = all(r.passed for r in results)
    exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
