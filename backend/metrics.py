"""Minimal in-process, stdlib-only metrics registry exposed at GET /metrics in
Prometheus text exposition format (https://prometheus.io/docs/instrumenting/exposition_formats/).

Deliberately NOT the `prometheus_client` package, and deliberately not backed by
Prometheus/Grafana/anything actually running -- this is the smallest thing that is
still genuinely scrapeable by a real Prometheus if one is ever pointed at this
service, without adding a dependency or a second piece of infrastructure for a
single-process local/demo deployment. See README "Observability" for the tradeoff.

Two metric shapes only, matching what backend/logging_config.py's structured events
already measure -- no new taxonomy invented:

  - Counter: monotonically increasing count, e.g. how many times something happened.
  - Duration summary: a count + total (so `total/count` gives the mean) per labelset,
    the simplest Prometheus-compatible way to expose "how long did X take" without
    implementing histogram bucket configuration.

Thread-safe (a single lock) -- FastAPI runs sync `def` routes in a thread pool, so
concurrent requests can update these simultaneously even under uvicorn's default
single worker process.
"""

from __future__ import annotations

import threading

_LabelKey = tuple[tuple[str, str], ...]

_lock = threading.Lock()
_counters: dict[str, dict[_LabelKey, float]] = {}
_duration_count: dict[str, dict[_LabelKey, int]] = {}
_duration_sum_ms: dict[str, dict[_LabelKey, float]] = {}


def _label_key(labels: dict[str, str]) -> _LabelKey:
    return tuple(sorted(labels.items()))


def increment(name: str, *, value: float = 1.0, **labels: str) -> None:
    """Adds `value` to the named counter for this exact labelset (created at 0 if new)."""
    key = _label_key(labels)
    with _lock:
        bucket = _counters.setdefault(name, {})
        bucket[key] = bucket.get(key, 0.0) + value


def observe_duration_ms(name: str, duration_ms: float, **labels: str) -> None:
    """Records one observed duration for the named metric/labelset."""
    key = _label_key(labels)
    with _lock:
        counts = _duration_count.setdefault(name, {})
        sums = _duration_sum_ms.setdefault(name, {})
        counts[key] = counts.get(key, 0) + 1
        sums[key] = sums.get(key, 0.0) + duration_ms


def _format_labels(key: _LabelKey) -> str:
    if not key:
        return ""
    pairs = ",".join(f'{k}="{v}"' for k, v in key)
    return "{" + pairs + "}"


def render_prometheus_text() -> str:
    """Renders the current state of every metric in Prometheus text exposition
    format. Called fresh on every GET /metrics -- there is no periodic flush/export;
    the registry above IS the current state."""
    lines: list[str] = []

    with _lock:
        counters_snapshot = {name: dict(buckets) for name, buckets in _counters.items()}
        counts_snapshot = {name: dict(buckets) for name, buckets in _duration_count.items()}
        sums_snapshot = {name: dict(buckets) for name, buckets in _duration_sum_ms.items()}

    for name in sorted(counters_snapshot):
        lines.append(f"# TYPE {name} counter")
        for key, value in sorted(counters_snapshot[name].items()):
            lines.append(f"{name}{_format_labels(key)} {value}")

    for name in sorted(counts_snapshot):
        metric_name = f"{name}_duration_ms"
        lines.append(f"# TYPE {metric_name} summary")
        for key in sorted(counts_snapshot[name]):
            count = counts_snapshot[name][key]
            total = sums_snapshot.get(name, {}).get(key, 0.0)
            lines.append(f"{metric_name}_count{_format_labels(key)} {count}")
            lines.append(f"{metric_name}_sum{_format_labels(key)} {total}")

    return "\n".join(lines) + "\n" if lines else ""


def reset() -> None:
    """Test-only: clears all recorded state."""
    with _lock:
        _counters.clear()
        _duration_count.clear()
        _duration_sum_ms.clear()
