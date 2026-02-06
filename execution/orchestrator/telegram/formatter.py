"""Format DecisionResult and system info into Telegram messages."""
from __future__ import annotations

from ..models import Decision, DecisionResult


_DECISION_EMOJI = {
    Decision.MALICIOUS: "\u2757",   # ❗
    Decision.LIMIT: "\u26a0\ufe0f", # ⚠️
    Decision.SAFE: "\u2705",        # ✅
    Decision.UNKNOWN: "\u2753",     # ❓
}

_DECISION_LABEL = {
    Decision.MALICIOUS: "MALICIOUS",
    Decision.LIMIT: "LIMIT",
    Decision.SAFE: "SAFE",
    Decision.UNKNOWN: "UNKNOWN",
}


def format_alert(result: DecisionResult) -> str:
    emoji = _DECISION_EMOJI.get(result.decision, "")
    label = _DECISION_LABEL.get(result.decision, "?")
    action = result.action_taken or "none"

    lines = [
        f"{emoji} <b>{label}</b> — Confianza: {result.confidence:.2f}",
        f"Proceso: <code>{result.event.comm}</code> (PID: {result.event.pid}, UID: {result.event.uid})",
        f"Dimension: {result.event.dimension.name}",
        f"Razon: {result.reasoning}",
        f"Accion: {action}",
        f"Tier: {result.tier.name}",
    ]
    return "\n".join(lines)


def format_status(stats: dict, uptime_seconds: float, dry_run: bool) -> str:
    mode = "DRY-RUN" if dry_run else "ACTIVE"
    hours = int(uptime_seconds // 3600)
    minutes = int((uptime_seconds % 3600) // 60)

    lines = [
        f"\U0001f4ca <b>LinuxIAKernel Status</b>",
        f"Modo: <b>{mode}</b>",
        f"Uptime: {hours}h {minutes}m",
        "",
        f"Eventos totales: {stats.get('total_events', 0)}",
        f"  Tier 1 (rules): {stats.get('tier1_count', 0)}",
        f"  Tier 2 (cache): {stats.get('tier2_count', 0)}",
        f"  Tier 3 (LLM):   {stats.get('tier3_count', 0)}",
        "",
        f"SAFE:      {stats.get('safe_count', 0)}",
        f"LIMIT:     {stats.get('limited_count', 0)}",
        f"MALICIOUS: {stats.get('blocked_count', 0)}",
    ]
    return "\n".join(lines)


def format_help() -> str:
    lines = [
        "\U0001f4cb <b>Comandos disponibles</b>",
        "",
        "/status — Estado del monitor",
        "/help — Esta ayuda",
        "",
        "<b>Archivos:</b>",
        "/home — Listar directorio home",
        "/ls &lt;ruta&gt; — Listar directorio",
        "/cat &lt;ruta&gt; — Ver archivo (50 lineas max)",
        "/mkdir &lt;ruta&gt; — Crear directorio",
        "/touch &lt;ruta&gt; — Crear archivo vacio",
        "",
        "<b>Avanzado:</b>",
        "/cmd &lt;comando&gt; — Ejecutar comando (30s timeout)",
    ]
    return "\n".join(lines)
