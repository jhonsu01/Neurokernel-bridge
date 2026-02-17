# Kernel Security Monitor - eBPF + AI


## Objetivo

Sistema de monitoreo de seguridad del kernel Linux que utiliza eBPF para capturar eventos en 5 dimensiones y un motor de decisiones de 3 niveles (reglas deterministicas, cache vectorial, IA) para clasificar amenazas en tiempo real.

## Entradas

- Eventos del kernel via eBPF (execve, openat2, tcp_connect, etc.)
- Configuracion en `.env` (API keys, thresholds, paths)
- Memoria previa en ChromaDB y claude-mem

## Salidas

- **Acciones:** SIGTERM a procesos maliciosos, renice a procesos limitados
- **Logs:** JSON estructurado en `logs/orchestrator.jsonl`
- **Memoria:** Decisiones cacheadas en ChromaDB, sesiones comprimidas en claude-mem


## Integracion Telegram

Bot de Telegram para alertas de seguridad y administracion remota.

### Comandos disponibles

| Comando | Funcion |
|---------|---------|
| /status | Estado del monitor (uptime, contadores, modo) |
| /help | Lista de comandos |
| /home | Listar directorio home del usuario |
| /ls \<ruta\> | Listar directorio |
| /cat \<ruta\> | Ver archivo (50 lineas max) |
| /mkdir \<ruta\> | Crear directorio |
| /touch \<ruta\> | Crear archivo vacio |
| /cmd \<comando\> | Ejecutar comando (30s timeout) |

### Comandos deshabilitados (seguridad)

| Comando | Razon |
|---------|-------|
| /shutdown | Podria apagar el sistema remotamente |
| /reboot | Podria reiniciar el sistema remotamente |
| /logout | loginctl terminate-user congela el escritorio |

### Configuracion de alertas

- **Cooldown**: 30 segundos entre alertas (evita spam)
- **Decisiones notificadas**: MALICIOUS, LIMIT
- **Confianza minima**: 0.5
- **Autorizacion**: Solo el chat_id configurado en .env

### Arquitectura asyncio

El bot de Telegram corre en el mismo event loop que el collector de eventos.
Es CRITICO que `_flush()` ceda control con `await asyncio.sleep(0)` despues de
cada evento para que el polling de Telegram pueda ejecutarse. Sin esto,
el event loop se satura y los comandos no responden.

## Herramientas Requeridas

- Script: `execution/sensor.c` (eBPF, 339 lineas, 11 probes)
- Paquete: `execution/orchestrator/` (Python, 23 modulos)
- APIs: Anthropic Claude API (claude-sonnet-4-20250514), Telegram Bot API
- DB: ChromaDB (local), claude-mem HTTP (localhost:37777)
- Telegram: python-telegram-bot v22.6 (long polling)

## Configuracion de Ejecucion

- Temperatura fases DET: 0.0 (reglas puras, sin LLM)
- Temperatura fase STO: 0.1 (precision maxima para seguridad)
- Rate limit Tier 3: 20 llamadas/minuto
- Confidence minima para bloqueo: 0.8
- Batch window: 1.0s | Max batch: 50 eventos
- File throttle en kernel: 100ms por PID

## Restricciones y Casos Borde

- Requiere root para ejecutar (kprobes necesitan privilegios)
- SIGTERM (no SIGKILL) para permitir cleanup
- Confidence < 0.8 no bloquea, solo registra
- Rate limit excedido: fallback conservador (SAFE, confidence 0.3)
- API key ausente: solo Tier 1 y Tier 2 funcionan
- Self-filter: el orquestador nunca se monitorea a si mismo
- Procesos whitelisted: systemd, sshd, cron, snapd, networkd, journald, udevd, dbus-daemon, polkitd
- **Solo UNA instancia del orquestador** — multiples procesos causan errores Conflict en Telegram API
- **dry_run=True por defecto** — iniciar siempre en modo observacion, activar con LIAK_DRY_RUN=false
- **Clasificacion de archivos 3 niveles**: critical (shadow,kcore) → MALICIOUS; sensitive (sudoers,.ssh) → UNKNOWN/escalar; safe_system (passwd,group) → siempre SAFE
- **/etc/passwd es world-readable (644)** — NUNCA marcar como malicioso; todos los procesos lo leen para getpwuid()
- **protected_procs** previene matar terminales/desktop/shells sin importar la deteccion
- **NUNCA escalar mmap_exec/mprotect_exec a Tier 2/3** — llamadas sincronas a ChromaDB/API bloquean el event loop de asyncio y matan el polling de Telegram. Resolver TODO en Tier 1 con JIT whitelist
- **Telegram alert cooldown = 30s** — maximo 2 alertas/minuto para evitar spam
- **Comandos Telegram peligrosos deshabilitados**: /shutdown, /reboot, /logout — loginctl terminate-user mata toda la sesion de escritorio causando congelamiento
- **asyncio event loop starvation** — collector._flush() procesando eventos sincronicamente bloquea el event loop. Fix: `await asyncio.sleep(0)` despues de cada evento para ceder control al polling de Telegram

## Historial de Aprendizajes

| Fecha | Problema | Solucion | Sesion |
| ----- | -------- | -------- | ------ |
| 2026-02-05 | os.system vulnerable a inyeccion | Reemplazado con subprocess.run | Inicial |
| 2026-02-05 | API call por cada evento no escala | Motor 3 niveles con reglas + cache | Inicial |
| 2026-02-05 | SIGKILL mata sin cleanup | Cambiado a SIGTERM | Inicial |
| 2026-02-05 | Bare except oculta bugs | Excepciones tipadas con logging | Inicial |
| 2026-02-05 | time.time() como ID colisiona | SHA256 hash de signature+timestamp | Inicial |
| 2026-02-05 | /etc/passwd flagged como MALICIOUS mataba konsole | Clasificacion 3 niveles: critical/sensitive/safe_system | Sesion 2 |
| 2026-02-05 | mmap_exec/mprotect_exec spam de alertas en Telegram | JIT whitelist (python3, java, node, chrome, etc.) resuelve en Tier 1 | Sesion 2 |
| 2026-02-05 | /logout congelo el equipo (loginctl terminate-user) | Comandos /shutdown, /reboot, /logout deshabilitados | Sesion 2 |
| 2026-02-05 | Telegram no respondia comandos (event loop saturado) | await asyncio.sleep(0) en collector._flush() cede control al polling | Sesion 2 |
| 2026-02-05 | Multiples instancias causan Conflict en Telegram API | Documentar: siempre matar procesos viejos antes de reiniciar | Sesion 2 |
| 2026-02-05 | Alert cooldown de 1s generaba spam en Telegram | Cooldown aumentado a 30s, max 2 alertas/minuto | Sesion 2 |
