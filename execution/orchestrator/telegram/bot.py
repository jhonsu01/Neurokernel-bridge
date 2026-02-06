"""Telegram bot for security alerts and remote administration."""
from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

import structlog
from telegram import Update, Bot
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)
from telegram.constants import ParseMode

from ..config import TelegramConfig
from ..models import DecisionResult
from . import formatter

logger = structlog.get_logger("telegram_bot")

# Max message length for Telegram API
_MAX_MSG = 4000
# Rate limit: min seconds between alert messages (30s prevents flooding)
_ALERT_COOLDOWN = 30.0


class TelegramBot:
    """Telegram bot: sends security alerts, receives admin commands."""

    def __init__(self, config: TelegramConfig, stats_fn=None, dry_run: bool = True):
        self.config = config
        self.token = config.telegram_bot_token
        self.chat_id = config.telegram_chat_id
        self._stats_fn = stats_fn
        self._dry_run = dry_run
        self._start_time = time.time()
        self._last_alert_time = 0.0
        self._app: Optional[Application] = None
        self._bot: Optional[Bot] = None
        self._running = False

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def _authorized(self, update: Update) -> bool:
        chat_id = str(update.effective_chat.id)
        if chat_id != self.chat_id:
            logger.warning("telegram_unauthorized", chat_id=chat_id)
            return False
        return True

    async def start(self) -> None:
        if not self.enabled:
            logger.info("telegram_disabled", reason="no token or chat_id")
            return

        self._app = Application.builder().token(self.token).build()
        self._bot = self._app.bot

        self._app.add_handler(CommandHandler("status", self._cmd_status))
        self._app.add_handler(CommandHandler("help", self._cmd_help))
        self._app.add_handler(CommandHandler("start", self._cmd_help))
        self._app.add_handler(CommandHandler("shutdown", self._cmd_shutdown))
        self._app.add_handler(CommandHandler("reboot", self._cmd_reboot))
        self._app.add_handler(CommandHandler("logout", self._cmd_logout))
        self._app.add_handler(CommandHandler("home", self._cmd_home))
        self._app.add_handler(CommandHandler("ls", self._cmd_ls))
        self._app.add_handler(CommandHandler("cat", self._cmd_cat))
        self._app.add_handler(CommandHandler("mkdir", self._cmd_mkdir))
        self._app.add_handler(CommandHandler("touch", self._cmd_touch))
        self._app.add_handler(CommandHandler("cmd", self._cmd_exec))

        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)
        self._running = True

        logger.info("telegram_bot_started", chat_id=self.chat_id)
        await self._send(
            "\u2705 <b>LinuxIAKernel</b> monitor conectado.\n"
            "Escribe /help para ver comandos."
        )

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        try:
            await self._send("\U0001f534 Monitor detenido.")
            if self._app:
                await self._app.updater.stop()
                await self._app.stop()
                await self._app.shutdown()
        except Exception as e:
            logger.error("telegram_stop_error", error=str(e))
        logger.info("telegram_bot_stopped")

    async def notify_alert(self, result: DecisionResult) -> None:
        if not self._running:
            return
        decision_name = result.decision.name
        if decision_name not in self.config.notify_decisions:
            return
        if result.confidence < self.config.notify_min_confidence:
            return

        now = time.time()
        if (now - self._last_alert_time) < _ALERT_COOLDOWN:
            return
        self._last_alert_time = now

        msg = formatter.format_alert(result)
        await self._send(msg)

    async def _send(self, text: str) -> None:
        if not self._bot or not self.chat_id:
            return
        try:
            await self._bot.send_message(
                chat_id=self.chat_id,
                text=text[:_MAX_MSG],
                parse_mode=ParseMode.HTML,
            )
        except Exception as e:
            logger.error("telegram_send_error", error=str(e))

    # ── Command handlers ──────────────────────────────────

    async def _cmd_status(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        stats = self._stats_fn() if self._stats_fn else {}
        uptime = time.time() - self._start_time
        msg = formatter.format_status(stats, uptime, self._dry_run)
        await update.message.reply_text(msg, parse_mode=ParseMode.HTML)

    async def _cmd_help(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        await update.message.reply_text(formatter.format_help(), parse_mode=ParseMode.HTML)

    async def _cmd_shutdown(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        logger.warning("telegram_shutdown_blocked", user=update.effective_user.id)
        await update.message.reply_text(
            "\U0001f6ab /shutdown deshabilitado por seguridad.\n"
            "Usa la terminal local.", parse_mode=ParseMode.HTML)

    async def _cmd_reboot(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        logger.warning("telegram_reboot_blocked", user=update.effective_user.id)
        await update.message.reply_text(
            "\U0001f6ab /reboot deshabilitado por seguridad.\n"
            "Usa la terminal local.", parse_mode=ParseMode.HTML)

    async def _cmd_logout(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        logger.warning("telegram_logout_blocked", user=update.effective_user.id)
        await update.message.reply_text(
            "\U0001f6ab /logout deshabilitado por seguridad.\n"
            "loginctl terminate-user congela el escritorio.", parse_mode=ParseMode.HTML)

    async def _cmd_home(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        user = os.environ.get("SUDO_USER", "root")
        home_dir = f"/home/{user}" if user != "root" else "/root"
        result = self._safe_run(["ls", "-la", home_dir])
        await update.message.reply_text(
            f"\U0001f3e0 Home de {user} ({home_dir})\n<pre>{result}</pre>",
            parse_mode=ParseMode.HTML)

    async def _cmd_ls(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        path = " ".join(ctx.args) if ctx.args else "/"
        result = self._safe_run(["ls", "-la", path])
        await update.message.reply_text(f"<pre>{result}</pre>", parse_mode=ParseMode.HTML)

    async def _cmd_cat(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        if not ctx.args:
            await update.message.reply_text("Uso: /cat &lt;ruta&gt;", parse_mode=ParseMode.HTML)
            return
        filepath = " ".join(ctx.args)
        result = self._safe_run(["head", "-50", filepath])
        await update.message.reply_text(f"<pre>{result}</pre>", parse_mode=ParseMode.HTML)

    async def _cmd_mkdir(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        if not ctx.args:
            await update.message.reply_text("Uso: /mkdir &lt;ruta&gt;", parse_mode=ParseMode.HTML)
            return
        dirpath = " ".join(ctx.args)
        result = self._safe_run(["mkdir", "-p", dirpath])
        if "error" not in result.lower():
            result = f"Directorio creado: {dirpath}\n" + self._safe_run(["ls", "-ld", dirpath])
        await update.message.reply_text(f"<pre>{result}</pre>", parse_mode=ParseMode.HTML)

    async def _cmd_touch(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        if not ctx.args:
            await update.message.reply_text("Uso: /touch &lt;ruta&gt;", parse_mode=ParseMode.HTML)
            return
        filepath = " ".join(ctx.args)
        result = self._safe_run(["touch", filepath])
        if "error" not in result.lower():
            result = f"Archivo creado: {filepath}\n" + self._safe_run(["ls", "-l", filepath])
        await update.message.reply_text(f"<pre>{result}</pre>", parse_mode=ParseMode.HTML)

    async def _cmd_exec(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        if not ctx.args:
            await update.message.reply_text("Uso: /cmd &lt;comando&gt;", parse_mode=ParseMode.HTML)
            return
        command = " ".join(ctx.args)
        logger.warning("telegram_remote_cmd", command=command, user=update.effective_user.id)
        result = self._safe_run(["bash", "-c", command], timeout=30)
        await update.message.reply_text(f"<pre>{result}</pre>", parse_mode=ParseMode.HTML)

    # ── Helpers ───────────────────────────────────────────

    @staticmethod
    def _safe_run(args: list[str], timeout: int = 10) -> str:
        try:
            proc = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout, check=False,
            )
            output = proc.stdout or ""
            if proc.stderr:
                output += f"\n[stderr] {proc.stderr}"
            return (output.strip() or "(sin salida)")[:_MAX_MSG]
        except subprocess.TimeoutExpired:
            return f"[timeout] Comando excedio {timeout}s"
        except Exception as e:
            return f"[error] {e}"
