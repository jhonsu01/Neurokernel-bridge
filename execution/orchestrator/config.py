from __future__ import annotations
from pydantic_settings import BaseSettings
from pydantic import Field
from pathlib import Path
from typing import Optional

class SensorConfig(BaseSettings):
    sensor_path: Path = Field(default=Path(__file__).parent.parent / "sensor.c")
    self_filter_comms: list[str] = Field(default=["python3", "orchestrator"])

    model_config = {"env_prefix": "LIAK_", "extra": "ignore"}

class DecisionConfig(BaseSettings):
    # Tier 1: Rules
    # Critical paths: only root should access — non-root = MALICIOUS
    critical_paths: list[str] = Field(default=[
        "/etc/shadow", "/etc/gshadow",
        "/proc/kcore", "/dev/mem", "/dev/kmem",
    ])
    # Sensitive paths: non-root access is suspicious but not immediately malicious
    sensitive_paths: list[str] = Field(default=[
        "/etc/sudoers", ".ssh/", "/root/",
    ])
    # World-readable system files that should NEVER trigger alerts
    safe_system_files: list[str] = Field(default=[
        "/etc/passwd", "/etc/group", "/etc/hostname", "/etc/hosts",
        "/etc/nsswitch.conf", "/etc/resolv.conf", "/etc/localtime",
    ])
    suspicious_ports: list[int] = Field(default=[4444, 5555, 6666, 1337, 31337, 8888])
    whitelisted_procs: list[str] = Field(default=[
        # System daemons
        "systemd", "sshd", "cron", "snapd", "networkd",
        "journald", "udevd", "dbus-daemon", "polkitd",
        # Terminals and shells
        "bash", "zsh", "fish", "sh", "dash",
        "konsole", "gnome-terminal-", "xterm", "alacritty", "kitty", "terminator",
        # Desktop environment
        "kwin_wayland", "kwin_x11", "plasmashell", "gnome-shell", "Xorg", "Xwayland",
        # Common dev tools
        "python3", "git", "code", "cursor", "node",
    ])
    # Processes that must NEVER be killed regardless of detection
    protected_procs: list[str] = Field(default=[
        # Core system
        "systemd", "init",
        # Terminals
        "konsole", "gnome-terminal-", "xterm", "alacritty", "kitty",
        "terminator", "tilix", "yakuake",
        # Shells
        "bash", "zsh", "fish", "sh", "dash",
        # Desktop environment
        "kwin_wayland", "kwin_x11", "plasmashell", "gnome-shell",
        "Xorg", "Xwayland", "mutter",
        # Session managers
        "sddm", "gdm", "lightdm", "login",
    ])
    # Dry-run mode: log actions but don't kill/renice anything
    dry_run: bool = Field(default=True)

    # Tier 2: ChromaDB
    chromadb_path: Path = Field(default=Path("./system_memory"))
    chromadb_collection: str = Field(default="security_decisions")
    similarity_threshold: float = Field(default=0.85)

    # Tier 3: Claude API
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-sonnet-4-20250514")
    max_api_calls_per_minute: int = Field(default=20)
    api_timeout_seconds: float = Field(default=2.0)

    model_config = {"env_prefix": "LIAK_", "env_file": ".env", "populate_by_name": True, "extra": "ignore"}

class BatchingConfig(BaseSettings):
    batch_window_seconds: float = Field(default=1.0)
    max_batch_size: int = Field(default=50)

    model_config = {"env_prefix": "LIAK_", "extra": "ignore"}

class MemoryConfig(BaseSettings):
    claude_mem_api_url: str = Field(default="http://localhost:37777")
    enable_claude_mem: bool = Field(default=True)
    session_compress_interval_minutes: int = Field(default=30)

    model_config = {"env_prefix": "LIAK_", "extra": "ignore"}

class TelegramConfig(BaseSettings):
    telegram_bot_token: Optional[str] = Field(default=None)
    telegram_chat_id: Optional[str] = Field(default=None)
    notify_decisions: list[str] = Field(default=["MALICIOUS", "LIMIT"])
    notify_min_confidence: float = Field(default=0.5)
    enable_remote_commands: bool = Field(default=True)

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}

class AppConfig(BaseSettings):
    sensor: SensorConfig = Field(default_factory=SensorConfig)
    decision: DecisionConfig = Field(default_factory=DecisionConfig)
    batching: BatchingConfig = Field(default_factory=BatchingConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)
    log_level: str = Field(default="INFO")
    log_file: Optional[Path] = Field(default=Path("./logs/orchestrator.jsonl"))

    model_config = {"env_prefix": "LIAK_", "env_file": ".env", "extra": "ignore"}
