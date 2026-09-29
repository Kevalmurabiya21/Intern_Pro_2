"""
Configuration loading for RDRS.

Reads config.yaml and exposes it as a typed Settings object so the rest of
the app never has to touch raw dicts or worry about missing keys.

Implementation note: this module uses stdlib `dataclasses` rather than
`pydantic`. Functionally they play the same role here (typed, validated-ish
config objects with defaults). If you have `pydantic` installed and prefer
it, swapping these dataclasses for BaseModel subclasses is a drop-in change
- nothing else in the app touches these internals, everything goes through
get_settings().
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml


@dataclass
class MonitorSettings:
    watch_paths: List[str] = field(default_factory=lambda: ["./data/sandbox"])
    ignore_patterns: List[str] = field(default_factory=list)


@dataclass
class Thresholds:
    files_modified_per_minute: int = 20
    renames_per_minute: int = 15
    extension_changes_per_minute: int = 10
    high_entropy_value: float = 7.5
    cpu_spike_percent: float = 70.0


@dataclass
class DetectionSettings:
    window_seconds: int = 60
    thresholds: Thresholds = field(default_factory=Thresholds)


@dataclass
class ScoringWeights:
    rapid_encryption: int = 40
    mass_rename: int = 30
    high_entropy: int = 25
    cpu_spike: int = 15
    unknown_program: int = 10


@dataclass
class ScoringBands:
    normal_max: int = 40
    warning_max: int = 70


@dataclass
class ScoringSettings:
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    bands: ScoringBands = field(default_factory=ScoringBands)


@dataclass
class ResponseSettings:
    simulation_mode: bool = True
    quarantine_dir: str = "./data/quarantine"
    known_programs: List[str] = field(default_factory=list)
    incident_cooldown_seconds: int = 30


@dataclass
class DatabaseSettings:
    path: str = "./data/rdrs.db"


@dataclass
class LoggingSettings:
    dir: str = "./logs"
    level: str = "INFO"
    rotation: str = "10 MB"
    retention: str = "10 days"


@dataclass
class ApiSettings:
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass
class DashboardSettings:
    refresh_seconds: int = 3


@dataclass
class Settings:
    monitor: MonitorSettings = field(default_factory=MonitorSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    scoring: ScoringSettings = field(default_factory=ScoringSettings)
    response: ResponseSettings = field(default_factory=ResponseSettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    api: ApiSettings = field(default_factory=ApiSettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)


class ConfigError(ValueError):
    """Raised when config.yaml contains a value that can't be used safely,
    e.g. wrong top-level structure or a field that can't be coerced to its
    expected type."""


_PRIMITIVE_CASTERS = {int: int, float: float, str: str, bool: bool}


def _cast_field(cls_name: str, field_name: str, expected_type, value):
    """Best-effort cast of a raw YAML value to the field's declared type.
    Raises ConfigError with a clear message rather than letting a bad type
    (e.g. a string where a number is expected) silently propagate and crash
    something far away (e.g. a division in the detection engine)."""
    if expected_type is bool:
        if isinstance(value, bool):
            return value
        raise ConfigError(
            f"{cls_name}.{field_name} must be true/false, got {value!r}"
        )
    if expected_type in (int, float):
        if isinstance(value, bool):  # bool is an int subclass - reject explicitly
            raise ConfigError(f"{cls_name}.{field_name} must be a number, got {value!r}")
        try:
            return expected_type(value)
        except (TypeError, ValueError):
            raise ConfigError(
                f"{cls_name}.{field_name} must be a {expected_type.__name__}, got {value!r}"
            )
    if expected_type is str:
        if isinstance(value, (dict, list)):
            raise ConfigError(f"{cls_name}.{field_name} must be text, got {value!r}")
        return str(value)
    return value  # list/nested types handled elsewhere


def _build(cls, raw: dict):
    """Recursively build a dataclass from a raw dict, ignoring unknown keys,
    falling back to defaults for missing ones, and raising ConfigError on
    values that can't be safely coerced to the expected type."""
    if raw is None:
        return cls()
    if not isinstance(raw, dict):
        raise ConfigError(
            f"Expected a mapping (key: value) for {cls.__name__}, got "
            f"{type(raw).__name__}: {raw!r}. Check config.yaml's structure."
        )
    kwargs = {}
    for f in cls.__dataclass_fields__.values():
        if f.name not in raw:
            continue
        value = raw[f.name]
        ftype = f.type
        nested_map = {
            "MonitorSettings": MonitorSettings, "Thresholds": Thresholds,
            "DetectionSettings": DetectionSettings, "ScoringWeights": ScoringWeights,
            "ScoringBands": ScoringBands, "ScoringSettings": ScoringSettings,
            "ResponseSettings": ResponseSettings, "DatabaseSettings": DatabaseSettings,
            "LoggingSettings": LoggingSettings, "ApiSettings": ApiSettings,
            "DashboardSettings": DashboardSettings,
        }
        if isinstance(ftype, str) and ftype in nested_map:
            kwargs[f.name] = _build(nested_map[ftype], value)
        elif isinstance(ftype, str) and ftype in ("int", "float", "str", "bool"):
            expected = {"int": int, "float": float, "str": str, "bool": bool}[ftype]
            kwargs[f.name] = _cast_field(cls.__name__, f.name, expected, value)
        else:
            # List[str] and similar - accept as-is but reject obviously wrong shapes.
            if isinstance(ftype, str) and ftype.startswith("List") and not isinstance(value, list):
                raise ConfigError(
                    f"{cls.__name__}.{f.name} must be a list, got {type(value).__name__}: {value!r}"
                )
            kwargs[f.name] = value
    return cls(**kwargs)


def load_settings(path: str | Path = "config.yaml") -> Settings:
    """Load config.yaml into a Settings object. Falls back to defaults for
    any missing section/key, and raises a clear error if the file itself is
    missing."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Config file not found at '{p}'. Copy config.yaml to the project "
            "root or pass an explicit path."
        )
    with p.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return _build(Settings, raw)


# A process-wide singleton so every module shares the same loaded config.
_settings: Settings | None = None


def get_settings(path: str | Path = "config.yaml") -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings(path)
    return _settings


def reset_settings_cache() -> None:
    """Used by tests to force a fresh reload."""
    global _settings
    _settings = None
