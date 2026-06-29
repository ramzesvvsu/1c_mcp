"""Конфигурация MCP-прокси сервера."""

import json
import os
from pathlib import Path
from typing import Optional, Literal, List
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


class OneCBase(BaseModel):
    """Описание одной базы 1С (одного MCP-endpoint мультибазового прокси)."""

    id: str = Field(..., description="Идентификатор базы — становится сегментом пути (/<id>/mcp/)")
    url: str = Field(..., description="URL базы 1С (например, http://192.168.2.50/erp)")
    username: Optional[str] = Field(default=None, description="Имя пользователя 1С")
    password: Optional[str] = Field(default=None, description="Пароль пользователя 1С")
    service_root: str = Field(default="mcp", description="Корневой URL HTTP-сервиса в 1С")

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        value = value.strip().strip("/")
        if not value:
            raise ValueError("id базы не должен быть пустым")
        if "/" in value:
            raise ValueError(f"id базы '{value}' не должен содержать '/'")
        return value


class Config(BaseSettings):
    """Настройки MCP-прокси сервера."""

    # Настройки сервера
    host: str = Field(default="127.0.0.1", description="Хост для HTTP-сервера")
    port: int = Field(default=8000, description="Порт для HTTP-сервера")

    # Настройки подключения к 1С (одиночная база — обратная совместимость)
    onec_url: Optional[str] = Field(default=None, description="URL базы 1С (одиночный режим)")
    onec_username: Optional[str] = Field(default=None, description="Имя пользователя 1С")
    onec_password: Optional[str] = Field(default=None, description="Пароль пользователя 1С")
    onec_service_root: str = Field(default="mcp", description="Корневой URL HTTP-сервиса в 1С")

    # Мультибазовый режим: путь к JSON-файлу со списком баз
    bases_file: Optional[str] = Field(default=None, description="Путь к JSON-файлу со списком баз 1С")

    # Список баз (заполняется в get_config(), не из окружения напрямую)
    bases: List[OneCBase] = Field(default_factory=list, exclude=True)

    # Настройки MCP
    server_name: str = Field(default="1C Configuration Data Tools", description="Имя MCP-сервера")
    server_version: str = Field(default="1.0.0", description="Версия MCP-сервера")

    # Настройки логирования
    log_level: str = Field(default="INFO", description="Уровень логирования")

    # Настройки безопасности
    cors_origins: list[str] = Field(default=["*"], description="Разрешенные CORS origins")

    # Настройки авторизации OAuth2
    auth_mode: Literal["none", "oauth2"] = Field(default="none", description="Режим авторизации: none или oauth2")

    @field_validator("auth_mode", mode="before")
    @classmethod
    def normalize_auth_mode(cls, v: str) -> str:
        if isinstance(v, str):
            return v.lower()
        return v
    public_url: Optional[str] = Field(default=None, description="Публичный URL прокси для OAuth2 (если не задан, формируется из запроса)")
    oauth2_code_ttl: int = Field(default=120, description="TTL authorization code в секундах")
    oauth2_access_ttl: int = Field(default=3600, description="TTL access token в секундах")
    oauth2_refresh_ttl: int = Field(default=1209600, description="TTL refresh token в секундах (14 дней)")

    class Config:
        env_file = ".env"
        env_prefix = "MCP_"


def _load_bases_from_file(path: Path, default_service_root: str) -> List[OneCBase]:
    """Загрузить список баз из JSON-файла.

    Поддерживаются ключи url, user/username, password, service_root, id.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))

    # Допускаем как массив, так и {"bases": [...]}
    if isinstance(raw, dict):
        raw = raw.get("bases", [])
    if not isinstance(raw, list):
        raise ValueError("Файл баз должен содержать JSON-массив или объект с ключом 'bases'")

    bases: List[OneCBase] = []
    seen_ids = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError(f"Некорректная запись базы (ожидался объект): {entry!r}")
        base = OneCBase(
            id=entry["id"],
            url=entry["url"],
            username=entry.get("user", entry.get("username")),
            password=entry.get("password"),
            service_root=entry.get("service_root", default_service_root),
        )
        if base.id in seen_ids:
            raise ValueError(f"Дублирующийся id базы: '{base.id}'")
        seen_ids.add(base.id)
        bases.append(base)

    if not bases:
        raise ValueError(f"Файл баз '{path}' не содержит ни одной базы")
    return bases


def get_config() -> Config:
    """Получить конфигурацию.

    Источник списка баз (по приоритету):
      1. JSON-файл MCP_BASES_FILE (или ./bases.json, если существует) — мультибазовый режим;
      2. одиночная база из MCP_ONEC_URL / MCP_ONEC_USERNAME / MCP_ONEC_PASSWORD.
    """
    config = Config()

    # Определяем путь к файлу баз: явный MCP_BASES_FILE или дефолтный ./bases.json
    bases_path: Optional[Path] = None
    if config.bases_file:
        bases_path = Path(config.bases_file)
        if not bases_path.exists():
            raise ValueError(f"Файл баз не найден: {bases_path}")
    else:
        default_path = Path("bases.json")
        if default_path.exists():
            bases_path = default_path

    if bases_path is not None:
        config.bases = _load_bases_from_file(bases_path, config.onec_service_root)
    elif config.onec_url:
        # Обратная совместимость: одиночная база из плоских переменных
        config.bases = [OneCBase(
            id="default",
            url=config.onec_url,
            username=config.onec_username,
            password=config.onec_password,
            service_root=config.onec_service_root,
        )]
    else:
        raise ValueError(
            "Не задан ни файл баз (MCP_BASES_FILE / ./bases.json), ни одиночная база (MCP_ONEC_URL)"
        )

    return config
