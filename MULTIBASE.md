# Мультибазовый режим (несколько баз 1С на одном порту)

Прокси умеет обслуживать несколько баз 1С одним процессом на одном порту.
Каждая база получает собственный набор MCP-endpoint'ов по пути `/<id>/...`:

```
http://host:8000/erp/mcp/     ← Streamable HTTP базы erp
http://host:8000/erp/sse      ← SSE базы erp
http://host:8000/erp/health   ← health одной базы
http://host:8000/buh/mcp/     ← база buh
...
http://host:8000/health       ← агрегированный статус по всем базам
http://host:8000/info         ← список баз и endpoint'ов
```

## Конфигурация: bases.json

Список баз задаётся JSON-файлом. Путь к нему — переменная `MCP_BASES_FILE`
(в Docker по умолчанию `/app/bases.json`). Если переменная не задана, но рядом есть
`./bases.json`, берётся он. Если нет ни файла, ни `MCP_ONEC_URL` — старт прерывается.

Формат (см. `bases.json.example`):

```json
[
  { "id": "erp", "url": "http://192.168.2.50/erp", "user": "Администратор", "password": "...", "service_root": "mcp" },
  { "id": "buh", "url": "http://192.168.2.50/buh", "user": "Администратор", "password": "..." }
]
```

- `id` — сегмент пути (`/<id>/mcp/`); без `/`, уникальный.
- `url` — адрес опубликованной базы 1С (как в одиночном режиме).
- `user` / `password` — учётка 1С (можно `username` вместо `user`).
- `service_root` — корень HTTP-сервиса, по умолчанию `mcp`.

`bases.json` содержит пароли и в git не коммитится (он в `.gitignore`).

## Обратная совместимость

Если `bases.json` нет, но заданы `MCP_ONEC_URL` / `MCP_ONEC_USERNAME` / `MCP_ONEC_PASSWORD` —
работает как раньше, одна база с `id=default` на путях `/default/mcp/`, `/default/sse`.

## Запуск в Docker / Synology Container Manager

1. Положить рядом с `docker-compose.yml` файл `bases.json` (скопировать из `bases.json.example`).
2. Поднять проект — `compose` примонтирует `bases.json` в контейнер только на чтение.
3. Проверка: `http://<host>:8000/health` — статус по всем базам.

## Подключение к Claude Code

Каждая база регистрируется своим endpoint'ом (порт один):

```bash
claude mcp add --transport http 1c-erp http://<host>:8000/erp/mcp/
claude mcp add --transport http 1c-buh http://<host>:8000/buh/mcp/
```

## Режим stdio

stdio обслуживает только одну базу — берётся первая из списка. Для нескольких баз
используйте HTTP-режим.

## OAuth2

Совместим с мультибазовым режимом: логин/пароль берутся из сессии пользователя,
серверная проверка креденшилов выполняется через HTTP-сервис первой базы.
