"""HTTP-сервер с поддержкой SSE и Streamable HTTP для MCP (мультибазовый режим)."""

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager, AsyncExitStack
from urllib.parse import urlencode, parse_qs

from fastapi import FastAPI, Request, Response, HTTPException, Form
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx

from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.models import InitializationOptions
from starlette.types import Scope, Receive, Send
from starlette.middleware.base import BaseHTTPMiddleware

from .mcp_server import MCPProxy, current_onec_credentials
from .config import Config
from .auth import OAuth2Service, OAuth2Store


logger = logging.getLogger(__name__)


class OAuth2BearerMiddleware(BaseHTTPMiddleware):
	"""Middleware для проверки Bearer токенов в режиме OAuth2."""

	def __init__(self, app, oauth2_service: Optional[OAuth2Service], auth_mode: str):
		super().__init__(app)
		self.oauth2_service = oauth2_service
		self.auth_mode = auth_mode

	def _is_protected(self, path: str) -> bool:
		"""Защищаем любой транспортный путь базы: /<id>/mcp/ и /<id>/sse."""
		return "/mcp/" in path or "/sse" in path

	async def dispatch(self, request: Request, call_next):
		"""Проверка авторизации для защищённых путей."""
		# Пропускаем, если auth_mode != oauth2
		if self.auth_mode != "oauth2":
			return await call_next(request)

		# Проверяем, является ли путь защищённым
		path = request.url.path
		if not self._is_protected(path):
			return await call_next(request)

		# Извлекаем Bearer token
		auth_header = request.headers.get("Authorization", "")
		if not auth_header.startswith("Bearer "):
			return JSONResponse(
				status_code=401,
				content={"error": "invalid_token"},
				headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
			)

		token = auth_header[7:]  # Убираем "Bearer "

		# Валидируем токен (поддерживаем два формата)
		creds = None

		# 1. Простой формат: simple_base64(username:password)
		if token.startswith("simple_"):
			try:
				import base64
				creds_string = base64.b64decode(token[7:]).decode()
				username, password = creds_string.split(":", 1)
				creds = (username, password)
				logger.debug(f"Простой токен валидирован для пользователя: {username}")
			except Exception as e:
				logger.warning(f"Ошибка декодирования простого токена: {e}")
				creds = None

		# 2. OAuth2 формат: через хранилище
		if not creds:
			creds = self.oauth2_service.validate_access_token(token)

		if not creds:
			return JSONResponse(
				status_code=401,
				content={"error": "invalid_token"},
				headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
			)

		# Устанавливаем креденшилы в context var для этой сессии
		login, password = creds
		current_onec_credentials.set((login, password))

		# Передаём управление дальше
		response = await call_next(request)
		return response


class MCPHttpServer:
	"""HTTP-сервер для MCP с поддержкой SSE и Streamable HTTP (несколько баз на одном порту)."""

	def __init__(self, config: Config):
		"""Инициализация HTTP-сервера.

		Args:
			config: Конфигурация сервера
		"""
		self.config = config

		# По одному MCP-прокси и session manager на каждую базу 1С
		self.proxies: Dict[str, MCPProxy] = {}
		self.session_managers: Dict[str, StreamableHTTPSessionManager] = {}
		for base in config.bases:
			proxy = MCPProxy(config, base)
			self.proxies[base.id] = proxy
			self.session_managers[base.id] = StreamableHTTPSessionManager(proxy.server)
		logger.info(f"Сконфигурировано баз 1С: {len(self.proxies)} ({', '.join(self.proxies)})")

		# Инициализация OAuth2 (если включено)
		self.oauth2_store: Optional[OAuth2Store] = None
		self.oauth2_service: Optional[OAuth2Service] = None
		if config.auth_mode == "oauth2":
			self.oauth2_store = OAuth2Store()
			self.oauth2_service = OAuth2Service(
				self.oauth2_store,
				code_ttl=config.oauth2_code_ttl,
				access_ttl=config.oauth2_access_ttl,
				refresh_ttl=config.oauth2_refresh_ttl
			)
			logger.info("OAuth2 авторизация включена")

		self.app = FastAPI(
			title="1C MCP Proxy",
			description="MCP-прокси для взаимодействия с 1С",
			version=config.server_version,
			lifespan=self._lifespan
		)

		# Настройка CORS
		self.app.add_middleware(
			CORSMiddleware,
			allow_origins=config.cors_origins,
			allow_credentials=True,
			allow_methods=["*"],
			allow_headers=["*"],
		)

		# Добавляем OAuth2 middleware
		self.app.add_middleware(
			OAuth2BearerMiddleware,
			oauth2_service=self.oauth2_service,
			auth_mode=config.auth_mode
		)

		# Монтируем транспорты
		self._mount_transports()

		# Регистрация основных маршрутов
		self._register_routes()

	@asynccontextmanager
	async def _lifespan(self, app: FastAPI):
		"""Управление жизненным циклом приложения."""
		logger.debug("Запуск HTTP-сервера MCP")

		# Запускаем задачу очистки OAuth2 токенов (если включено)
		if self.oauth2_store:
			await self.oauth2_store.start_cleanup_task(interval=60)

		# Запускаем session manager'ы для всех баз
		async with AsyncExitStack() as stack:
			for base_id, manager in self.session_managers.items():
				await stack.enter_async_context(manager.run())
				logger.debug(f"Session manager запущен для базы '{base_id}'")
			yield

		# Останавливаем задачу очистки OAuth2
		if self.oauth2_store:
			await self.oauth2_store.stop_cleanup_task()

		logger.debug("Остановка HTTP-сервера MCP")

	def _create_sse_asgi(self, mcp_proxy: MCPProxy, base_id: str):
		"""Создание чистого ASGI обработчика для SSE для конкретной базы.

		Использует прямую работу с ASGI примитивами (scope/receive/send)
		вместо зависимости от Starlette Request и приватных атрибутов.

		Args:
			mcp_proxy: MCP-прокси обслуживаемой базы
			base_id: идентификатор базы (сегмент пути)
		"""
		# Endpoint сообщений сообщаем клиенту абсолютным путём с учётом базы
		messages_endpoint = f"/{base_id}/sse/messages/"
		sse_transport = SseServerTransport(messages_endpoint)

		async def asgi(scope: Scope, receive: Receive, send: Send) -> None:
			"""ASGI обработчик для SSE соединений."""
			# Обработка lifespan событий
			if scope["type"] == "lifespan":
				while True:
					message = await receive()
					if message["type"] == "lifespan.startup":
						await send({"type": "lifespan.startup.complete"})
					elif message["type"] == "lifespan.shutdown":
						await send({"type": "lifespan.shutdown.complete"})
						return

			# Обработка HTTP запросов
			if scope["type"] != "http":
				return

			# После mount Starlette уже срезает префикс /<id>/sse — путь относительный
			path = scope["path"]
			if not path:
				path = "/"
			if path == "/messages":
				path = "/messages/"

			method = scope["method"]

			# Маршрутизация:
			# GET / -> SSE подключение
			# POST /messages -> отправка сообщений
			if method == "GET" and path == "/":
				logger.debug(f"Новое SSE подключение (база '{base_id}')")
				try:
					# Подключаем SSE с использованием транспорта
					async with sse_transport.connect_sse(scope, receive, send) as streams:
						# Запускаем MCP сервер с потоками
						await mcp_proxy.server.run(
							streams[0],
							streams[1],
							mcp_proxy.get_initialization_options()
						)
				except Exception as e:
					logger.error(f"Ошибка в SSE обработчике (база '{base_id}'): {e}")
					raise
				finally:
					logger.debug(f"SSE подключение закрыто (база '{base_id}')")

			elif method == "POST" and path.startswith("/messages"):
				# Обработка POST сообщений через транспорт
				adjusted_scope = dict(scope)
				adjusted_scope["path"] = path
				if "raw_path" in adjusted_scope:
					adjusted_scope["raw_path"] = path.encode("utf-8")
				await sse_transport.handle_post_message(adjusted_scope, receive, send)

			else:
				# Неизвестный маршрут
				await send({
					"type": "http.response.start",
					"status": 404,
					"headers": [[b"content-type", b"text/plain"]],
				})
				await send({
					"type": "http.response.body",
					"body": b"Not Found",
				})

		return asgi

	def _create_streamable_http_asgi(self, session_manager: StreamableHTTPSessionManager, base_id: str):
		"""Создание ASGI обработчика для Streamable HTTP конкретной базы."""

		async def asgi(scope: Scope, receive: Receive, send: Send) -> None:
			"""ASGI обработчик для Streamable HTTP соединений."""
			logger.debug(f"Новое Streamable HTTP подключение (база '{base_id}')")

			try:
				# Используем правильный API handle_request для ASGI
				await session_manager.handle_request(scope, receive, send)
			except Exception as e:
				logger.error(f"Ошибка в Streamable HTTP обработчике (база '{base_id}'): {e}")
				raise
			finally:
				logger.debug(f"Streamable HTTP подключение закрыто (база '{base_id}')")

		return asgi

	def _mount_transports(self):
		"""Монтирование транспортов MCP по каждой базе.

		Для базы <id>:
		  /<id>/sse   — SSE транспорт
		  /<id>/mcp/  — Streamable HTTP транспорт (с trailing slash против 307-редиректов)
		"""
		for base_id, proxy in self.proxies.items():
			sse_app = self._create_sse_asgi(proxy, base_id)
			self.app.mount(f"/{base_id}/sse", sse_app)

			streamable_app = self._create_streamable_http_asgi(self.session_managers[base_id], base_id)
			self.app.mount(f"/{base_id}/mcp/", streamable_app)

			logger.debug(f"Смонтированы транспорты базы '{base_id}': /{base_id}/mcp/ , /{base_id}/sse")

	def _base_endpoints(self) -> Dict[str, Dict[str, str]]:
		"""Карта endpoints по базам для /info и /."""
		return {
			base_id: {
				"streamable_http": f"/{base_id}/mcp/",
				"sse": f"/{base_id}/sse",
				"messages": f"/{base_id}/sse/messages/",
				"health": f"/{base_id}/health",
			}
			for base_id in self.proxies
		}

	async def _check_base_health(self, base_id: str) -> Dict[str, Any]:
		"""Прямая проверка доступности HTTP-сервиса 1С для одной базы."""
		base = next((b for b in self.config.bases if b.id == base_id), None)
		if base is None:
			return {"onec_connection": "unknown", "error_details": "база не найдена"}

		# В режиме oauth2 креды per-session — серверной проверки без логина нет
		if self.config.auth_mode == "oauth2":
			return {"onec_connection": "per_session", "auth": "oauth2"}

		url = f"{base.url.rstrip('/')}/hs/{base.service_root.strip('/')}/health"
		try:
			auth = httpx.BasicAuth(base.username or "", base.password or "")
			async with httpx.AsyncClient(timeout=10.0) as client:
				response = await client.get(url, auth=auth)
				response.raise_for_status()
				body = response.json()
				if body.get("status") == "ok":
					return {"onec_connection": "ok"}
				return {"onec_connection": "error", "error_details": f"1С вернула: {body}"}
		except Exception as e:
			return {"onec_connection": "error", "error_details": str(e)}

	def _register_routes(self):
		"""Регистрация основных маршрутов."""

		@self.app.get("/")
		async def root():
			"""Корневой маршрут — список баз и endpoints."""
			result = {
				"message": "1C MCP Proxy Server (multi-base)",
				"bases": list(self.proxies.keys()),
				"endpoints": {
					"info": "/info",
					"health": "/health",
					"per_base": self._base_endpoints(),
				},
			}
			if self.config.auth_mode == "oauth2":
				result["endpoints"]["oauth2"] = {
					"well_known_prm": "/.well-known/oauth-protected-resource",
					"well_known_as": "/.well-known/oauth-authorization-server",
					"register": "/register",
					"authorize": "/authorize",
					"token": "/token"
				}
			return result

		@self.app.get("/info")
		async def info():
			"""Информационный маршрут."""
			return {
				"name": self.config.server_name,
				"version": self.config.server_version,
				"description": "MCP-прокси для взаимодействия с 1С (несколько баз на одном порту)",
				"bases": list(self.proxies.keys()),
				"transports": self._base_endpoints(),
			}

		@self.app.get("/health")
		async def health():
			"""Агрегированная проверка здоровья по всем базам."""
			bases_status = {}
			all_ok = True
			for base_id in self.proxies:
				status = await self._check_base_health(base_id)
				bases_status[base_id] = status
				if status.get("onec_connection") not in ("ok", "per_session"):
					all_ok = False

			return {
				"status": "healthy" if all_ok else "degraded",
				"auth": {"mode": self.config.auth_mode},
				"bases": bases_status,
			}

		@self.app.get("/{base_id}/health")
		async def base_health(base_id: str):
			"""Проверка здоровья одной базы."""
			if base_id not in self.proxies:
				raise HTTPException(status_code=404, detail=f"База '{base_id}' не найдена")
			status = await self._check_base_health(base_id)
			ok = status.get("onec_connection") in ("ok", "per_session")
			return {
				"status": "healthy" if ok else "unhealthy",
				"base": base_id,
				"auth": {"mode": self.config.auth_mode},
				**status,
			}

		# OAuth2 endpoints (если включено)
		if self.config.auth_mode == "oauth2":
			self._register_oauth2_routes()

	def _oauth2_validation_url(self) -> str:
		"""URL базы для серверной проверки креденшилов OAuth2.

		В мультибазовом режиме берём первую базу (для проверки логина/пароля
		достаточно любого доступного HTTP-сервиса 1С).
		"""
		base = self.config.bases[0]
		return f"{base.url.rstrip('/')}/hs/{base.service_root.strip('/')}"

	def _register_oauth2_routes(self):
		"""Регистрация OAuth2 маршрутов."""

		@self.app.get("/.well-known/oauth-protected-resource")
		async def well_known_prm(request: Request):
			"""Protected Resource Metadata (RFC 9728)."""
			if self.config.public_url:
				public_url = self.config.public_url
			else:
				scheme = request.url.scheme
				netloc = request.headers.get("host", f"{request.client.host}:{request.url.port}")
				public_url = f"{scheme}://{netloc}"

			return self.oauth2_service.generate_prm_document(public_url)

		@self.app.get("/.well-known/oauth-authorization-server")
		async def well_known_as_metadata(request: Request):
			"""Authorization Server Metadata (RFC 8414)."""
			if self.config.public_url:
				base_url = self.config.public_url
			else:
				scheme = request.url.scheme
				netloc = request.headers.get("host", f"{request.client.host}:{request.url.port}")
				base_url = f"{scheme}://{netloc}"

			return {
				"issuer": base_url,
				"authorization_endpoint": f"{base_url}/authorize",
				"token_endpoint": f"{base_url}/token",
				"registration_endpoint": f"{base_url}/register",
				"grant_types_supported": [
					"authorization_code",
					"refresh_token",
					"password"
				],
				"response_types_supported": ["code"],
				"code_challenge_methods_supported": ["S256"],
				"token_endpoint_auth_methods_supported": ["none"],
				"revocation_endpoint_auth_methods_supported": ["none"]
			}

		@self.app.post("/register")
		async def register_client(request: Request):
			"""Dynamic Client Registration (RFC 7591) — упрощённая версия."""
			try:
				body = await request.json()
				logger.debug(f"Client registration request: {body}")
			except:
				body = {}

			if self.config.public_url:
				base_url = self.config.public_url
			else:
				scheme = request.url.scheme
				netloc = request.headers.get("host", f"{request.client.host}:{request.url.port}")
				base_url = f"{scheme}://{netloc}"

			client_data = {
				"client_id": "mcp-public-client",
				"client_secret": "",
				"client_id_issued_at": 1640000000,
				"grant_types": ["authorization_code", "refresh_token", "password"],
				"response_types": ["code"],
				"redirect_uris": [
					f"{base_url}/callback",
					"http://localhost/callback",
					"http://127.0.0.1/callback"
				],
				"token_endpoint_auth_method": "none",
				"application_type": "web"
			}

			if "redirect_uris" in body:
				for uri in body.get("redirect_uris", []):
					if uri not in client_data["redirect_uris"]:
						client_data["redirect_uris"].append(uri)

			logger.info("Client registration: вернули фиксированный client_id='mcp-public-client'")
			return client_data

		@self.app.get("/authorize")
		async def authorize_get(
			request: Request,
			response_type: str = None,
			client_id: str = None,
			redirect_uri: str = None,
			state: str = None,
			code_challenge: str = None,
			code_challenge_method: str = None
		):
			"""Authorization endpoint — показывает форму логина."""
			if not all([response_type, client_id, redirect_uri, code_challenge, code_challenge_method]):
				return HTMLResponse(
					content="<html><body><h1>Ошибка</h1><p>Отсутствуют обязательные параметры OAuth2</p></body></html>",
					status_code=400
				)

			if response_type != "code":
				return HTMLResponse(
					content="<html><body><h1>Ошибка</h1><p>Поддерживается только response_type=code</p></body></html>",
					status_code=400
				)

			if code_challenge_method != "S256":
				return HTMLResponse(
					content="<html><body><h1>Ошибка</h1><p>Поддерживается только code_challenge_method=S256</p></body></html>",
					status_code=400
				)

			query_params = urlencode({
				"redirect_uri": redirect_uri,
				"state": state or "",
				"code_challenge": code_challenge
			})

			html_content = f"""
			<!DOCTYPE html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>Авторизация 1С MCP</title>
				<style>
					body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }}
					h1 {{ color: #333; }}
					form {{ display: flex; flex-direction: column; }}
					label {{ margin-top: 10px; color: #666; }}
					input {{ padding: 8px; margin-top: 5px; border: 1px solid #ddd; border-radius: 4px; }}
					button {{ margin-top: 20px; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }}
					button:hover {{ background: #0056b3; }}
					.error {{ color: red; margin-top: 10px; }}
				</style>
			</head>
			<body>
				<h1>Вход в 1С</h1>
				<p>Введите учётные данные пользователя 1С:</p>
				<form method="post" action="/authorize?{query_params}">
					<label for="username">Логин:</label>
					<input type="text" id="username" name="username" required autofocus>

					<label for="password">Пароль:</label>
					<input type="password" id="password" name="password" required>

					<button type="submit">Войти</button>
				</form>
			</body>
			</html>
			"""
			return HTMLResponse(content=html_content)

		@self.app.post("/authorize")
		async def authorize_post(
			request: Request,
			username: str = Form(...),
			password: str = Form(...),
			redirect_uri: str = None,
			state: str = None,
			code_challenge: str = None
		):
			"""Обработка формы логина и выдача authorization code."""
			if not all([redirect_uri, code_challenge]):
				return HTMLResponse(
					content="<html><body><h1>Ошибка</h1><p>Отсутствуют обязательные параметры</p></body></html>",
					status_code=400
				)

			# Валидация креденшилов через вызов к 1С health endpoint
			try:
				async with httpx.AsyncClient(timeout=10.0) as client:
					health_url = f"{self._oauth2_validation_url()}/health"
					response = await client.get(
						health_url,
						auth=httpx.BasicAuth(username, password)
					)

					if response.status_code == 401:
						error_html = """
						<!DOCTYPE html>
						<html>
						<head><meta charset="utf-8"><title>Ошибка авторизации</title></head>
						<body>
							<h1>Ошибка авторизации</h1>
							<p style="color:red">Неверный логин или пароль 1С</p>
							<p><a href="javascript:history.back()">← Вернуться назад</a></p>
						</body>
						</html>
						"""
						return HTMLResponse(content=error_html, status_code=401)

					if response.status_code == 403:
						error_html = f"""
						<!DOCTYPE html>
						<html>
						<head><meta charset="utf-8"><title>Недостаточно прав</title></head>
						<body>
							<h1>Недостаточно прав</h1>
							<p style="color:red">Пользователь <b>{username}</b> не имеет прав на работу с MCP HTTP-сервисом в 1С.</p>
							<p><a href="javascript:history.back()">← Вернуться назад</a></p>
						</body>
						</html>
						"""
						return HTMLResponse(content=error_html, status_code=403)

					if response.status_code != 200:
						logger.warning(f"1С вернула статус {response.status_code} при проверке креденшилов пользователя {username}")
						return HTMLResponse(
							content=f"<html><body><h1>Ошибка</h1><p>1С вернула неожиданный статус {response.status_code}</p></body></html>",
							status_code=502
						)
			except Exception as e:
				logger.error(f"Ошибка проверки креденшилов 1С: {e}")
				return HTMLResponse(
					content=f"<html><body><h1>Ошибка</h1><p>Не удалось подключиться к 1С: {e}</p></body></html>",
					status_code=503
				)

			# Генерируем authorization code
			code = self.oauth2_service.generate_authorization_code(
				login=username,
				password=password,
				redirect_uri=redirect_uri,
				code_challenge=code_challenge
			)

			params = {"code": code}
			if state:
				params["state"] = state

			redirect_url = f"{redirect_uri}?{urlencode(params)}"
			logger.info(f"Authorization code выдан для пользователя {username}, redirect: {redirect_uri}")
			return RedirectResponse(url=redirect_url, status_code=302)

		@self.app.post("/token")
		async def token_endpoint(
			request: Request,
			grant_type: str = Form(...),
			code: str = Form(None),
			redirect_uri: str = Form(None),
			code_verifier: str = Form(None),
			refresh_token: str = Form(None),
			username: str = Form(None),
			password: str = Form(None)
		):
			"""Token endpoint для обмена code на токены, refresh или password grant."""

			# Password Grant
			if grant_type == "password":
				if username is None:
					return JSONResponse(
						status_code=400,
						content={"error": "invalid_request", "error_description": "Missing username"}
					)

				try:
					async with httpx.AsyncClient(timeout=10.0) as client:
						health_url = f"{self._oauth2_validation_url()}/health"
						response = await client.get(
							health_url,
							auth=httpx.BasicAuth(username, password or "")
						)

						if response.status_code == 401:
							return JSONResponse(
								status_code=400,
								content={"error": "invalid_grant", "error_description": "Invalid username or password"}
							)

						if response.status_code == 403:
							return JSONResponse(
								status_code=403,
								content={"error": "insufficient_scope", "error_description": f"User '{username}' does not have permissions for MCP HTTP service."}
							)

						if response.status_code != 200:
							logger.warning(f"1C returned status {response.status_code} during credential check for user {username}")
							return JSONResponse(
								status_code=502,
								content={"error": "server_error", "error_description": f"1C returned unexpected status {response.status_code}"}
							)
				except Exception as e:
					logger.error(f"Ошибка проверки креденшилов 1С для password grant: {e}")
					return JSONResponse(
						status_code=503,
						content={"error": "server_error", "error_description": "Unable to validate credentials"}
					)

				import base64
				creds_string = f"{username}:{password}"
				simple_token = "simple_" + base64.b64encode(creds_string.encode()).decode()
				logger.info(f"Password grant выдан для пользователя {username}")

				return {
					"access_token": simple_token,
					"token_type": "Bearer",
					"expires_in": 86400,
					"scope": "mcp"
				}

			# Authorization Code Grant
			if grant_type == "authorization_code":
				if not all([code, redirect_uri, code_verifier]):
					return JSONResponse(
						status_code=400,
						content={"error": "invalid_request", "error_description": "Missing required parameters"}
					)

				result = self.oauth2_service.exchange_code_for_tokens(code, redirect_uri, code_verifier)
				if not result:
					return JSONResponse(
						status_code=400,
						content={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"}
					)

				access_token, token_type, expires_in, refresh = result
				return {
					"access_token": access_token,
					"token_type": token_type,
					"expires_in": expires_in,
					"refresh_token": refresh,
					"scope": "mcp"
				}

			elif grant_type == "refresh_token":
				if not refresh_token:
					return JSONResponse(
						status_code=400,
						content={"error": "invalid_request", "error_description": "Missing refresh_token"}
					)

				result = self.oauth2_service.refresh_tokens(refresh_token)
				if not result:
					return JSONResponse(
						status_code=400,
						content={"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}
					)

				access_token, token_type, expires_in, new_refresh = result
				return {
					"access_token": access_token,
					"token_type": token_type,
					"expires_in": expires_in,
					"refresh_token": new_refresh,
					"scope": "mcp"
				}

			else:
				return JSONResponse(
					status_code=400,
					content={"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' not supported"}
				)

	async def start(self):
		"""Запуск HTTP-сервера."""
		config = uvicorn.Config(
			app=self.app,
			host=self.config.host,
			port=self.config.port,
			log_level=self.config.log_level.lower(),
			access_log=True
		)

		server = uvicorn.Server(config)
		logger.debug(f"Запуск HTTP-сервера на {self.config.host}:{self.config.port}")
		await server.serve()


async def run_http_server(config: Config):
	"""Запуск HTTP-сервера.

	Args:
		config: Конфигурация сервера
	"""
	server = MCPHttpServer(config)
	await server.start()
