"""Stdio сервер для MCP."""

import asyncio
import logging

import mcp.server.stdio
from .mcp_server import MCPProxy
from .config import Config


logger = logging.getLogger(__name__)


async def run_stdio_server(config: Config):
	"""Запуск stdio сервера.
	
	Args:
		config: Конфигурация сервера
	"""
	logger.info("Запуск MCP сервера в режиме stdio")

	# Stdio обслуживает одну базу — берём первую из списка
	base = config.bases[0]
	if len(config.bases) > 1:
		logger.warning(
			f"В режиме stdio задействована только первая база '{base.id}'. "
			f"Для нескольких баз используйте HTTP-режим."
		)

	# Создаем прокси
	mcp_proxy = MCPProxy(config, base)
	
	try:
		# Запускаем сервер через stdio
		async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
			await mcp_proxy.server.run(
				read_stream,
				write_stream,
				mcp_proxy.get_initialization_options()
			)
	except Exception as e:
		logger.error(f"Ошибка в stdio сервере: {e}")
		raise 