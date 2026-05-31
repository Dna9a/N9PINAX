# backend/__main__.py
# Run the API with: ``python -m backend``.

from __future__ import annotations

import logging

import uvicorn

from scanner.config import get_config


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    cfg = get_config()
    uvicorn.run(
        "backend.app:app",
        host=cfg.api_host,
        port=cfg.api_port,
        reload=False,
        # IMPORTANT: keep workers=1. The SSE EventBus (backend/events.py) is an
        # in-process asyncio pub/sub — multiple workers would each hold their own
        # bus, so SSE clients on one worker would miss events published by another.
        # Migrate the bus to Redis Pub/Sub before scaling past a single worker.
        workers=1,
        log_level="info",
    )


if __name__ == "__main__":
    main()
