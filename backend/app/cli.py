"""Console entrypoint: `sentinelscan` launches the local API server."""

from __future__ import annotations

import uvicorn

from backend.app.config import settings


def main() -> None:
    uvicorn.run(
        "backend.app.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
