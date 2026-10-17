from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from db_gateway.metadata import connect, migrate
from db_gateway.settings import get_settings


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    conn = await connect(get_settings().metadata_db_path)
    try:
        await migrate(conn)
        app.state.metadata = conn
        yield
    finally:
        await conn.close()


def create_app() -> FastAPI:
    app = FastAPI(lifespan=_lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
