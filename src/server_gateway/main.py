from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from pydantic import BaseModel

from . import __version__
from .auth import AuthContext, authenticate_request
from .config import Settings
from .state import RateLimiter, ReplayStore


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    auth_mode: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.load()
    settings.state_db_path.parent.mkdir(parents=True, exist_ok=True)
    app.state.settings = settings
    app.state.replay_store = ReplayStore(str(settings.state_db_path), settings.request_id_ttl_seconds)
    app.state.rate_limiter = RateLimiter(settings.rate_limit_per_minute)
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    yield


app = FastAPI(
    title="Server Gateway",
    version=__version__,
    lifespan=lifespan,
)


def _settings(request: Request) -> Settings:
    return request.app.state.settings


async def _auth_dependency(request: Request) -> AuthContext:
    return await authenticate_request(
        request,
        request.app.state.settings,
        request.app.state.replay_store,
        request.app.state.rate_limiter,
    )


@app.get("/health", response_model=HealthResponse)
async def health(request: Request):
    settings = _settings(request)
    return {
        "status": "ok",
        "service": settings.service_name,
        "auth_mode": settings.auth_mode,
        "version": __version__,
    }
