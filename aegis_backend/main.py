"""
AEGIS Backend FastAPI Application Entrypoint.
Coordinates HTTP API routing, CORS policies, safe exception handling,
and repository dependency injection.
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from aegis_backend.config import settings
from aegis_backend.schemas import ErrorResponse
from aegis_backend.routers import health, system, hosts, alerts, telemetry, security_checker, incidents
from aegis_backend.state_machine import state_machine, DatabaseState

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis_backend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to run startup, background tasks, and shutdown procedures."""
    logger.info("Initializing AEGIS Backend in database mode: %s", settings.database_mode)
    mirror_worker_task = None

    if settings.database_mode == "cloud_ssot":
        # 1. Startup immediate catch-up replay and unmirrored scan
        try:
            from aegis_backend.repository import get_repository
            repo = get_repository()
            if hasattr(repo, "replay_failed_mirrors"):
                res = repo.replay_failed_mirrors()
                if res.get("replayed", 0) > 0:
                    logger.info("Startup mirror replay recovered %d records: %s", res.get("replayed"), res)
            if hasattr(repo, "catch_up_unmirrored_from_cloud"):
                catch_res = repo.catch_up_unmirrored_from_cloud()
                if catch_res.get("caught_up", 0) > 0:
                    logger.info("Startup mirror catch-up recovered %d unmirrored records: %s", catch_res.get("caught_up"), catch_res)
            
            state_machine.transition_to(DatabaseState.CLOUD_SSoT, "Startup catch-up and mirror replay successfully completed", force=True)
            state_machine.set_catch_up_completed(True)
        except Exception as e:
            logger.critical("Startup consistency catch-up encountered fatal error: %s", e)
            state_machine.transition_to(
                DatabaseState.RECOVERY_REQUIRED,
                reason=f"Startup catch-up failed: {e}",
                error_message=str(e),
                force=True,
            )
            state_machine.set_catch_up_completed(False)

        # 2. Continuous background worker for mirror recovery (every 60s)
        async def _periodic_mirror_worker():
            import asyncio
            while True:
                try:
                    await asyncio.sleep(60)
                    repo = get_repository()
                    if hasattr(repo, "replay_failed_mirrors"):
                        res = repo.replay_failed_mirrors()
                        if res.get("replayed", 0) > 0:
                            logger.info("Background mirror worker recovered %d records: %s", res.get("replayed"), res)
                    if hasattr(repo, "catch_up_unmirrored_from_cloud"):
                        catch_res = repo.catch_up_unmirrored_from_cloud()
                        if catch_res.get("caught_up", 0) > 0:
                            logger.info("Background mirror worker caught up %d unmirrored records: %s", catch_res.get("caught_up"), catch_res)
                except asyncio.CancelledError:
                    break
                except Exception as ex:
                    logger.debug("Background mirror worker non-critical error: %s", ex)

        import asyncio
        mirror_worker_task = asyncio.create_task(_periodic_mirror_worker())
    else:
        state_machine.transition_to(DatabaseState.HYBRID, "Running in local Hybrid mode", force=True)

    yield

    if mirror_worker_task:
        mirror_worker_task.cancel()
        try:
            await mirror_worker_task
        except Exception:
            pass

    logger.info("Shutting down AEGIS Backend...")

# Create FastAPI app
app = FastAPI(
    title="AEGIS Backend API",
    description="AI-Powered Linux Security Monitoring and Incident Investigation API",
    version="0.1.0",
    lifespan=lifespan,
)

@app.middleware("http")
async def enforce_database_state_gate(request: Request, call_next):
    """
    Traffic gate enforcing strict fail-closed and consistency:
    Rejects mutating requests (POST, PUT, PATCH, DELETE) with HTTP 503 if the database
    is in a non-operational or recovery-required state.
    """
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        path = request.url.path
        # Allow health checks and internal test overrides
        if not path.startswith("/api/health"):
            if not state_machine.is_mutation_allowed():
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "error": "Database Mutation Rejected",
                        "detail": f"System is currently in '{state_machine.current_state.value}' state. Mutations are suspended.",
                        "state": state_machine.current_state.value,
                        "reason": state_machine.reason,
                        "authoritative_database": state_machine.get_authoritative_database(),
                    },
                )
    return await call_next(request)


# CORS Middleware (Allows frontend development on Vite default ports)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Safe Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Prevents stack traces and sensitive database credentials from leaking into HTTP responses."""
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="InternalServerError",
            message="An unexpected server error occurred. Details have been logged securely.",
            code="INTERNAL_ERROR",
        ).model_dump(),
    )


# Register Routers
app.include_router(health.router)
app.include_router(system.router)
app.include_router(hosts.router)
app.include_router(alerts.router)
app.include_router(telemetry.router)
app.include_router(security_checker.router)
app.include_router(incidents.router)


@app.get("/", include_in_schema=False)
def root_redirect():
    return {
        "service": "AEGIS Security Monitoring Backend",
        "status": "online",
        "version": "0.1.0",
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "aegis_backend.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=(settings.aegis_env == "development"),
    )
