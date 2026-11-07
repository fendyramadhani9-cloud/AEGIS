"""
AEGIS Backend FastAPI Application Entrypoint.
Coordinates HTTP API routing, CORS policies, safe exception handling,
and repository dependency injection.
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
from aegis_backend.config import settings
from aegis_backend.schemas import ErrorResponse
from aegis_backend.routers import health, system, hosts, alerts, telemetry, operations

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aegis_backend")

# Create FastAPI app
app = FastAPI(
    title="AEGIS Security Monitoring & Incident Investigation Backend",
    description="Official API gateway for AEGIS Linux Security Monitoring Platform.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware (Configurable via AEGIS_CORS_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=("*" not in settings.cors_origins),
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Attaches defensive HTTP security headers to all backend responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


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
app.include_router(operations.router)


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
