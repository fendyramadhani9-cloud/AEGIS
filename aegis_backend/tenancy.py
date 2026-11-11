"""
AEGIS Authentication, RBAC & Hard Multi-Tenant Isolation.

Threat model: "this is my host, that is yours, you must never see mine."

Isolation is enforced SERVER-SIDE at three independent layers (never only in the UI):

1. Gateway (deny-by-default middleware): every /api/* route requires a valid signed session token
   unless explicitly whitelisted (health, login, agent-token endpoints).
2. Data layer (`TenantScopedRepository`): every read/write that a logged-in user can trigger goes through a
   repository wrapper that hides rows belonging to other tenants. Cross-tenant lookups by ID behave exactly
   like "not found" (404), so tenants cannot even probe for the existence of each other's resources.
3. Ingestion (`HostTenantRegistry`): each tenant owns its own agent token. A host is bound to the tenant that
   first reported it (first-claim wins); any other tenant attempting to report for / spoof that host is rejected.

Roles:
- superadmin : tenant "*" — sees every tenant (command HQ / platform owner).
- engineer   : bound to exactly one tenant — read + operate within that tenant.
- viewer     : bound to exactly one tenant — strictly read-only (all mutating HTTP methods blocked).

Secrets handling: passwords are PBKDF2-HMAC-SHA256 hashed (200k iterations, per-user salt); agent tokens are
stored only as SHA-256 digests; session tokens are HMAC-SHA256 signed, short-lived and revocable on logout.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from aegis_backend.config import settings
from aegis_backend.repository import BaseAegisRepository, get_repository

logger = logging.getLogger("aegis_backend.tenancy")

SUPERADMIN_TENANT = "*"
ROLES = ("superadmin", "engineer", "viewer")
_TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$")
_PBKDF2_ITERATIONS = 200_000
_MAX_DRAIN_ROWS = 20_000


# ==============================================================================
# 1. USER MODEL
# ==============================================================================

@dataclass(frozen=True)
class AuthUser:
    username: str
    tenant: str
    role: str

    @property
    def is_super(self) -> bool:
        return self.role == "superadmin" and self.tenant == SUPERADMIN_TENANT


# Identity used only when AEGIS_AUTH_ENABLED=false (local development / automated tests).
DEV_USER = AuthUser(username="anonymous-dev", tenant=SUPERADMIN_TENANT, role="superadmin")


# ==============================================================================
# 2. PASSWORD & TOKEN PRIMITIVES
# ==============================================================================

def hash_password(password: str, *, iterations: int = _PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password_hash(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# Pre-computed hash used to equalize timing when a username does not exist (anti user-enumeration).
_DUMMY_HASH = hash_password("aegis-timing-equalizer")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


_RUNTIME_SECRET = secrets.token_bytes(32)
_SECRET_KEY_PATH = Path(settings.auth_file).parent / ".auth_secret.key"
_REVOKED_TOKENS_PATH = Path(settings.auth_file).parent / ".revoked_tokens.json"
_revoked_jti: Dict[str, int] = {}
_revoked_lock = threading.Lock()


def _get_persistent_secret() -> bytes:
    if settings.auth_secret:
        return settings.auth_secret.encode("utf-8")
    try:
        if _SECRET_KEY_PATH.exists():
            content = _SECRET_KEY_PATH.read_bytes()
            if len(content) >= 32:
                return content
        _SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        new_secret = secrets.token_bytes(32)
        tmp = _SECRET_KEY_PATH.with_suffix(".tmp")
        tmp.write_bytes(new_secret)
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(_SECRET_KEY_PATH)
        return new_secret
    except Exception as e:
        logger.warning(f"Could not persist auth secret, falling back to runtime secret: {e}")
        return _RUNTIME_SECRET


def _signing_key() -> bytes:
    return _get_persistent_secret()


def _sync_revoked_tokens() -> None:
    now = int(time.time())
    if _REVOKED_TOKENS_PATH.exists():
        try:
            data = json.loads(_REVOKED_TOKENS_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for jti, exp in data.items():
                    if exp > now:
                        _revoked_jti[jti] = int(exp)
        except Exception:
            pass


def _persist_revoked_tokens() -> None:
    now = int(time.time())
    try:
        active = {jti: exp for jti, exp in _revoked_jti.items() if exp > now}
        tmp = _REVOKED_TOKENS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(active), encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(_REVOKED_TOKENS_PATH)
    except Exception as e:
        logger.debug(f"Failed to persist revoked tokens: {e}")


def issue_token(user: AuthUser) -> Tuple[str, int]:
    """Returns (signed_token, ttl_seconds)."""
    ttl = settings.token_ttl_min * 60
    payload = {
        "sub": user.username,
        "tnt": user.tenant,
        "rol": user.role,
        "exp": int(time.time()) + ttl,
        "jti": secrets.token_hex(8),
    }
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64u(hmac.new(_signing_key(), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}", ttl


def decode_token(token: str) -> Dict[str, Any]:
    """Validates signature, expiry and revocation. Raises ValueError on any failure."""
    try:
        body, sig = token.split(".")
    except ValueError:
        raise ValueError("malformed token")
    expected = _b64u(hmac.new(_signing_key(), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise ValueError("bad signature")
    payload = json.loads(_b64u_decode(body))
    now = int(time.time())
    if int(payload.get("exp", 0)) <= now:
        raise ValueError("expired")
    jti = payload.get("jti")
    if jti in _revoked_jti:
        raise ValueError("revoked")
    _sync_revoked_tokens()
    if jti in _revoked_jti:
        raise ValueError("revoked")
    if payload.get("rol") not in ROLES or not payload.get("sub") or not payload.get("tnt"):
        raise ValueError("invalid claims")
    return payload


def revoke_token(token: str) -> None:
    try:
        payload = decode_token(token)
    except ValueError:
        return
    with _revoked_lock:
        now = int(time.time())
        _sync_revoked_tokens()
        for jti in [j for j, exp in _revoked_jti.items() if exp <= now]:
            _revoked_jti.pop(jti, None)
        _revoked_jti[payload["jti"]] = int(payload["exp"])
        _persist_revoked_tokens()


# ==============================================================================
# 3. AUTH STORE (tenants, users, agent tokens)
# ==============================================================================

def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


class AuthStore:
    """File-backed registry of tenants, users and agent-token digests (hot-reloads on file change)."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._lock = threading.RLock()
        self._mtime: Optional[float] = None
        self._data: Dict[str, Any] = {"tenants": {}, "users": {}}

    def _reload_if_changed(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            self._data = {"tenants": {}, "users": {}}
            self._mtime = None
            return
        if mtime == self._mtime:
            return
        try:
            loaded = json.loads(self._path.read_text(encoding="utf-8"))
            self._data = {
                "tenants": dict(loaded.get("tenants", {})),
                "users": dict(loaded.get("users", {})),
            }
            self._mtime = mtime
        except Exception as e:
            logger.error("Failed to load auth file %s: %s", self._path, type(e).__name__)

    def _save(self) -> None:
        _atomic_write_json(self._path, self._data)
        self._mtime = self._path.stat().st_mtime

    # ---- queries -------------------------------------------------------------
    def has_users(self) -> bool:
        with self._lock:
            self._reload_if_changed()
            return bool(self._data["users"])

    def tenant_exists(self, tenant_id: str) -> bool:
        with self._lock:
            self._reload_if_changed()
            return tenant_id == settings.default_tenant or tenant_id in self._data["tenants"]

    def tenant_name(self, tenant_id: str) -> str:
        if tenant_id == SUPERADMIN_TENANT:
            return "Global Security Operations (All Clusters)"
        with self._lock:
            self._reload_if_changed()
            return self._data["tenants"].get(tenant_id, {}).get("name") or tenant_id

    def list_tenants(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._reload_if_changed()
            return [
                {"id": tid, "name": t.get("name", tid)} for tid, t in sorted(self._data["tenants"].items())
            ]

    def list_users(self) -> List[Dict[str, str]]:
        with self._lock:
            self._reload_if_changed()
            return [
                {"username": u["username"], "tenant": u["tenant"], "role": u["role"]}
                for _, u in sorted(self._data["users"].items())
            ]

    def authenticate(self, username: str, password: str) -> Optional[AuthUser]:
        with self._lock:
            self._reload_if_changed()
            record = self._data["users"].get(username.strip().lower())
        stored = record["password_hash"] if record else _DUMMY_HASH
        ok = verify_password_hash(password, stored)
        if not record or not ok:
            return None
        return AuthUser(username=record["username"], tenant=record["tenant"], role=record["role"])

    def resolve_agent_token(self, token: str) -> Optional[str]:
        """Maps a tenant-scoped agent token to its tenant id (constant-time digest comparison)."""
        digest = _sha256_hex(token)
        with self._lock:
            self._reload_if_changed()
            tenants = dict(self._data["tenants"])
        found: Optional[str] = None
        for tid, t in tenants.items():
            if hmac.compare_digest(digest, t.get("agent_token_sha256", "")):
                found = tid
        return found

    # ---- mutations (used by scripts/manage_auth.py) ----------------------------
    @staticmethod
    def new_agent_token() -> str:
        return "aegis_agt_" + secrets.token_urlsafe(32)

    def add_tenant(self, tenant_id: str, name: str) -> str:
        tenant_id = tenant_id.strip().lower()
        if not _TENANT_ID_RE.match(tenant_id):
            raise ValueError("Tenant id must be 2-48 chars: lowercase letters, digits, '-' or '_'.")
        with self._lock:
            self._reload_if_changed()
            if tenant_id in self._data["tenants"]:
                raise ValueError(f"Tenant '{tenant_id}' already exists.")
            token = self.new_agent_token()
            self._data["tenants"][tenant_id] = {"name": name.strip() or tenant_id, "agent_token_sha256": _sha256_hex(token)}
            self._save()
            return token

    def rotate_agent_token(self, tenant_id: str) -> str:
        with self._lock:
            self._reload_if_changed()
            if tenant_id not in self._data["tenants"]:
                raise ValueError(f"Tenant '{tenant_id}' does not exist.")
            token = self.new_agent_token()
            self._data["tenants"][tenant_id]["agent_token_sha256"] = _sha256_hex(token)
            self._save()
            return token

    def add_user(self, username: str, password: str, tenant: str, role: str) -> None:
        if not _USERNAME_RE.match(username):
            raise ValueError("Username must be 2-64 chars (letters, digits, '.', '_', '-').")
        if role not in ROLES:
            raise ValueError(f"Role must be one of: {', '.join(ROLES)}.")
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters.")
        tenant = tenant.strip().lower() if tenant != SUPERADMIN_TENANT else tenant
        if role == "superadmin" and tenant != SUPERADMIN_TENANT:
            raise ValueError("Role 'superadmin' must use tenant '*'.")
        if role != "superadmin" and tenant == SUPERADMIN_TENANT:
            raise ValueError("Only role 'superadmin' may use tenant '*'.")
        with self._lock:
            self._reload_if_changed()
            if tenant != SUPERADMIN_TENANT and not self.tenant_exists(tenant):
                raise ValueError(f"Tenant '{tenant}' does not exist. Create it first.")
            key = username.strip().lower()
            if key in self._data["users"]:
                raise ValueError(f"User '{username}' already exists.")
            self._data["users"][key] = {
                "username": username,
                "tenant": tenant,
                "role": role,
                "password_hash": hash_password(password),
            }
            self._save()

    def set_password(self, username: str, password: str) -> None:
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters.")
        with self._lock:
            self._reload_if_changed()
            key = username.strip().lower()
            if key not in self._data["users"]:
                raise ValueError(f"User '{username}' does not exist.")
            self._data["users"][key]["password_hash"] = hash_password(password)
            self._save()

    def delete_user(self, username: str) -> bool:
        with self._lock:
            self._reload_if_changed()
            removed = self._data["users"].pop(username.strip().lower(), None)
            if removed:
                self._save()
            return bool(removed)


_auth_store: Optional[AuthStore] = None
_auth_store_lock = threading.Lock()


def get_auth_store() -> AuthStore:
    global _auth_store
    with _auth_store_lock:
        if _auth_store is None or str(_auth_store._path) != settings.auth_file:
            _auth_store = AuthStore(settings.auth_file)
        return _auth_store


# ==============================================================================
# 4. HOST OWNERSHIP REGISTRY (host -> tenant)
# ==============================================================================

class HostOwnershipError(Exception):
    pass


class HostTenantRegistry:
    """
    Persistent host -> tenant binding. First-claim wins; unbound legacy hosts belong to the default tenant.
    """

    def __init__(self, path: str):
        self._path = Path(path)
        self._lock = threading.RLock()
        self._mtime: Optional[float] = None
        self._map: Dict[str, str] = {}

    def _reload_if_changed(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except FileNotFoundError:
            self._map, self._mtime = {}, None
            return
        if mtime == self._mtime:
            return
        try:
            self._map = dict(json.loads(self._path.read_text(encoding="utf-8")).get("hosts", {}))
            self._mtime = mtime
        except Exception as e:
            logger.error("Failed to load host-tenant registry: %s", type(e).__name__)

    def owner(self, host_id: Optional[str]) -> str:
        if not host_id:
            return settings.default_tenant
        with self._lock:
            self._reload_if_changed()
            return self._map.get(host_id, settings.default_tenant)

    def is_bound(self, host_id: str) -> bool:
        with self._lock:
            self._reload_if_changed()
            return host_id in self._map

    def list_all(self) -> Dict[str, str]:
        with self._lock:
            self._reload_if_changed()
            return dict(self._map)

    def claim(self, host_id: str, tenant: str, *, exists_in_repo: bool) -> None:
        """
        Binds an unbound host to `tenant`, or verifies the existing owner.
        Raises HostOwnershipError if another tenant owns the host.
        """
        with self._lock:
            self._reload_if_changed()
            current = self._map.get(host_id)
            if current is not None:
                if current != tenant:
                    raise HostOwnershipError(host_id)
                return
            # Unbound host that already exists is a legacy host owned by the default tenant.
            if exists_in_repo and tenant != settings.default_tenant:
                raise HostOwnershipError(host_id)
            if tenant == settings.default_tenant and exists_in_repo:
                return  # implicit ownership, no need to persist
            self._map[host_id] = tenant
            _atomic_write_json(self._path, {"hosts": self._map})
            self._mtime = self._path.stat().st_mtime


_registry: Optional[HostTenantRegistry] = None
_registry_lock = threading.Lock()


def get_host_registry() -> HostTenantRegistry:
    global _registry
    with _registry_lock:
        if _registry is None or str(_registry._path) != settings.host_tenant_file:
            _registry = HostTenantRegistry(settings.host_tenant_file)
        return _registry


# ==============================================================================
# 5. AGENT AUTHENTICATION & HOST CLAIMING
# ==============================================================================

def authenticate_agent_token(x_agent_token: Optional[str]) -> str:
    """
    Validates an agent token and returns the tenant it belongs to.
    - Tenant-scoped tokens (issued via manage_auth.py) -> that tenant.
    - Legacy global AGENT_INGEST_TOKEN -> the default tenant.
    """
    if not x_agent_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required authentication token header: X-Agent-Token",
        )
    tenant = get_auth_store().resolve_agent_token(x_agent_token)
    if tenant:
        return tenant
    expected = settings.agent_ingest_token
    if not expected:
        logger.error("AGENT_INGEST_TOKEN is not configured on the server.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server ingestion authentication is misconfigured.",
        )
    if hmac.compare_digest(x_agent_token.encode("utf-8"), expected.encode("utf-8")):
        return settings.default_tenant
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid agent authentication token.",
    )


def agent_token_dependency(
    x_agent_token: Optional[str] = Header(None, alias="X-Agent-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """FastAPI dependency: returns the tenant id of the authenticated agent."""
    token = x_agent_token
    if not token and authorization:
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
        else:
            token = authorization.strip()
    return authenticate_agent_token(token)


def claim_host_for_agent(host_id: str, tenant: str, repo: BaseAegisRepository) -> None:
    """Enforces that an agent may only write data for hosts owned by its own tenant."""
    try:
        exists = repo.get_host_by_id(host_id) is not None
    except Exception:
        exists = False
    try:
        get_host_registry().claim(host_id, tenant, exists_in_repo=exists)
    except HostOwnershipError:
        owner = get_host_registry().owner(host_id)
        logger.warning("Rejected cross-tenant host claim: host='%s' tenant='%s' (owner='%s')", host_id, tenant, owner)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Host is owned by tenant '{owner}'. Request rejected.",
        )


# ==============================================================================
# 6. SESSION AUTHENTICATION (dashboard / mobile app users)
# ==============================================================================

def _bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get("authorization", "")
    parts = header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
        return parts[1].strip()
    return None


def get_current_user(request: Request) -> AuthUser:
    """FastAPI dependency / helper resolving the authenticated user for the request."""
    if not settings.auth_enabled:
        return DEV_USER
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    token = _bearer_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = decode_token(token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = AuthUser(username=claims["sub"], tenant=claims["tnt"], role=claims["rol"])
    request.state.user = user
    return user


_PUBLIC_EXACT = frozenset(
    {
        "/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/health",
        "/api/auth/login",
        "/api/security-checker/health",
        "/api/security-checker/agent-results",  # authenticated by X-Agent-Token dependency
    }
)
_PUBLIC_PREFIXES = ("/api/telemetry/",)  # every telemetry route is authenticated by X-Agent-Token
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _is_public_path(path: str) -> bool:
    return path in _PUBLIC_EXACT or path.startswith(_PUBLIC_PREFIXES)


# Per-request identity, readable from worker threads (used to stamp the audit trail with the real actor/tenant).
current_user_var: ContextVar[Optional[AuthUser]] = ContextVar("aegis_current_user", default=None)


def infer_audit_tenant(target_type: str, target_id: str, details: Optional[Dict[str, Any]]) -> Optional[str]:
    """Best-effort tenant tag for audit entries produced outside a user session (e.g. by agents)."""
    host_id = (details or {}).get("host_id")
    if not host_id and target_type == "host":
        host_id = target_id
    if host_id:
        return get_host_registry().owner(host_id)
    return None


async def auth_gate_middleware(request: Request, call_next):
    """Deny-by-default gateway: all /api routes need a valid session unless whitelisted."""
    path = request.url.path
    if (
        not settings.auth_enabled
        or request.method == "OPTIONS"
        or not path.startswith("/api")
        or _is_public_path(path)
    ):
        return await call_next(request)

    try:
        user = get_current_user(request)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers)

    if user.role == "viewer" and request.method in _MUTATING_METHODS and path != "/api/auth/logout":
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Read-only account: this action is not permitted for the 'viewer' role."},
        )
    current_user_var.set(user)
    return await call_next(request)


# ==============================================================================
# 7. LOGIN BRUTE-FORCE PROTECTION
# ==============================================================================

def extract_client_ip(request: Request) -> str:
    """Safely resolves client IP, prioritizing X-Forwarded-For / X-Real-IP behind reverse proxy."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip and x_real_ip.strip():
        return x_real_ip.strip()
    return request.client.host if request.client else "unknown"


_LOGIN_MAX_FAILURES = 5
_LOGIN_WINDOW_SEC = 300
_LOGIN_LOCK_SEC = 60
_login_state: Dict[str, Dict[str, float]] = {}
_login_lock = threading.Lock()


def _login_key(ip: str, username: str) -> str:
    return f"{ip}|{username.strip().lower()}"


def login_lock_remaining(ip: str, username: str) -> int:
    with _login_lock:
        st = _login_state.get(_login_key(ip, username))
        if not st:
            return 0
        return max(0, int(st.get("locked_until", 0) - time.time()))


def register_login_failure(ip: str, username: str) -> None:
    now = time.time()
    with _login_lock:
        key = _login_key(ip, username)
        st = _login_state.get(key)
        if not st or now - st["first"] > _LOGIN_WINDOW_SEC:
            st = {"count": 0, "first": now, "locked_until": 0}
        st["count"] += 1
        if st["count"] >= _LOGIN_MAX_FAILURES:
            st["locked_until"] = now + _LOGIN_LOCK_SEC
            st["count"] = 0
            st["first"] = now
        _login_state[key] = st
        if len(_login_state) > 5000:  # bound memory
            for k in [k for k, v in _login_state.items() if now - v["first"] > _LOGIN_WINDOW_SEC and v["locked_until"] < now]:
                _login_state.pop(k, None)


def clear_login_failures(ip: str, username: str) -> None:
    with _login_lock:
        _login_state.pop(_login_key(ip, username), None)


def reset_login_state_for_tests() -> None:
    with _login_lock:
        _login_state.clear()
    with _revoked_lock:
        _revoked_jti.clear()


# ==============================================================================
# 8. TENANT-SCOPED REPOSITORY (data-layer isolation)
# ==============================================================================

class TenantScopedRepository(BaseAegisRepository):
    """
    Repository view restricted to hosts owned by one tenant.
    Anything outside the tenant behaves as if it does not exist (reads) or is refused (writes).
    """

    def __init__(self, base: BaseAegisRepository, tenant: str):
        self._base = base
        self._tenant = tenant
        self._registry = get_host_registry()

    # ---- helpers ---------------------------------------------------------------
    def _ok(self, host_id: Optional[str]) -> bool:
        return bool(host_id) and self._registry.owner(host_id) == self._tenant

    def _require(self, host_id: Optional[str]) -> None:
        if not self._ok(host_id):
            raise PermissionError("Access to this host is not permitted for the current tenant.")

    def _visible_host_ids(self) -> List[str]:
        reg_hosts = [hid for hid, owner in self._registry.list_all().items() if owner == self._tenant]
        if reg_hosts:
            return reg_hosts
        rows = self._drain(self._base.list_hosts)
        return [h["id"] for h in rows if self._ok(h.get("id"))]

    @staticmethod
    def _drain(fn, **kwargs) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        offset, chunk = 0, 500
        while offset < _MAX_DRAIN_ROWS:
            rows, total = fn(limit=chunk, offset=offset, **kwargs)
            out.extend(rows)
            offset += chunk
            if not rows or offset >= total:
                break
        return out

    def _paged(self, fn, limit: int, offset: int, host_id: Optional[str], **filters):
        """Lists host-bound rows, restricted to the tenant, with correct total & pagination."""
        if host_id:
            if not self._ok(host_id):
                return [], 0
            return fn(limit=limit, offset=offset, host_id=host_id, **filters)
        visible_set = set(self._visible_host_ids())
        if not visible_set:
            return [], 0
        rows = [r for r in self._drain(fn, **filters) if r.get("host_id") in visible_set]
        return rows[offset : offset + limit], len(rows)

    def _incident_ok(self, incident_id: str) -> bool:
        inc = self._base.get_incident_by_id(incident_id)
        return bool(inc) and self._ok(inc.get("host_id"))

    # ---- platform / admin (not tenant data) ------------------------------------
    def check_database_health(self):
        return self._base.check_database_health()

    def get_system_status(self):
        return self._base.get_system_status()

    def get_mirror_sync_stats(self) -> Dict[str, Any]:
        raise PermissionError("Platform administration is restricted to superadmin.")

    def replay_failed_mirrors(self) -> Dict[str, Any]:
        raise PermissionError("Platform administration is restricted to superadmin.")

    def catch_up_unmirrored_from_cloud(self, batch_size: int = 100) -> Dict[str, Any]:
        raise PermissionError("Platform administration is restricted to superadmin.")

    # ---- hosts -----------------------------------------------------------------
    def list_hosts(self, limit: int = 20, offset: int = 0, status: Optional[str] = None):
        rows = [h for h in self._drain(self._base.list_hosts, status=status) if self._ok(h.get("id"))]
        return rows[offset : offset + limit], len(rows)

    def get_host_by_id(self, host_id: str):
        return self._base.get_host_by_id(host_id) if self._ok(host_id) else None

    def upsert_host(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        self._require(host_data.get("id"))
        return self._base.upsert_host(host_data)

    # ---- telemetry & alerts ----------------------------------------------------
    def insert_telemetry_events(self, events: List[Dict[str, Any]]):
        for ev in events:
            self._require(ev.get("host_id"))
        return self._base.insert_telemetry_events(events)

    def list_alerts(self, limit: int = 20, offset: int = 0, host_id: Optional[str] = None, severity: Optional[str] = None):
        return self._paged(self._base.list_alerts, limit, offset, host_id, severity=severity)

    def get_alert_by_id(self, alert_id: str):
        alert = self._base.get_alert_by_id(alert_id)
        return alert if alert and self._ok(alert.get("host_id")) else None

    def get_alert_evidence(self, alert_id: str):
        alert = self._base.get_alert_by_id(alert_id)
        if not alert or not self._ok(alert.get("host_id")):
            return None
        return self._base.get_alert_evidence(alert_id)

    def insert_alerts(self, alerts: List[Dict[str, Any]], alert_evidence: List[Dict[str, Any]]):
        for a in alerts:
            self._require(a.get("host_id"))
        return self._base.insert_alerts(alerts, alert_evidence)

    # ---- security checker ------------------------------------------------------
    def insert_security_check_run(self, run_data: Dict[str, Any], findings: List[Dict[str, Any]]):
        self._require(run_data.get("host_id"))
        return self._base.insert_security_check_run(run_data, findings)

    def list_security_findings(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ):
        return self._paged(
            self._base.list_security_findings, limit, offset, host_id,
            category=category, severity=severity, status=status, search=search,
        )

    def get_security_finding_by_id(self, finding_id: str):
        f = self._base.get_security_finding_by_id(finding_id)
        return f if f and self._ok(f.get("host_id")) else None

    def list_security_runs(self, limit: int = 20, offset: int = 0, host_id: Optional[str] = None):
        return self._paged(self._base.list_security_runs, limit, offset, host_id)

    def get_security_run_by_id(self, run_id: str):
        r = self._base.get_security_run_by_id(run_id)
        return r if r and self._ok(r.get("host_id")) else None

    def get_host_security_history(self, host_id: str, limit: int = 10):
        return self._base.get_host_security_history(host_id, limit) if self._ok(host_id) else []

    def get_security_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        # Computed from tenant-visible rows only (never trusts a backend-wide aggregate).
        findings, _ = self.list_security_findings(limit=_MAX_DRAIN_ROWS, offset=0, host_id=host_id)
        runs, _ = self.list_security_runs(limit=_MAX_DRAIN_ROWS, offset=0, host_id=host_id)
        runs = sorted(runs, key=lambda r: r.get("started_at") or "", reverse=True)
        last_checked = (runs[0].get("completed_at") or runs[0].get("started_at")) if runs else None

        def n(pred) -> int:
            return sum(1 for f in findings if pred(f))

        def fails(sev: str) -> int:
            return n(lambda f: f.get("status") == "fail" and f.get("severity") == sev)

        if host_id:
            total_hosts = 1 if self._ok(host_id) else 0
        else:
            total_hosts = len(self._visible_host_ids())
        return {
            "total_checks": len(findings),
            "passed": n(lambda f: f.get("status") == "pass"),
            "failed": n(lambda f: f.get("status") == "fail"),
            "warning": n(lambda f: f.get("status") == "warning"),
            "not_applicable": n(lambda f: f.get("status") == "not_applicable"),
            "error": n(lambda f: f.get("status") == "error"),
            "total_hosts": total_hosts,
            "last_checked_at": last_checked,
            "critical_fails": fails("critical"),
            "high_fails": fails("high"),
            "medium_fails": fails("medium"),
            "low_fails": fails("low"),
        }

    # ---- incidents -------------------------------------------------------------
    def get_incident_by_id(self, incident_id: str):
        inc = self._base.get_incident_by_id(incident_id)
        return inc if inc and self._ok(inc.get("host_id")) else None

    def get_incident_risk_factors(self, incident_id: str):
        return self._base.get_incident_risk_factors(incident_id) if self._incident_ok(incident_id) else []

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        host_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
    ):
        return self._paged(
            self._base.list_incidents, limit, offset, host_id,
            status=status, severity=severity, search=search,
        )

    def upsert_incident(self, incident_data: Dict[str, Any], alert_ids: Optional[List[str]] = None):
        self._require(incident_data.get("host_id"))
        return self._base.upsert_incident(incident_data, alert_ids=alert_ids)

    def update_incident_status(self, incident_id: str, status: str, note: Optional[str] = None, operator: str = "admin"):
        if not self._incident_ok(incident_id):
            return None
        return self._base.update_incident_status(incident_id, status, note=note, operator=operator)

    def get_incident_alerts(self, incident_id: str):
        if not self._incident_ok(incident_id):
            return []
        return [a for a in self._base.get_incident_alerts(incident_id) if self._ok(a.get("host_id"))]

    def save_ai_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        self._require(analysis_data.get("host_id"))
        return self._base.save_ai_analysis(analysis_data)

    def get_latest_ai_analysis(self, incident_id: str):
        return self._base.get_latest_ai_analysis(incident_id) if self._incident_ok(incident_id) else None

    def get_incident_timeline(self, incident_id: str):
        return self._base.get_incident_timeline(incident_id) if self._incident_ok(incident_id) else []

    def get_incidents_summary(self, host_id: Optional[str] = None) -> Dict[str, Any]:
        # NOTE: some backends ignore host_id in their native summary, so we aggregate from scoped rows.
        incs, _ = self.list_incidents(limit=_MAX_DRAIN_ROWS, offset=0, host_id=host_id)

        def by_status(*names: str) -> int:
            return sum(1 for i in incs if i.get("status") in names)

        def by_risk(level: str) -> int:
            return sum(1 for i in incs if i.get("risk_level") == level)

        stamps = [i.get("updated_at") or i.get("last_seen_at") for i in incs]
        stamps = [s for s in stamps if s]
        return {
            "total_incidents": len(incs),
            "new_incidents": by_status("new"),
            "open_incidents": by_status("new", "investigating"),
            "investigating": by_status("investigating"),
            "confirmed": by_status("confirmed"),
            "resolved": by_status("resolved"),
            "false_positives": by_status("false_positive"),
            "contained": by_status("contained"),
            "critical_risk": by_risk("critical"),
            "high_risk": by_risk("high"),
            "medium_risk": by_risk("medium"),
            "low_risk": by_risk("low"),
            "total_hosts_affected": len({i.get("host_id") for i in incs if i.get("host_id")}),
            "latest_incident_at": max(stamps) if stamps else None,
            "storage_backend": "tenant_scoped",
        }

    def __getattr__(self, name: str):
        # Any repository capability not explicitly scoped above is refused (secure by default).
        raise AttributeError(f"Repository operation '{name}' is not available to tenant-scoped sessions.")


def get_scoped_repository(request: Request) -> BaseAegisRepository:
    """
    FastAPI dependency replacing `get_repository` for every user-facing route.
    Superadmin (and auth-disabled dev mode) get the full repository; everyone else a tenant-scoped view.
    """
    base = get_repository()
    user = get_current_user(request)
    if user.is_super:
        return base
    return TenantScopedRepository(base, user.tenant)


def get_request_user(request: Request) -> AuthUser:
    """FastAPI dependency exposing the authenticated user to route handlers."""
    return get_current_user(request)


# ==============================================================================
# 9. NON-REPOSITORY SCOPING HELPERS (operational store)
# ==============================================================================

def user_can_access_host(user: AuthUser, host_id: Optional[str]) -> bool:
    if user.is_super:
        return True
    return bool(host_id) and get_host_registry().owner(host_id) == user.tenant


def user_can_access_hosts(user: AuthUser, host_ids: List[str]) -> bool:
    """True only if the list is non-empty and every host is accessible (superadmin: always)."""
    if user.is_super:
        return True
    return bool(host_ids) and all(user_can_access_host(user, h) for h in host_ids)


def actor_for(user: AuthUser, client_supplied: Optional[str]) -> str:
    """
    Identity written to audit trails / investigation notes.
    With authentication on, the verified username always wins over any client-supplied name (no spoofing).
    """
    if user != DEV_USER:
        return user.username
    return client_supplied or "ops-admin"
