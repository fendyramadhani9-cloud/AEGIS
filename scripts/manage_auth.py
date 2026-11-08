#!/usr/bin/env python3
"""
AEGIS Multi-Tenant Administration CLI.

Manages tenants, user credentials, RBAC roles, and tenant-scoped agent tokens.

Usage:
    python scripts/manage_auth.py init-defaults
    python scripts/manage_auth.py add-tenant <id> <name>
    python scripts/manage_auth.py rotate-token <tenant_id>
    python scripts/manage_auth.py list-tenants
    python scripts/manage_auth.py add-user <username> <password> --tenant <id> --role <superadmin|engineer|viewer>
    python scripts/manage_auth.py reset-password <username> <password>
    python scripts/manage_auth.py delete-user <username>
    python scripts/manage_auth.py list-users
"""

import argparse
import os
import sys

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from aegis_backend.config import settings
from aegis_backend.tenancy import (
    SUPERADMIN_TENANT,
    ROLES,
    get_auth_store,
    get_host_registry,
)


def cmd_init_defaults(args):
    store = get_auth_store()
    if store.has_users() and not args.force:
        print("[!] Auth database already contains users. Use --force to re-initialize.")
        return 1

    print("==================================================================")
    print(" AEGIS ZERO-TRUST INITIALIZATION: MULTI-TENANT & RBAC DEFAULTS")
    print("==================================================================")

    # 1. Superadmin User
    admin_user = args.admin_user or "admin"
    admin_pass = args.admin_pass or "Aegis@CommandHQ2026!"
    store.delete_user(admin_user)
    store.add_user(admin_user, admin_pass, SUPERADMIN_TENANT, "superadmin")
    print(f"\n[+] Superadmin Created:")
    print(f"    Username : {admin_user}")
    print(f"    Password : {admin_pass}")
    print(f"    Tenant   : * (Full Cross-Tenant Visibility / HQ Command)")
    print(f"    Role     : superadmin")

    # 2. Unit Alpha Tenant & Engineer
    t1_id = "unit_alpha"
    t1_name = "Unit Alpha"
    try:
        t1_token = store.add_tenant(t1_id, t1_name)
    except ValueError:
        t1_token = store.rotate_agent_token(t1_id)
    u1_user = "operator_alpha"
    u1_pass = "Alpha@Aegis2026!"
    store.delete_user(u1_user)
    store.add_user(u1_user, u1_pass, t1_id, "engineer")
    print(f"\n[+] Tenant 1 Configured:")
    print(f"    Tenant ID   : {t1_id} ({t1_name})")
    print(f"    Agent Token : {t1_token}")
    print(f"    User        : {u1_user} (Role: engineer)")
    print(f"    Password    : {u1_pass}")
    print(f"    Agent Setup : sudo ./scripts/install_agent.sh --server-url http://<AEGIS_HOST>:8000 --tenant-id {t1_id} --auth-token {t1_token}")

    # 3. Unit Bravo Tenant & Engineer
    t2_id = "unit_bravo"
    t2_name = "Unit Bravo"
    try:
        t2_token = store.add_tenant(t2_id, t2_name)
    except ValueError:
        t2_token = store.rotate_agent_token(t2_id)
    u2_user = "operator_bravo"
    u2_pass = "Bravo@Aegis2026!"
    store.delete_user(u2_user)
    store.add_user(u2_user, u2_pass, t2_id, "engineer")
    print(f"\n[+] Tenant 2 Configured:")
    print(f"    Tenant ID   : {t2_id} ({t2_name})")
    print(f"    Agent Token : {t2_token}")
    print(f"    User        : {u2_user} (Role: engineer)")
    print(f"    Password    : {u2_pass}")
    print(f"    Agent Setup : sudo ./scripts/install_agent.sh --server-url http://<AEGIS_HOST>:8000 --tenant-id {t2_id} --auth-token {t2_token}")

    print("\n[V] Initialization complete. Auth store written to:", settings.auth_file)
    print("    Isolation guarantee: operator_alpha will NEVER see hosts, alerts, or telemetry from operator_bravo.")
    return 0


def cmd_add_tenant(args):
    store = get_auth_store()
    try:
        token = store.add_tenant(args.tenant_id, args.name)
        print(f"[+] Tenant '{args.tenant_id}' created successfully.")
        print(f"    Name        : {args.name}")
        print(f"    Agent Token : {token}")
        print(f"\n[i] Deploy agents for this tenant using:")
        print(f"    sudo ./scripts/install_agent.sh --tenant-id {args.tenant_id} --auth-token {token}")
        return 0
    except ValueError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


def cmd_rotate_token(args):
    store = get_auth_store()
    try:
        token = store.rotate_agent_token(args.tenant_id)
        print(f"[+] Agent token rotated for tenant '{args.tenant_id}'.")
        print(f"    New Agent Token: {token}")
        print("[!] Existing host agents using the old token will be rejected until /etc/aegis/agent.env is updated.")
        return 0
    except ValueError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


def cmd_list_tenants(args):
    store = get_auth_store()
    tenants = store.list_tenants()
    registry = get_host_registry()
    print(f"\n{'TENANT ID':<20} {'TENANT NAME':<35} {'OWNED HOSTS'}")
    print("-" * 75)
    for t in tenants:
        tid = t["id"]
        hosts = [hid for hid, owner in registry.list_all().items() if owner == tid]
        host_count = f"{len(hosts)} hosts ({', '.join(hosts[:3])}{'...' if len(hosts) > 3 else ''})" if hosts else "0 hosts"
        print(f"{tid:<20} {t['name']:<35} {host_count}")
    print()
    return 0


def cmd_add_user(args):
    store = get_auth_store()
    try:
        store.add_user(args.username, args.password, args.tenant, args.role)
        print(f"[+] User '{args.username}' created successfully.")
        print(f"    Tenant : {args.tenant}")
        print(f"    Role   : {args.role}")
        return 0
    except ValueError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


def cmd_reset_password(args):
    store = get_auth_store()
    try:
        store.set_password(args.username, args.password)
        print(f"[+] Password reset successfully for '{args.username}'.")
        return 0
    except (ValueError, AttributeError) as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        return 1


def cmd_delete_user(args):
    store = get_auth_store()
    if store.delete_user(args.username):
        print(f"[+] User '{args.username}' deleted.")
        return 0
    else:
        print(f"[-] User '{args.username}' not found.", file=sys.stderr)
        return 1


def cmd_list_users(args):
    store = get_auth_store()
    users = store.list_users()
    print(f"\n{'USERNAME':<25} {'TENANT':<20} {'ROLE':<15}")
    print("-" * 65)
    for u in users:
        print(f"{u['username']:<25} {u['tenant']:<20} {u['role']:<15}")
    print()
    return 0


def main():
    parser = argparse.ArgumentParser(description="AEGIS Authentication & Multi-Tenant Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init-defaults
    p_init = subparsers.add_parser("init-defaults", help="Seed default superadmin and sample battalion tenants/users")
    p_init.add_argument("--force", action="store_true", help="Force re-initialization even if users exist")
    p_init.add_argument("--admin-user", default="admin", help="Custom superadmin username (default: admin)")
    p_init.add_argument("--admin-pass", default="Aegis@CommandHQ2026!", help="Custom superadmin password")
    p_init.set_defaults(func=cmd_init_defaults)

    # add-tenant
    p_at = subparsers.add_parser("add-tenant", help="Create a new isolated tenant")
    p_at.add_argument("tenant_id", help="Alphanumeric tenant identifier (e.g. batalyon3, perum_gas)")
    p_at.add_argument("name", help="Display name of the tenant or organization")
    p_at.set_defaults(func=cmd_add_tenant)

    # rotate-token
    p_rt = subparsers.add_parser("rotate-token", help="Rotate agent ingestion token for a tenant")
    p_rt.add_argument("tenant_id", help="Tenant ID")
    p_rt.set_defaults(func=cmd_rotate_token)

    # list-tenants
    p_lt = subparsers.add_parser("list-tenants", help="List all tenants and their assigned hosts")
    p_lt.set_defaults(func=cmd_list_tenants)

    # add-user
    p_au = subparsers.add_parser("add-user", help="Register a new user bound to a tenant and role")
    p_au.add_argument("username", help="Username")
    p_au.add_argument("password", help="Password (minimum 10 characters)")
    p_au.add_argument("--tenant", required=True, help="Tenant ID ('*' for superadmin)")
    p_au.add_argument("--role", required=True, choices=ROLES, help="Role: superadmin, engineer, viewer")
    p_au.set_defaults(func=cmd_add_user)

    # reset-password
    p_rp = subparsers.add_parser("reset-password", help="Reset password for an existing user")
    p_rp.add_argument("username", help="Username")
    p_rp.add_argument("password", help="New password (minimum 10 characters)")
    p_rp.set_defaults(func=cmd_reset_password)

    # delete-user
    p_du = subparsers.add_parser("delete-user", help="Remove an operator user")
    p_du.add_argument("username", help="Username")
    p_du.set_defaults(func=cmd_delete_user)

    # list-users
    p_lu = subparsers.add_parser("list-users", help="List registered users, tenants, and roles")
    p_lu.set_defaults(func=cmd_list_users)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)

