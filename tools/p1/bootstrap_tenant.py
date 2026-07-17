#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import UUID, uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "apps" / "control-plane" / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from vulnlab.enterprise.repository import EnterpriseRepository  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "One-time P1 tenant and administrator bootstrap. "
            "Run from a protected operator workstation and retain the output in an audit record."
        )
    )
    parser.add_argument("--tenant-id", type=UUID, default=None)
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument("--tenant-name", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--email")
    parser.add_argument(
        "--bootstrap-role",
        choices=("tenant_admin", "platform_admin"),
        default="tenant_admin",
    )
    parser.add_argument("--database-url-env", default="DATABASE_URL")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    database_url = os.getenv(args.database_url_env)
    if not database_url:
        raise SystemExit(f"{args.database_url_env} must contain the application PostgreSQL URL")
    tenant_id = args.tenant_id or uuid4()
    repository = EnterpriseRepository(database_url, min_size=1, max_size=2)
    try:
        user_id, assignment_id = repository.bootstrap_tenant(
            tenant_id=tenant_id,
            tenant_slug=args.tenant_slug,
            tenant_name=args.tenant_name,
            issuer=args.issuer.rstrip("/"),
            subject=args.subject,
            username=args.username,
            email=args.email,
            bootstrap_role=args.bootstrap_role,
        )
    finally:
        repository.close()
    print(
        json.dumps(
            {
                "tenant_id": str(tenant_id),
                "user_id": str(user_id),
                "role_assignment_id": str(assignment_id),
                "bootstrap_role": args.bootstrap_role,
                "next_step": "disable bootstrap access and authenticate through OIDC",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
