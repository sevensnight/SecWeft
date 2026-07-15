from __future__ import annotations

import sqlite3

import pytest
from conftest import make_user
from vulnlab.app import create_app
from vulnlab.db import Database
from vulnlab.scope import ScopeViolation


def test_legacy_database_is_migrated_and_old_approval_fails_closed(tmp_path):
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE users (
          id TEXT PRIMARY KEY, username TEXT UNIQUE, key_hash TEXT UNIQUE, role TEXT, active INTEGER, created_at TEXT
        );
        CREATE TABLE scopes (
          id TEXT PRIMARY KEY, name TEXT UNIQUE, target_pattern TEXT, protocols_json TEXT, ports_json TEXT,
          expires_at TEXT, approved INTEGER, created_by TEXT, created_at TEXT
        );
        CREATE TABLE target_profiles (
          id TEXT PRIMARY KEY, name TEXT UNIQUE, target TEXT, proxy_url TEXT, intent TEXT, indicators_json TEXT,
          scope_id TEXT, created_by TEXT, created_at TEXT
        );
        CREATE TABLE tasks (
          id TEXT PRIMARY KEY, title TEXT, target TEXT, intent TEXT, indicators_json TEXT, scope_id TEXT,
          status TEXT, approval_status TEXT, created_by TEXT, assigned_skills_json TEXT, plan_json TEXT,
          result_json TEXT, error TEXT, created_at TEXT, updated_at TEXT
        );
        CREATE TABLE audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, actor_id TEXT, action TEXT, resource_type TEXT,
          resource_id TEXT, outcome TEXT, details_json TEXT, prev_hash TEXT, entry_hash TEXT UNIQUE
        );
        INSERT INTO users VALUES('u','legacy','hash','analyst',1,'2025-01-01T00:00:00+00:00');
        INSERT INTO scopes VALUES(
          's','legacy-scope','127.0.0.1','["tcp"]','[8000]',NULL,1,'u','2025-01-01T00:00:00+00:00'
        );
        INSERT INTO tasks VALUES(
          't','legacy-task','tcp://127.0.0.1:8000','asset_inventory','[]','s','approved','approved','u','[]',
          NULL,NULL,NULL,'2025-01-01T00:00:00+00:00','2025-01-01T00:00:00+00:00'
        );
        """
    )
    connection.commit()
    connection.close()

    db = Database(path)
    db.initialize()
    scope = db.fetch_one("SELECT * FROM scopes WHERE id='s'")
    task = db.fetch_one("SELECT * FROM tasks WHERE id='t'")
    profile_columns = {row["name"] for row in db.fetch_all("PRAGMA table_info(target_profiles)")}
    assert scope["approved"] == 0
    assert scope["resolved_ips_json"] == "[]"
    assert len(scope["scope_hash"]) == 64
    assert task["status"] == "cancelled"
    assert task["approval_status"] == "revoked"
    assert task["scope_hash"] == scope["scope_hash"]
    assert "proxy_scope_id" in profile_columns


def test_restart_does_not_resign_tampered_approved_scope(client, app, settings, admin_headers):
    _, analyst_headers = make_user(client, admin_headers, "migration-analyst", "analyst")
    created = client.post(
        "/api/v1/scopes",
        headers=analyst_headers,
        json={
            "name": "signed",
            "target_pattern": "127.0.0.1",
            "protocols": ["tcp"],
            "ports": [8000],
        },
    ).json()
    approved = client.post(
        f"/api/v1/scopes/{created['id']}/approve",
        headers=admin_headers,
        json={"approved": True, "reason": "independent approval"},
    ).json()
    signed_hash = approved["scope_hash"]
    app.state.services.db.execute(
        "UPDATE scopes SET ports_json='[80]' WHERE id=?", (created["id"],)
    )

    restarted = create_app(settings)
    row = restarted.state.services.db.fetch_one(
        "SELECT scope_hash FROM scopes WHERE id=?", (created["id"],)
    )
    assert row["scope_hash"] == signed_hash
    with pytest.raises(ScopeViolation, match="changed after signing"):
        restarted.state.services.scope.validate("tcp://127.0.0.1:80", created["id"])
