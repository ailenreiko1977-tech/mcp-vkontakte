"""Encrypted tenant storage and one-attempt browser approvals. SQLite, one worker."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from cryptography.fernet import Fernet
from .catalog import PolicyError


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Store:
    def __init__(self, path: Path, key: str):
        self.cipher = Fernet(key.encode())
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS connections (
              owner TEXT NOT NULL, alias TEXT NOT NULL, kind TEXT NOT NULL,
              token BLOB NOT NULL, revision TEXT NOT NULL, PRIMARY KEY(owner,alias));
            CREATE TABLE IF NOT EXISTS sessions (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS actions (
              id TEXT PRIMARY KEY, owner TEXT NOT NULL, payload BLOB NOT NULL,
              digest TEXT NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL,
              result BLOB);
            CREATE TABLE IF NOT EXISTS quotas (owner TEXT, bucket INTEGER, count INTEGER, PRIMARY KEY(owner,bucket));
            """)
        try:
            path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def encrypt(self, obj):
        return self.cipher.encrypt(canonical(obj).encode())

    def decrypt(self, value):
        return json.loads(self.cipher.decrypt(value))

    def rate_limit(self, owner, limit=60):
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM quotas WHERE bucket < ?", (now//60 - 2,))
            row = db.execute("SELECT count FROM quotas WHERE owner=? AND bucket=?", (owner, now//60)).fetchone()
            if row and row[0] >= limit:
                raise PolicyError("Rate limit reached; try again in a minute")
            db.execute("INSERT INTO quotas VALUES (?,?,1) ON CONFLICT(owner,bucket) DO UPDATE SET count=count+1", (owner, now//60))

    def put_connection(self, owner, alias, kind, token):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", alias) or kind not in ("user", "group", "service"):
            raise PolicyError("Invalid connection alias or token type")
        if not token or len(token) > 4096 or any(c.isspace() for c in token):
            raise PolicyError("Invalid token format")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM connections WHERE owner=?", (owner,)).fetchone()[0] >= 10 and not db.execute("SELECT 1 FROM connections WHERE owner=? AND alias=?", (owner,alias)).fetchone():
                raise PolicyError("Maximum 10 connections")
            db.execute("INSERT INTO connections VALUES (?,?,?,?,?) ON CONFLICT(owner,alias) DO UPDATE SET kind=excluded.kind,token=excluded.token,revision=excluded.revision",
                       (owner, alias, kind, self.encrypt(token), secrets.token_hex(16)))

    def connections(self, owner):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT alias,kind FROM connections WHERE owner=? ORDER BY alias", (owner,))]

    def connection(self, owner, alias):
        with self.connect() as db:
            row = db.execute("SELECT * FROM connections WHERE owner=? AND alias=?", (owner,alias)).fetchone()
        if not row:
            raise PolicyError("Connection not found; add it in the account page")
        return {"kind": row["kind"], "token": self.decrypt(row["token"]), "revision": row["revision"]}

    def delete_connection(self, owner, alias):
        with self.connect() as db:
            db.execute("DELETE FROM connections WHERE owner=? AND alias=?", (owner,alias))

    def session(self, sid):
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            row = db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        return dict(row) if row else None

    def new_session(self, owner):
        sid = secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (sid, owner, secrets.token_urlsafe(32), time.time()+1800))
        return sid

    def logout(self, sid):
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (sid,))

    def prepare(self, owner, payload):
        action_id = secrets.token_urlsafe(24)
        digest = hashlib.sha256(canonical(payload).encode()).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM actions WHERE expires < ?", (time.time()-86400,))
            if db.execute("SELECT count(*) FROM actions WHERE owner=? AND state='pending' AND expires>?", (owner,time.time())).fetchone()[0] >= 30:
                raise PolicyError("Too many pending actions")
            db.execute("INSERT INTO actions VALUES (?,?,?,?,?,'pending',NULL)", (action_id,owner,self.encrypt(payload),digest,time.time()+900))
        return action_id, digest

    def action(self, owner, action_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM actions WHERE owner=? AND id=?", (owner,action_id)).fetchone()
        if not row:
            raise PolicyError("Action not found")
        return {"id": row["id"], "digest": row["digest"], "expires": row["expires"], "state": row["state"],
                "payload": self.decrypt(row["payload"]), "result": self.decrypt(row["result"]) if row["result"] else None}

    def claim(self, owner, action_id, digest):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute("UPDATE actions SET state='attempted' WHERE owner=? AND id=? AND digest=? AND state='pending' AND expires>?",
                                 (owner,action_id,digest,time.time())).rowcount
            if changed != 1:
                raise PolicyError("Action expired, changed, or already attempted; check VK before preparing another")
        return self.action(owner,action_id)["payload"]

    def finish(self, owner, action_id, state, result):
        with self.connect() as db:
            db.execute("UPDATE actions SET state=?,result=? WHERE owner=? AND id=? AND state='attempted'", (state,self.encrypt(result),owner,action_id))
