"""Tamper-evident audit log writer: each entry hashes in the previous entry's hash."""
import hashlib
import json

from sqlalchemy.orm import Session

from app.db.models import AuditLog


def _hash_entry(prev_hash: str, action: str, resource_type: str, resource_id: str, after_state: dict) -> str:
    payload = json.dumps(
        {"prev_hash": prev_hash, "action": action, "resource_type": resource_type,
         "resource_id": resource_id, "after_state": after_state},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_audit_log(
    db: Session, org_id: str, actor_user_id: str | None, action: str,
    resource_type: str, resource_id: str, before_state: dict | None = None,
    after_state: dict | None = None, source_ip: str | None = None,
) -> AuditLog:
    last = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == org_id)
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    prev_hash = last.entry_hash if last else "0" * 64
    entry_hash = _hash_entry(prev_hash, action, resource_type, resource_id, after_state or {})

    entry = AuditLog(
        org_id=org_id, actor_user_id=actor_user_id, action=action,
        resource_type=resource_type, resource_id=resource_id,
        before_state=before_state, after_state=after_state,
        source_ip=source_ip, prev_hash=prev_hash, entry_hash=entry_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
