"""
Factora Community Incident Moderation & Verification System
Module: backend.community_hub.moderation
Implements backend-authorized moderation workflow for community incident reports.

Supported Statuses:
- SUBMITTED (default initial status for user reports)
- UNDER_REVIEW (assigned when moderator begins evaluation)
- CORROBORATED (evidence verified against multiple victim signals or official registries)
- DISPUTED (contested by affected party or conflicting evidence)
- CLOSED (resolved, false positive, or no further action)
- ARCHIVED (retained for historical cyber intelligence)

Security & Guardrails:
1. Strict header authorization via 'X-Moderator-Key'.
2. Full audit trail recorded in SQLite 'moderation_audit_logs'.
3. PII protection: Victim sensitive contacts masked; raw documents access controlled.
4. Cautionary evaluation rules:
   - A cybercrime complaint acknowledgement (FIR ref) does NOT automatically prove an incident is genuine.
   - Shared indicators alone do NOT prove that incidents have the same attacker.
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from backend.community_hub.storage import (
    get_db_connection,
    mask_contact,
    compute_incident_risk_level,
    extract_row_indicators
)

MODERATOR_SECRET_KEY = os.getenv("FACTORA_MODERATOR_KEY", "factora-moderator-sentinel-2026")

VALID_STATUSES = {
    "SUBMITTED",
    "UNDER_REVIEW",
    "CORROBORATED",
    "DISPUTED",
    "CLOSED",
    "ARCHIVED"
}

VALID_FLAGS = {
    "clean",
    "duplicate",
    "spam",
    "misleading",
    "incomplete",
    "needs_info"
}


def verify_moderator_access(provided_key: Optional[str]) -> bool:
    """Verifies that the caller provided the authorized moderator secret key."""
    if not provided_key:
        return False
    return provided_key.strip() == MODERATOR_SECRET_KEY


def init_moderation_schema(conn: sqlite3.Connection):
    """Ensures moderation columns and audit log table exist in the SQLite database."""
    with conn:
        cursor = conn.cursor()
        
        # Check victim_reports columns
        cursor.execute("PRAGMA table_info(victim_reports)")
        columns = [row["name"] for row in cursor.fetchall()]
        
        if "moderator_notes" not in columns:
            cursor.execute("ALTER TABLE victim_reports ADD COLUMN moderator_notes TEXT DEFAULT NULL")
        if "is_public_approved" not in columns:
            cursor.execute("ALTER TABLE victim_reports ADD COLUMN is_public_approved INTEGER NOT NULL DEFAULT 1")
        if "duplicate_of_ref" not in columns:
            cursor.execute("ALTER TABLE victim_reports ADD COLUMN duplicate_of_ref TEXT DEFAULT NULL")
        if "moderation_flag" not in columns:
            cursor.execute("ALTER TABLE victim_reports ADD COLUMN moderation_flag TEXT NOT NULL DEFAULT 'clean'")

        # Moderation audit trail table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS moderation_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_ref TEXT NOT NULL,
            action TEXT NOT NULL,
            previous_status TEXT,
            new_status TEXT,
            moderator_id TEXT NOT NULL,
            notes TEXT,
            metadata_json TEXT DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mod_audit_ref ON moderation_audit_logs (incident_ref);")


def get_moderation_queue(
    status: Optional[str] = None,
    flag: Optional[str] = None,
    is_public: Optional[bool] = None,
    page: int = 1,
    page_size: int = 20
) -> Dict[str, Any]:
    """Retrieves paginated incident reports for moderator review with audit metadata."""
    conn = get_db_connection()
    try:
        init_moderation_schema(conn)
        cursor = conn.cursor()

        query_clauses = ["1=1"]
        params: List[Any] = []

        if status and status.upper() in VALID_STATUSES:
            query_clauses.append("verification_status = ?")
            params.append(status.upper())

        if flag and flag.lower() in VALID_FLAGS:
            query_clauses.append("moderation_flag = ?")
            params.append(flag.lower())

        if is_public is not None:
            query_clauses.append("is_public_approved = ?")
            params.append(1 if is_public else 0)

        where_sql = " AND ".join(query_clauses)

        # Count total items
        cursor.execute(f"SELECT COUNT(*) as total FROM victim_reports WHERE {where_sql}", tuple(params))
        total_items = cursor.fetchone()["total"]

        offset = max(0, (page - 1) * page_size)
        cursor.execute(f"""
            SELECT * FROM victim_reports 
            WHERE {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, tuple(params + [page_size, offset]))
        rows = cursor.fetchall()

        reports = []
        for r in rows:
            r_dict = dict(r)
            # Mask PII in contacts
            contacts = []
            try:
                raw_c = json.loads(r_dict.get("scammer_contacts") or "[]")
                contacts = [mask_contact(c) for c in raw_c]
            except Exception:
                pass

            links = []
            try:
                links = json.loads(r_dict.get("scammer_links") or "[]")
            except Exception:
                pass

            ev_files = []
            try:
                ev_files = json.loads(r_dict.get("evidence_filenames") or "[]")
            except Exception:
                pass

            risk_lvl, risk_color = compute_incident_risk_level(r_dict, 0)

            reports.append({
                "id": r_dict["id"],
                "incident_ref": r_dict["incident_ref"],
                "incident_title": r_dict["incident_title"],
                "claimed_organization": r_dict["claimed_organization"],
                "scam_type": r_dict["scam_type"],
                "category": r_dict["category"],
                "verification_status": r_dict["verification_status"],
                "moderation_flag": r_dict.get("moderation_flag", "clean"),
                "is_public_approved": bool(r_dict.get("is_public_approved", 1)),
                "duplicate_of_ref": r_dict.get("duplicate_of_ref"),
                "moderator_notes": r_dict.get("moderator_notes"),
                "amount_demanded_or_lost_inr": float(r_dict["amount_demanded_or_lost_inr"]),
                "financial_loss_occurred": bool(r_dict.get("financial_loss_occurred", 0)),
                "official_complaint_filed": bool(r_dict.get("official_complaint_filed", 0)),
                "complaint_ack_ref": r_dict.get("complaint_ack_ref"),
                "description": r_dict["description"],
                "evidence_filenames": ev_files,
                "scammer_contacts": contacts,
                "scammer_links": links,
                "reported_at": r_dict["reported_at"],
                "user_pseudonym": r_dict.get("user_pseudonym", "student-sentinel-anon"),
                "risk_level": risk_lvl,
                "risk_color": risk_color
            })

        total_pages = max(1, (total_items + page_size - 1) // page_size)

        return {
            "status": "success",
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_items,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            },
            "reports": reports
        }
    finally:
        conn.close()


def apply_moderator_action(
    incident_ref: str,
    action: str,
    moderator_id: str,
    new_status: Optional[str] = None,
    moderator_notes: Optional[str] = None,
    is_public_approved: Optional[bool] = None,
    duplicate_of_ref: Optional[str] = None,
    moderation_flag: Optional[str] = None
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Executes a moderator review decision, updates the incident record,
    and logs an immutable entry into moderation_audit_logs.
    """
    conn = get_db_connection()
    try:
        init_moderation_schema(conn)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM victim_reports WHERE incident_ref = ?", (incident_ref.strip(),))
        row = cursor.fetchone()
        if not row:
            return False, f"Incident '{incident_ref}' not found.", {}
        row = dict(row)

        prev_status = row["verification_status"]
        cur_is_public = row.get("is_public_approved", 1)
        cur_flag = row.get("moderation_flag", "clean")

        status_to_set = new_status.upper() if (new_status and new_status.upper() in VALID_STATUSES) else prev_status
        flag_to_set = moderation_flag.lower() if (moderation_flag and moderation_flag.lower() in VALID_FLAGS) else cur_flag
        public_to_set = (1 if is_public_approved else 0) if is_public_approved is not None else cur_is_public

        # If marking as duplicate, ensure duplicate_of_ref is recorded
        dup_ref = duplicate_of_ref.strip() if duplicate_of_ref else row.get("duplicate_of_ref")
        if flag_to_set == "duplicate" and not dup_ref:
            flag_to_set = "duplicate"

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with conn:
            cursor.execute("""
                UPDATE victim_reports
                SET verification_status = ?,
                    moderation_flag = ?,
                    is_public_approved = ?,
                    duplicate_of_ref = ?,
                    moderator_notes = ?
                WHERE incident_ref = ?
            """, (status_to_set, flag_to_set, public_to_set, dup_ref, moderator_notes or row.get("moderator_notes"), incident_ref))

            # Record audit log
            meta = {
                "action": action,
                "is_public_approved": bool(public_to_set),
                "moderation_flag": flag_to_set,
                "duplicate_of_ref": dup_ref
            }
            cursor.execute("""
                INSERT INTO moderation_audit_logs (
                    incident_ref, action, previous_status, new_status,
                    moderator_id, notes, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (incident_ref, action, prev_status, status_to_set, moderator_id, moderator_notes, json.dumps(meta), now_str))

        return True, "Moderation decision successfully applied and audit logged.", {
            "incident_ref": incident_ref,
            "previous_status": prev_status,
            "new_status": status_to_set,
            "moderation_flag": flag_to_set,
            "is_public_approved": bool(public_to_set),
            "duplicate_of_ref": dup_ref,
            "moderator_id": moderator_id,
            "moderator_notes": moderator_notes,
            "updated_at": now_str
        }
    finally:
        conn.close()


def get_incident_audit_trail(incident_ref: str) -> List[Dict[str, Any]]:
    """Retrieves the complete immutable audit history for an incident."""
    conn = get_db_connection()
    try:
        init_moderation_schema(conn)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM moderation_audit_logs
            WHERE incident_ref = ?
            ORDER BY id DESC
        """, (incident_ref.strip(),))
        rows = cursor.fetchall()

        trail = []
        for r in rows:
            meta = {}
            try:
                meta = json.loads(r["metadata_json"] or "{}")
            except Exception:
                pass

            trail.append({
                "log_id": r["id"],
                "incident_ref": r["incident_ref"],
                "action": r["action"],
                "previous_status": r["previous_status"],
                "new_status": r["new_status"],
                "moderator_id": r["moderator_id"],
                "notes": r["notes"],
                "metadata": meta,
                "created_at": r["created_at"]
            })
        return trail
    finally:
        conn.close()
