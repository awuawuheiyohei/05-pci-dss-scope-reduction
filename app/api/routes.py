"""FastAPI routes"""
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..models.db import get_conn, row_to_dict, rows_to_dicts, write_audit
from ..models.seed import seed_all
from ..collectors import (
    run_cde_isolation_check, run_panhunter_scan,
    run_tokenization_demo, run_saq_d_evaluation,
    run_all_engines, verify_evidence_integrity,
    tokenize_pan, luhn_check, detect_card_brand, scan_text_for_pan,
)


router = APIRouter()


# ============================ Health / Stats ============================
@router.get("/health")
async def health():
    return {"status": "ok", "service": "pci-dss-scope-reduction", "version": "1.0.0"}


@router.get("/stats")
async def stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) AS n FROM pci_requirements").fetchone()["n"]
    compliant = conn.execute("SELECT COUNT(*) AS n FROM pci_requirements WHERE status='COMPLIANT'").fetchone()["n"]
    partial = conn.execute("SELECT COUNT(*) AS n FROM pci_requirements WHERE status='PARTIAL'").fetchone()["n"]
    non = conn.execute("SELECT COUNT(*) AS n FROM pci_requirements WHERE status='NON_COMPLIANT'").fetchone()["n"]
    na = conn.execute("SELECT COUNT(*) AS n FROM pci_requirements WHERE status='NOT_APPLICABLE'").fetchone()["n"]
    not_eval = conn.execute("SELECT COUNT(*) AS n FROM pci_requirements WHERE status='NOT_EVALUATED'").fetchone()["n"]

    # CDE distribution
    cde_dist = {}
    for r in conn.execute("SELECT cde_zone, COUNT(*) AS n FROM network_assets GROUP BY cde_zone").fetchall():
        cde_dist[r["cde_zone"]] = r["n"]

    # DLP
    dlp_total = conn.execute("SELECT COUNT(*) AS n FROM dlp_scan_findings").fetchone()["n"]
    dlp_critical = conn.execute("SELECT COUNT(*) AS n FROM dlp_scan_findings WHERE severity='CRITICAL' AND status='OPEN'").fetchone()["n"]
    dlp_sad = conn.execute(
        "SELECT COUNT(*) AS n FROM dlp_scan_findings WHERE detected_pattern IN ('CVV_FULL_CARD','EXPIRY') AND status='OPEN'"
    ).fetchone()["n"]

    # Tokens
    tokens_total = conn.execute("SELECT COUNT(*) AS n FROM token_vault").fetchone()["n"]
    tokens_issued = conn.execute("SELECT COUNT(*) AS n FROM token_vault WHERE token_value != ''").fetchone()["n"]

    return {
        "pci": {
            "total_requirements": total, "compliant": compliant, "partial": partial,
            "non_compliant": non, "not_applicable": na, "not_evaluated": not_eval,
            "compliance_pct": round(compliant / total * 100, 1) if total else 0,
        },
        "cde_assets": {
            "total": sum(cde_dist.values()),
            "by_zone": cde_dist,
            "scope_reduction_pct": round(cde_dist.get("OUT_OF_SCOPE", 0) / max(sum(cde_dist.values()), 1) * 100, 1),
        },
        "dlp": {
            "total_findings": dlp_total,
            "critical_open": dlp_critical,
            "sad_violations": dlp_sad,
        },
        "tokens": {"total": tokens_total, "issued": tokens_issued},
    }


# ============================ PCI Requirements ============================
@router.get("/requirements")
async def list_requirements(principle_id: Optional[int] = None, status: Optional[str] = None):
    conn = get_conn()
    q = "SELECT * FROM pci_requirements WHERE 1=1"
    p = []
    if principle_id: q += " AND principle_id = ?"; p.append(principle_id)
    if status: q += " AND status = ?"; p.append(status)
    q += " ORDER BY principle_id, req_id"
    rows = conn.execute(q, p).fetchall()
    results = rows_to_dicts(rows)
    for r in results:
        try:
            r["sub_requirements_list"] = json.loads(r["sub_requirements"] or "[]")
        except Exception:
            r["sub_requirements_list"] = []
    return results


@router.get("/requirements/{req_id}")
async def get_requirement(req_id: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM pci_requirements WHERE req_id=?", (req_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    result = row_to_dict(row)
    try:
        result["sub_requirements_list"] = json.loads(result["sub_requirements"] or "[]")
    except Exception:
        result["sub_requirements_list"] = []
    # Recent evidence
    ev = conn.execute(
        "SELECT evidence_id, source_name, collected_at, sha256_hash FROM evidence_items WHERE req_id=? ORDER BY collected_at DESC LIMIT 5",
        (req_id,),
    ).fetchall()
    result["recent_evidences"] = rows_to_dicts(ev)
    return result


class RequirementUpdate(BaseModel):
    status: Optional[str] = None
    owner: Optional[str] = None


@router.put("/requirements/{req_id}")
async def update_requirement(req_id: str, body: RequirementUpdate, actor: str = "user"):
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM pci_requirements WHERE req_id=?", (req_id,)).fetchone():
        raise HTTPException(status_code=404, detail="Not found")
    updates, params = [], []
    if body.status is not None:
        updates.append("status = ?"); params.append(body.status)
        updates.append("last_assessed_at = ?"); params.append(datetime.now(timezone.utc).isoformat())
    if body.owner is not None:
        updates.append("owner = ?"); params.append(body.owner)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields")
    updates.append("updated_at = ?"); params.append(datetime.now(timezone.utc).isoformat())
    params.append(req_id)
    conn.execute(f"UPDATE pci_requirements SET {', '.join(updates)} WHERE req_id=?", params)
    conn.commit()
    write_audit(conn, actor=actor, action="UPDATE_REQ", entity_type="PCI", entity_id=req_id,
                details=body.dict(exclude_none=True))
    row = conn.execute("SELECT * FROM pci_requirements WHERE req_id=?", (req_id,)).fetchone()
    return row_to_dict(row)


# ============================ Network Assets ============================
@router.get("/assets")
async def list_assets(cde_zone: Optional[str] = None, in_cde_scope: Optional[bool] = None):
    conn = get_conn()
    q = "SELECT * FROM network_assets WHERE 1=1"
    p = []
    if cde_zone: q += " AND cde_zone = ?"; p.append(cde_zone)
    if in_cde_scope is not None: q += " AND in_cde_scope = ?"; p.append(1 if in_cde_scope else 0)
    q += " ORDER BY cde_zone, asset_name"
    return rows_to_dicts(conn.execute(q, p).fetchall())


# ============================ DLP Findings ============================
@router.get("/dlp-findings")
async def list_dlp_findings(severity: Optional[str] = None, status: Optional[str] = None,
                            pattern: Optional[str] = None):
    conn = get_conn()
    q = "SELECT * FROM dlp_scan_findings WHERE 1=1"
    p = []
    if severity: q += " AND severity=?"; p.append(severity)
    if status: q += " AND status=?"; p.append(status)
    if pattern: q += " AND detected_pattern=?"; p.append(pattern)
    q += " ORDER BY severity, detected_pattern"
    return rows_to_dicts(conn.execute(q, p).fetchall())


class FindingUpdate(BaseModel):
    status: str  # REMEDIATED / FALSE_POSITIVE


@router.put("/dlp-findings/{finding_id}")
async def update_finding(finding_id: str, body: FindingUpdate, actor: str = "user"):
    conn = get_conn()
    if not conn.execute("SELECT 1 FROM dlp_scan_findings WHERE finding_id=?", (finding_id,)).fetchone():
        raise HTTPException(status_code=404, detail="Not found")
    conn.execute("UPDATE dlp_scan_findings SET status=? WHERE finding_id=?", (body.status, finding_id))
    conn.commit()
    write_audit(conn, actor=actor, action="UPDATE_FINDING",
                entity_type="DLP_Finding", entity_id=finding_id, details={"status": body.status})
    row = conn.execute("SELECT * FROM dlp_scan_findings WHERE finding_id=?", (finding_id,)).fetchone()
    return row_to_dict(row)


# ============================ Token Vault ============================
@router.get("/tokens")
async def list_tokens(card_brand: Optional[str] = None):
    conn = get_conn()
    q = "SELECT token_id, masked_pan, pan_bin, pan_last4, card_brand, created_at, is_revoked FROM token_vault"
    p = []
    if card_brand:
        q += " WHERE card_brand = ?"
        p.append(card_brand)
    return rows_to_dicts(conn.execute(q, p).fetchall())


class TokenizeRequest(BaseModel):
    pan: str


class TokenizeResponse(BaseModel):
    token_id: str
    masked_pan: str
    card_brand: str
    pan_bin: str
    pan_last4: str
    token_preview: str


@router.post("/tokens/tokenize", response_model=TokenizeResponse)
async def api_tokenize_pan(req: TokenizeRequest, actor: str = "user"):
    if not luhn_check(req.pan):
        raise HTTPException(status_code=400, detail="Invalid PAN (Luhn check failed)")
    t = tokenize_pan(req.pan)
    conn = get_conn()
    conn.execute(
        """INSERT INTO token_vault (token_id, token_value, masked_pan, pan_bin, pan_last4, card_brand)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (t["token_id"], t["token_value"], t["masked_pan"], t["pan_bin"], t["pan_last4"], t["card_brand"])
    )
    conn.commit()
    write_audit(conn, actor=actor, action="TOKENIZE_PAN",
                entity_type="TokenVault", entity_id=t["token_id"],
                details={"masked_pan": t["masked_pan"]})
    return TokenizeResponse(
        token_id=t["token_id"], masked_pan=t["masked_pan"],
        card_brand=t["card_brand"], pan_bin=t["pan_bin"], pan_last4=t["pan_last4"],
        token_preview=t["token_value"][:32] + "...",
    )


# ============================ SAQ-D Answers ============================
@router.get("/saq-d")
async def list_saq_answers(req_id: Optional[str] = None):
    conn = get_conn()
    q = "SELECT * FROM saq_d_answers"
    p = []
    if req_id:
        q += " WHERE req_id = ?"
        p.append(req_id)
    q += " ORDER BY req_id"
    return rows_to_dicts(conn.execute(q, p).fetchall())


# ============================ Collectors / Engines ============================
@router.post("/collectors/run-all")
async def collectors_run_all(actor: str = "dashboard_user"):
    conn = get_conn()
    write_audit(conn, actor=actor, action="RUN_ALL_ENGINES")
    results = run_all_engines(conn)
    return {"engines_run": len(results), "items": results}


@router.post("/collectors/{engine_name}")
async def collectors_run_one(engine_name: str, actor: str = "dashboard_user"):
    conn = get_conn()
    fn_map = {
        "cde_isolation_check": run_cde_isolation_check,
        "panhunter_scan":       run_panhunter_scan,
        "tokenization_demo":   run_tokenization_demo,
        "saq_d_evaluation":    run_saq_d_evaluation,
    }
    fn = fn_map.get(engine_name)
    if not fn:
        raise HTTPException(status_code=404, detail=f"Unknown engine: {engine_name}")
    write_audit(conn, actor=actor, action="RUN_ENGINE", entity_type=engine_name)
    r = fn(conn)
    return {"engine": engine_name, "evidence_id": r["evidence_id"]}


@router.post("/collectors/scan-text")
async def collectors_scan_text(text: str = Query(...), source: str = Query("inline")):
    """临时文本扫描 (adhoc PanHunter)"""
    conn = get_conn()
    findings = scan_text_for_pan(text, source_file=source)
    written = 0
    for f in findings:
        fid = str(uuid_module().uuid4())
        conn.execute(
            """INSERT INTO dlp_scan_findings
               (finding_id, source_file, line_number, detected_pattern, severity,
                sample_redacted, luhn_valid, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')""",
            (fid, f["source_file"], f["line_number"], f["detected_pattern"], f["severity"],
             f["sample_redacted"], f["luhn_valid"])
        )
        written += 1
    conn.commit()
    return {"findings": findings, "written_to_db": written}


def uuid_module():
    import uuid as _u
    return _u


@router.post("/evidence/{evidence_id}/verify")
async def verify_evidence(evidence_id: str):
    conn = get_conn()
    return verify_evidence_integrity(conn, evidence_id)


# ============================ Audit / Export ============================
@router.get("/audit/export")
async def audit_export(format: str = Query("json", pattern="^(json|csv)$")):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM pci_requirements ORDER BY principle_id, req_id").fetchall()
    results = rows_to_dicts(rows)
    write_audit(conn, actor="dashboard_user", action="EXPORT_PCI",
                details={"format": format, "count": len(results)})
    if format == "csv":
        from fastapi.responses import StreamingResponse
        import io, csv
        output = io.StringIO()
        if results:
            w = csv.DictWriter(output, fieldnames=results[0].keys())
            w.writeheader()
            for r in results:
                w.writerow(r)
        return StreamingResponse(iter([output.getvalue()]),
                                  media_type="text/csv",
                                  headers={"Content-Disposition": "attachment; filename=pci_export.csv"})
    return {"format": "json", "requirements": results,
            "exported_at": datetime.now(timezone.utc).isoformat()}


@router.get("/audit/trail")
async def audit_trail(limit: int = Query(default=50, le=500)):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM audit_trail ORDER BY audit_id DESC LIMIT ?", (limit,)).fetchall()
    return rows_to_dicts(rows)


# ============================ Admin ============================
@router.post("/admin/seed")
async def admin_seed(actor: str = "admin"):
    stats = seed_all(verbose=False)
    write_audit(get_conn(), actor=actor, action="RESET_AND_SEED", details=stats)
    return {"status": "ok", "seeded": stats}