"""PCI DSS v4.0 tests"""
from app.models.pci_requirements import PCI_DSS_V4_REQUIREMENTS, count_by_principle
from app.models.db import get_conn
from app.collectors import (
    run_cde_isolation_check, run_panhunter_scan, run_tokenization_demo, run_saq_d_evaluation,
    run_all_engines, verify_evidence_integrity,
    luhn_check, detect_card_brand, tokenize_pan, detokenize, scan_text_for_pan,
)


# ============================ Catalog ============================
def test_total_requirements_is_12():
    counts = count_by_principle()
    assert sum(counts.values()) == 12


def test_principle_distribution():
    counts = count_by_principle()
    assert counts[1] == 2  # Req 1, 2
    assert counts[2] == 2  # Req 3, 4
    assert counts[3] == 2  # Req 5, 6
    assert counts[4] == 3  # Req 7, 8, 9
    assert counts[5] == 2  # Req 10, 11
    assert counts[6] == 1  # Req 12


def test_all_req_ids_unique():
    ids = [r[0] for r in PCI_DSS_V4_REQUIREMENTS]
    assert len(ids) == len(set(ids))


def test_v4_new_requirements_documented():
    """PCI v4.0 关键新增要求"""
    from app.models.pci_requirements import PCI_V4_NEW_REQUIREMENTS
    assert "6.4.3" in PCI_V4_NEW_REQUIREMENTS
    assert "8.4.2" in PCI_V4_NEW_REQUIREMENTS
    assert "11.6.1" in PCI_V4_NEW_REQUIREMENTS


# ============================ Seed ============================
def test_seed_creates_12_requirements():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS n FROM pci_requirements").fetchone()["n"]
    assert n == 12


def test_seed_creates_assets():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS n FROM network_assets").fetchone()["n"]
    assert n == 15


def test_seed_zone_distribution():
    conn = get_conn()
    zones = {}
    for r in conn.execute("SELECT cde_zone, COUNT(*) AS n FROM network_assets GROUP BY cde_zone").fetchall():
        zones[r["cde_zone"]] = r["n"]
    assert zones["CDE"] == 5
    assert zones["CONNECTED"] == 5
    assert zones["OUT_OF_SCOPE"] == 5


def test_seed_dlp_findings():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS n FROM dlp_scan_findings").fetchone()["n"]
    assert n >= 5


def test_seed_tokens():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) AS n FROM token_vault").fetchone()["n"]
    assert n == 10


# ============================ Luhn & Tokenization ============================
def test_luhn_check_valid_visa():
    assert luhn_check("4111111111111111") is True


def test_luhn_check_invalid():
    assert luhn_check("4111111111111112") is False  # wrong check digit


def test_card_brand_detection():
    assert detect_card_brand("411111") == "Visa"
    assert detect_card_brand("555555") == "MasterCard"
    assert detect_card_brand("378282") == "Amex"
    assert detect_card_brand("353011") == "JCB"
    assert detect_card_brand("620000") == "UnionPay"


def test_tokenize_roundtrip():
    pan = "4111111111111111"
    t = tokenize_pan(pan)
    assert t["card_brand"] == "Visa"
    assert t["pan_bin"] == "411111"
    assert t["pan_last4"] == "1111"
    assert detokenize(t["token_value"]) == pan


def test_tokenize_rejects_invalid_pan():
    import pytest
    with pytest.raises(ValueError):
        tokenize_pan("1234567890123456")


# ============================ PanHunter Scan ============================
def test_scan_text_finds_pan():
    text = "Payment logged: card 4111111111111111 at 2026-09-23"
    findings = scan_text_for_pan(text, "test.log")
    pans = [f for f in findings if f["detected_pattern"] == "PAN"]
    assert len(pans) == 1
    assert pans[0]["sample_redacted"] == "411111******1111"
    assert pans[0]["luhn_valid"] == 1


def test_scan_text_finds_cvv():
    text = "Debug output: cvv=123"
    findings = scan_text_for_pan(text)
    cvv = [f for f in findings if f["detected_pattern"] == "CVV_FULL_CARD"]
    assert len(cvv) == 1
    assert cvv[0]["severity"] == "CRITICAL"


def test_scan_text_finds_expiry():
    text = "Card stored: 4111111111111111 exp:12/27"
    findings = scan_text_for_pan(text)
    expiry = [f for f in findings if f["detected_pattern"] == "EXPIRY"]
    assert len(expiry) == 1


def test_scan_text_no_finding():
    text = "User logged in successfully"
    findings = scan_text_for_pan(text)
    assert len(findings) == 0


# ============================ Engines ============================
def test_cde_isolation_check():
    conn = get_conn()
    r = run_cde_isolation_check(conn)
    result = r["result"]
    assert result["total_assets"] == 15
    assert result["cde_count"] == 5
    assert result["out_of_scope_count"] == 5
    # All CDE assets have TLS 1.3 + encryption (per seed), so violations should be 0
    assert result["violations_found"] == 0


def test_panhunter_scan_finds_critical():
    conn = get_conn()
    r = run_panhunter_scan(conn)
    result = r["result"]
    assert result["critical_pan_count"] >= 3
    assert result["cvv_sad_violations"] >= 1


def test_tokenization_demo_generates_tokens():
    conn = get_conn()
    r = run_tokenization_demo(conn)
    assert r["result"]["generated_tokens"] == 10
    # Verify tokens in DB
    n = conn.execute("SELECT COUNT(*) AS n FROM token_vault WHERE token_value != ''").fetchone()["n"]
    assert n == 10


def test_saq_d_evaluation_scores_12_reqs():
    conn = get_conn()
    r = run_saq_d_evaluation(conn)
    result = r["result"]
    assert result["total_requirements"] == 12
    assert result["weighted_score_pct"] > 0
    # Has mix of YES / PARTIAL
    assert result["yes_count"] >= 5
    assert result["partial_count"] >= 1


def test_all_engines_run():
    conn = get_conn()
    results = run_all_engines(conn)
    assert len(results) == 4


# ============================ SHA-256 Integrity ============================
def test_engine_creates_evidence_with_sha256():
    conn = get_conn()
    r = run_saq_d_evaluation(conn)
    eid = r["evidence_id"]
    ev = conn.execute("SELECT sha256_hash FROM evidence_items WHERE evidence_id=?", (eid,)).fetchone()
    h = ev["sha256_hash"]
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_tamper_detection():
    conn = get_conn()
    r = run_cde_isolation_check(conn)
    eid = r["evidence_id"]
    # initial valid
    check = verify_evidence_integrity(conn, eid)
    assert check["valid"]
    # tamper
    conn.execute("UPDATE evidence_items SET content_payload = '{}' WHERE evidence_id=?", (eid,))
    conn.commit()
    check = verify_evidence_integrity(conn, eid)
    assert not check["valid"]
    assert check["reason"] == "HASH_MISMATCH"


# ============================ Stats / API ============================
def test_stats_consistency():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    r = client.get("/api/stats")
    assert r.status_code == 200
    s = r.json()
    assert s["pci"]["total_requirements"] == 12
    assert s["cde_assets"]["total"] == 15


def test_tokenize_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    r = client.post("/api/tokens/tokenize", json={"pan": "4111111111111111"})
    assert r.status_code == 200
    body = r.json()
    assert body["card_brand"] == "Visa"
    assert body["masked_pan"] == "411111******1111"


def test_tokenize_endpoint_rejects_invalid_pan():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    r = client.post("/api/tokens/tokenize", json={"pan": "1234567890123456"})
    assert r.status_code == 400


def test_update_finding():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    fid = client.get("/api/dlp-findings").json()[0]["finding_id"]
    r = client.put(f"/api/dlp-findings/{fid}", json={"status": "REMEDIATED"})
    assert r.status_code == 200
    assert r.json()["status"] == "REMEDIATED"


# ============================ End-to-end Smoke ============================
def test_full_workflow():
    """端到端: seed → 4 engines → tamper → fail"""
    conn = get_conn()
    # 1. seed OK
    assert conn.execute("SELECT COUNT(*) AS n FROM pci_requirements").fetchone()["n"] == 12
    # 2. 4 engines
    results = run_all_engines(conn)
    assert len(results) == 4
    # 3. SHA-256 valid for all
    for r in results:
        if r.get("evidence_id"):
            check = verify_evidence_integrity(conn, r["evidence_id"])
            assert check["valid"]
    # 4. Token issued
    assert conn.execute("SELECT COUNT(*) AS n FROM token_vault WHERE token_value != ''").fetchone()["n"] == 10
    # 5. Tamper → fail
    first = results[0]["evidence_id"]
    conn.execute("UPDATE evidence_items SET content_payload='{}' WHERE evidence_id=?", (first,))
    conn.commit()
    assert not verify_evidence_integrity(conn, first)["valid"]