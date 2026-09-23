"""
PCI DSS v4.0 Collectors
1. CDE Network Isolation Checker
2. PanHunter (Luhn + Regex + Entropy)
4. Tokenization Gateway (AES-256-GCM)
4. SAQ-D Rulebook Evaluation
"""
import hashlib
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..models.db import get_conn, write_audit


# ============================================================
# AES-256-GCM Tokenization（PCI DSS v4.0 Req 3.5 / 3.6）
# ============================================================

# 注意：演示用 key，生产环境应来自 Vault / AWS KMS
DEMO_MASTER_KEY = bytes.fromhex(
    "0011223344556677889900112233445566778899aabbccddeeff001122334455"
)
aesgcm = AESGCM(DEMO_MASTER_KEY)


def tokenize_pan(plain_pan: str) -> dict:
    """PAN → token (AES-256-GCM 加密)
    返回 {token_id, token_value (hex), masked_pan, card_brand, bin, last4}
    """
    # Luhn check first
    if not luhn_check(plain_pan):
        raise ValueError("Invalid PAN (Luhn check failed)")

    # BIN (first 6) + Last 4
    digits = re.sub(r"[^\d]", "", plain_pan)
    bin_ = digits[:6]
    last4 = digits[-4:]
    masked = f"{bin_}******{last4}"

    # Card brand detection
    brand = detect_card_brand(bin_)

    # AES-256-GCM
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plain_pan.encode("utf-8"), None)
    token_value = (nonce + ciphertext).hex()
    token_id = str(uuid.uuid4())

    return {
        "token_id": token_id,
        "token_value": token_value,
        "masked_pan": masked,
        "pan_bin": bin_,
        "pan_last4": last4,
        "card_brand": brand,
    }


def detokenize(token_value_hex: str) -> str:
    """token → 原始 PAN（仅审计 / 反洗钱场景用）"""
    data = bytes.fromhex(token_value_hex)
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


# ============================================================
# Luhn Check + Card Brand Detection
# ============================================================
def luhn_check(pan: str) -> bool:
    """校验 PAN 是否通过 Luhn 校验（业界通行）"""
    digits = [int(d) for d in re.sub(r"[^\d]", "", pan)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect_card_brand(bin_: str) -> str:
    """根据 BIN 前缀检测卡组织"""
    if bin_.startswith("4"):
        return "Visa"
    if bin_.startswith(("51", "52", "53", "54", "55")):
        return "MasterCard"
    if bin_.startswith(("34", "37")):
        return "Amex"
    if bin_.startswith(("62", "81")):
        return "UnionPay"
    if bin_.startswith(("35", "2131", "1800")):
        return "JCB"
    if bin_.startswith("6011") or bin_.startswith("65"):
        return "Discover"
    return "Unknown"


# ============================================================
# PanHunter (Luhn + Regex + Entropy DLP)
# ============================================================
PAN_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
CVV_REGEX = re.compile(r"cvv[:= ]+(\d{3,4})", re.IGNORECASE)
EXPIRY_REGEX = re.compile(r"exp(?:iry|iration)?[:/= ]+(\d{2}/\d{2,4})", re.IGNORECASE)


def shannon_entropy(s: str) -> float:
    """计算 Shannon 熵（识别高熵字符串如密钥 / Token）"""
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((c / length) * log2(c / length) for c in freq.values())


def scan_text_for_pan(text: str, source_file: str = "inline") -> list:
    """扫描文本，返回所有 PAN/CVV/EXPIY findings
    每条 finding 包含: pattern / sample (脱敏) / luhn_valid / severity
    """
    findings = []
    for line_no, line in enumerate(text.split("\n"), 1):
        # 1. PAN detection
        for m in PAN_REGEX.finditer(line):
            candidate = re.sub(r"[^\d]", "", m.group())
            if 13 <= len(candidate) <= 19 and luhn_check(candidate):
                bin_ = candidate[:6]
                masked = f"{bin_}******{candidate[-4:]}"
                findings.append({
                    "source_file": source_file,
                    "line_number": line_no,
                    "detected_pattern": "PAN",
                    "severity": "CRITICAL",
                    "sample_redacted": masked,
                    "luhn_valid": 1,
                })
        # 2. CVV detection (PCI 红线：禁止存储)
        for m in CVV_REGEX.finditer(line):
            findings.append({
                "source_file": source_file,
                "line_number": line_no,
                "detected_pattern": "CVV_FULL_CARD",
                "severity": "CRITICAL",
                "sample_redacted": f"CVV redaction requires immediate remediation",
                "luhn_valid": 0,
            })
        # 3. Expiry detection
        for m in EXPIRY_REGEX.finditer(line):
            findings.append({
                "source_file": source_file,
                "line_number": line_no,
                "detected_pattern": "EXPIRY",
                "severity": "HIGH",
                "sample_redacted": f"exp: {m.group(1)}",
                "luhn_valid": 0,
            })
    return findings


# ============================================================
# Engine 1: CDE Network Isolation Checker
# ============================================================
def run_cde_isolation_check(conn) -> dict:
    """检查所有网络资产的 CDE 隔离状态
    - CDE zone 资产必须 TLS 1.3 + encryption_at_rest
    - OUT_OF_SCOPE 资产不应在 CDE subnet
    - CONNECTED 资产应有 WAF / 网关隔离
    """
    assets = conn.execute("""
        SELECT asset_id, asset_name, asset_type, cde_zone, in_cde_scope,
               encryption_at_rest, tls_version
        FROM network_assets
    """).fetchall()

    violations = []
    for a in assets:
        # 1. CDE 资产必须 TLS 1.3 + encryption
        if a["cde_zone"] == "CDE":
            if a["tls_version"] != "TLS 1.3":
                violations.append({
                    "asset": a["asset_name"], "rule": "CDE 必须 TLS 1.3",
                    "current": a["tls_version"], "severity": "CRITICAL",
                })
            if not a["encryption_at_rest"]:
                violations.append({
                    "asset": a["asset_name"], "rule": "CDE 必须 encryption_at_rest",
                    "current": "NO", "severity": "CRITICAL",
                })
        # 2. CONNECTED 资产必须 TLS ≥ 1.2
        if a["cde_zone"] == "CONNECTED" and a["tls_version"] not in ("TLS 1.2", "TLS 1.3"):
            violations.append({
                "asset": a["asset_name"], "rule": "CONNECTED 必须 TLS ≥ 1.2",
                "current": a["tls_version"] or "NONE", "severity": "HIGH",
            })

    cde_count = sum(1 for a in assets if a["cde_zone"] == "CDE")
    connected_count = sum(1 for a in assets if a["cde_zone"] == "CONNECTED")
    out_of_scope_count = sum(1 for a in assets if a["cde_zone"] == "OUT_OF_SCOPE")
    scope_reduction_pct = round(out_of_scope_count / len(assets) * 100, 1)

    result = {
        "check_type": "CDE_ISOLATION",
        "tsc_criteria": ["Req 1", "Req 2"],
        "total_assets": len(assets),
        "cde_count": cde_count,
        "connected_count": connected_count,
        "out_of_scope_count": out_of_scope_count,
        "scope_reduction_pct": scope_reduction_pct,
        "violations_found": len(violations),
        "violations": violations,
        "target": "CDE 资产 ≤ 20%, CONNECTED ≤ 30%, OUT_OF_SCOPE ≥ 50%",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    payload_str = json.dumps(result, sort_keys=True, indent=2)
    sha256 = hashlib.sha256(payload_str.encode()).hexdigest()
    evidence_id = str(uuid.uuid4())
    now = result["timestamp"]
    conn.execute(
        """INSERT INTO evidence_items
           (evidence_id, req_id, source_name, collected_at, content_payload, sha256_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, "1", "CDE_Isolation_Checker", now, payload_str, sha256)
    )
    conn.commit()
    write_audit(conn, actor="CDE_Isolation_Checker", action="RUN_CHECK",
                entity_type="CDE", entity_id=evidence_id,
                details={"violations": len(violations), "sha256_prefix": sha256[:12]})

    status = "PASSED" if not violations else "NON_COMPLIANT"
    conn.execute(
        """UPDATE pci_requirements
           SET status = ?, last_assessed_at = ? WHERE req_id IN ('1', '2')""",
        (status, now)
    )
    conn.commit()
    return {"evidence_id": evidence_id, "result": result}


# ============================================================
# Engine 2: PanHunter DLP Scanner
# ============================================================
def run_panhunter_scan(conn) -> dict:
    """扫描所有 OPEN DLP findings + 重新评估 PAN 风险"""
    findings = conn.execute("""
        SELECT finding_id, source_file, detected_pattern, severity, sample_redacted, luhn_valid
        FROM dlp_scan_findings WHERE status = 'OPEN'
    """).fetchall()

    critical_pan = [f for f in findings if f["detected_pattern"] == "PAN" and f["severity"] == "CRITICAL"]
    cvv_findings = [f for f in findings if f["detected_pattern"] == "CVV_FULL_CARD"]
    expiry_findings = [f for f in findings if f["detected_pattern"] == "EXPIRY"]
    bin_findings = [f for f in findings if f["detected_pattern"] == "CARD_BIN"]

    # SAD (Sensitive Auth Data) 红线：PCI v4.0 Req 3.3 禁止存储
    sad_violations = len(cvv_findings) + len(expiry_findings)

    result = {
        "check_type": "PANHUNTER_SCAN",
        "tsc_criteria": ["Req 3", "Req 10"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "critical_pan_count": len(critical_pan),
        "cvv_sad_violations": len(cvv_findings),
        "expiry_sad_violations": len(expiry_findings),
        "bin_findings_acceptable": len(bin_findings),
        "sad_total_violations": sad_violations,
        "remediation_priority": [
            f"Finding {f['finding_id'][:8]}: {f['source_file']}:{f['detected_pattern']}"
            for f in critical_pan[:5]
        ],
    }

    payload_str = json.dumps(result, sort_keys=True, indent=2)
    sha256 = hashlib.sha256(payload_str.encode()).hexdigest()
    evidence_id = str(uuid.uuid4())
    now = result["timestamp"]
    conn.execute(
        """INSERT INTO evidence_items
           (evidence_id, req_id, source_name, collected_at, content_payload, sha256_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, "3", "PanHunter_Engine", now, payload_str, sha256)
    )
    conn.commit()
    write_audit(conn, actor="PanHunter_Engine", action="RUN_SCAN",
                entity_type="PanHunter", entity_id=evidence_id,
                details={"findings": len(findings), "sha256_prefix": sha256[:12]})

    status = "PASSED" if sad_violations == 0 and len(critical_pan) == 0 else "NON_COMPLIANT"
    conn.execute(
        """UPDATE pci_requirements
           SET status = ?, last_assessed_at = ? WHERE req_id IN ('3', '10')""",
        (status, now)
    )
    conn.commit()
    return {"evidence_id": evidence_id, "result": result}


# ============================================================
# Engine 3: Tokenization Gateway (生成 demo tokens)
# ============================================================
def run_tokenization_demo(conn) -> dict:
    """为 PAN BIN/Last4 表生成 AES-256-GCM tokenization"""
    rows = conn.execute("""
        SELECT token_id, pan_bin, pan_last4 FROM token_vault WHERE token_value = ''
    """).fetchall()

    if not rows:
        return {"evidence_id": None, "result": {"generated": 0, "message": "No tokens to generate"}}

    generated = 0
    samples = []
    for r in rows:
        # 合成一个 Luhn-valid PAN 用于演示
        # 实际生产环境会从真实 PAN 输入
        demo_pan = r["pan_bin"] + ("0" * (10 - len(r["pan_last4"]))) + r["pan_last4"]
        # 调 Luhn fix: 计算最后一位校验位
        digits = [int(d) for d in demo_pan[:-1]]
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 0:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        check_digit = (10 - (checksum % 10)) % 10
        valid_pan = demo_pan[:-1] + str(check_digit)

        if luhn_check(valid_pan):
            t = tokenize_pan(valid_pan)
            conn.execute(
                "UPDATE token_vault SET token_value = ? WHERE token_id = ?",
                (t["token_value"], r["token_id"])
            )
            samples.append({
                "masked_pan": t["masked_pan"],
                "card_brand": t["card_brand"],
                "token_preview": t["token_value"][:32] + "...",
                "token_length": len(t["token_value"]),
            })
            generated += 1
    conn.commit()

    result = {
        "check_type": "TOKENIZATION_GATEWAY",
        "tsc_criteria": ["Req 3.5", "Req 3.6"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "generated_tokens": generated,
        "algorithm": "AES-256-GCM",
        "key_rotation_required": "quarterly (PCI Req 3.6.4)",
        "samples": samples[:5],
    }

    payload_str = json.dumps(result, sort_keys=True, indent=2)
    sha256 = hashlib.sha256(payload_str.encode()).hexdigest()
    evidence_id = str(uuid.uuid4())
    now = result["timestamp"]
    conn.execute(
        """INSERT INTO evidence_items
           (evidence_id, req_id, source_name, collected_at, content_payload, sha256_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, "3", "Tokenization_Gateway", now, payload_str, sha256)
    )
    conn.commit()
    write_audit(conn, actor="Tokenization_Gateway", action="RUN_TOKENIZE",
                entity_type="TokenVault", entity_id=evidence_id,
                details={"generated": generated, "sha256_prefix": sha256[:12]})

    return {"evidence_id": evidence_id, "result": result}


# ============================================================
# Engine 4: SAQ-D Rulebook (12 req 自评)
# ============================================================
SAQ_D_RULEBOOK = {
    "1": {"question": "Are network security controls (firewalls, routers) installed and maintained?",
          "default_response": "YES"},
    "2": {"question": "Are vendor-supplied defaults changed and secure configurations maintained?",
          "default_response": "YES"},
    "3": {"question": "Is stored cardholder data properly protected (encryption, truncation, masking)?",
          "default_response": "PARTIAL"},
    "4": {"question": "Is cardholder data encrypted during transmission over open networks?",
          "default_response": "YES"},
    "5": {"question": "Is anti-virus software installed and regularly updated?",
          "default_response": "YES"},
    "6": {"question": "Are secure systems and software developed and maintained (Req 6.4.3 / 11.6.1)?",
          "default_response": "PARTIAL"},
    "7": {"question": "Is access to cardholder data restricted by business need-to-know?",
          "default_response": "YES"},
    "8": {"question": "Are unique IDs assigned and MFA enforced (Req 8.4.2 v4.0)?",
          "default_response": "PARTIAL"},
    "9": {"question": "Is physical access to cardholder data restricted?",
          "default_response": "YES"},
    "10": {"question": "Are access to network resources and cardholder data tracked and monitored?",
           "default_response": "YES"},
    "11": {"question": "Are security systems and processes regularly tested (Req 11.6.1)?",
           "default_response": "PARTIAL"},
    "12": {"question": "Is an information security policy maintained and disseminated?",
           "default_response": "YES"},
}


def run_saq_d_evaluation(conn) -> dict:
    """SAQ-D 12 req 自评（生成自评答案 + 计算合规率）"""
    answers = []
    for req_id, rule in SAQ_D_RULEBOOK.items():
        # 写入 saq_d_answers（demo）
        conn.execute(
            """INSERT OR REPLACE INTO saq_d_answers (req_id, question, response, evidence_summary, assessed_by)
               VALUES (?, ?, ?, ?, 'GRC Team')""",
            (req_id, rule["question"], rule["default_response"], f"Auto SAQ-D v4.0 - {datetime.now().strftime('%Y-%m')}")
        )
        answers.append({"req_id": req_id, "response": rule["default_response"]})

    conn.commit()

    yes = sum(1 for a in answers if a["response"] == "YES")
    partial = sum(1 for a in answers if a["response"] == "PARTIAL")
    no = sum(1 for a in answers if a["response"] == "NO")
    na = sum(1 for a in answers if a["response"] == "N/A")
    total = len(answers)

    # 加权得分：YES=1.0, PARTIAL=0.5, N/A=1.0, NO=0.0
    weighted = yes * 1.0 + partial * 0.5 + na * 1.0 + no * 0.0
    score = round(weighted / (total - na) * 100, 1) if (total - na) else 0

    result = {
        "check_type": "SAQ_D_EVAL",
        "tsc_criteria": [str(i) for i in range(1, 13)],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_requirements": total,
        "yes_count": yes,
        "partial_count": partial,
        "no_count": no,
        "na_count": na,
        "weighted_score_pct": score,
        "saq_type": "SAQ-D (Service Provider storing CHD)",
        "answers": answers,
    }

    payload_str = json.dumps(result, sort_keys=True, indent=2)
    sha256 = hashlib.sha256(payload_str.encode()).hexdigest()
    evidence_id = str(uuid.uuid4())
    now = result["timestamp"]
    conn.execute(
        """INSERT INTO evidence_items
           (evidence_id, req_id, source_name, collected_at, content_payload, sha256_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (evidence_id, "12", "SAQ_D_Rulebook", now, payload_str, sha256)
    )
    conn.commit()
    write_audit(conn, actor="SAQ_D_Rulebook", action="RUN_EVAL",
                entity_type="SAQ", entity_id=evidence_id,
                details={"score": score, "sha256_prefix": sha256[:12]})

    # 更新所有 req 的 last_assessed_at
    conn.execute(
        """UPDATE pci_requirements SET last_assessed_at = ?""", (now,)
    )
    conn.commit()

    return {"evidence_id": evidence_id, "result": result}


# ============================================================
# Run All
# ============================================================
def run_all_engines(conn) -> list:
    results = []
    for fn in (run_cde_isolation_check, run_panhunter_scan, run_tokenization_demo, run_saq_d_evaluation):
        r = fn(conn)
        results.append({
            "engine": r["result"]["check_type"],
            "evidence_id": r["evidence_id"],
        })
    return results


def verify_evidence_integrity(conn, evidence_id: str) -> dict:
    """验证 evidence_items 的 SHA-256"""
    row = conn.execute(
        "SELECT sha256_hash, content_payload FROM evidence_items WHERE evidence_id=?",
        (evidence_id,)
    ).fetchone()
    if not row:
        return {"evidence_id": evidence_id, "valid": False, "reason": "NOT_FOUND"}
    expected = row[0]
    payload = row[1]
    computed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "evidence_id": evidence_id,
        "valid": computed == expected,
        "expected_prefix": expected[:16],
        "computed_prefix": computed[:16],
        "reason": "OK" if computed == expected else "HASH_MISMATCH",
    }