"""Seed PCI DSS v4.0 + 演示数据"""
import uuid
from datetime import datetime, timezone, timedelta
from .db import get_conn, init_db
from .pci_requirements import PCI_DSS_V4_REQUIREMENTS


def seed_pci_requirements(verbose: bool = False) -> int:
    init_db()
    conn = get_conn()
    # 清空
    conn.execute("DELETE FROM dlp_scan_findings")
    conn.execute("DELETE FROM token_vault")
    conn.execute("DELETE FROM saq_d_answers")
    conn.execute("DELETE FROM network_assets")
    conn.execute("DELETE FROM evidence_items")
    conn.execute("DELETE FROM audit_trail")
    conn.execute("DELETE FROM pci_requirements")

    for req_id, pid, principle, title, desc, subs in PCI_DSS_V4_REQUIREMENTS:
        conn.execute(
            """INSERT INTO pci_requirements
               (req_id, principle, principle_id, title, description, sub_requirements,
                is_applicable, status, owner)
               VALUES (?, ?, ?, ?, ?, ?, 1, 'NOT_EVALUATED', 'GRC Team')""",
            (req_id, principle, pid, title, desc, subs)
        )
    conn.commit()
    if verbose:
        print(f"[+] Seeded {len(PCI_DSS_V4_REQUIREMENTS)} PCI DSS v4.0 requirements")
    return len(PCI_DSS_V4_REQUIREMENTS)


def seed_demo_assets(verbose: bool = False) -> int:
    """CDE 网络资产清单（15 个，含 CDE / CONNECTED / OUT_OF_SCOPE）"""
    conn = get_conn()
    assets = [
        # CDE 核心
        ("web-payment-01", "Checkout Web Tier",      "Web Server",   "10.10.1.10",  "CDE",         1, 1, "TLS 1.3"),
        ("api-payment-01", "Payment API Service",   "App Server",   "10.10.2.10",  "CDE",         1, 1, "TLS 1.3"),
        ("db-pan-01",      "PAN Token Database",     "DB",           "10.10.3.10",  "CDE",         1, 1, "TLS 1.3"),
        ("vault-01",       "Tokenization Vault",     "KMS",          "10.10.4.10",  "CDE",         1, 1, "TLS 1.3"),
        ("waf-01",         "WAF Frontend",            "WAF",          "10.10.1.5",   "CDE",         1, 1, "TLS 1.3"),
        # CONNECTED（连接 CDE 但不存 PAN，应隔离）
        ("order-svc-01",   "Order Service",           "App Server",   "10.20.1.10",  "CONNECTED",   1, 1, "TLS 1.2"),
        ("report-svc-01",  "Daily Report Service",      "App Server",   "10.20.1.20",  "CONNECTED",   1, 1, "TLS 1.2"),
        ("log-shipper-01", "Log Shipper",             "App Server",   "10.20.2.10",  "CONNECTED",   1, 1, "TLS 1.2"),
        ("monitor-01",     "Monitoring Agent",         "App Server",   "10.20.2.20",  "CONNECTED",   1, 1, "TLS 1.2"),
        ("backup-01",      "Backup Server",           "DB",           "10.20.3.10",  "CONNECTED",   1, 1, "TLS 1.2"),
        # OUT_OF_SCOPE（应严格隔离）
        ("search-svc-01",  "Search Service",          "App Server",   "10.30.1.10",  "OUT_OF_SCOPE", 0, 0, "TLS 1.2"),
        ("cms-01",         "CMS / Marketing",         "Web Server",   "10.30.1.20",  "OUT_OF_SCOPE", 0, 0, "TLS 1.2"),
        ("analytics-01",   "Analytics Service",       "App Server",   "10.30.2.10",  "OUT_OF_SCOPE", 0, 0, "TLS 1.2"),
        ("hr-svc-01",      "HR System",               "App Server",   "10.30.3.10",  "OUT_OF_SCOPE", 0, 0, "TLS 1.2"),
        ("docs-01",        "Document Wiki",           "Web Server",   "10.30.4.10",  "OUT_OF_SCOPE", 0, 0, "TLS 1.2"),
    ]

    inserted = 0
    for a in assets:
        # tuple: (asset_id, asset_name, asset_type, ip, cde_zone, in_cde_scope, encryption_at_rest, tls_version)
        aid = a[0]  # use the provided asset_id (not a new UUID)
        conn.execute(
            """INSERT INTO network_assets
               (asset_id, asset_name, asset_type, ip_address, cde_zone,
                in_cde_scope, encryption_at_rest, tls_version, last_scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (aid, a[1], a[2], a[3], a[4], a[5], a[6], a[7], datetime.now(timezone.utc).isoformat())
        )
        inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} network assets")
    return inserted


def seed_demo_dlp_findings(verbose: bool = False) -> int:
    """8 条 PanHunter findings（含 1 CVV critical）"""
    conn = get_conn()
    findings = [
        # 严重：明文卡号写入 log
        ("app.log",          42,   "PAN",          "CRITICAL", "411111******1111", 1),
        ("payment-error.log", 17, "PAN",          "CRITICAL", "555555******4444", 1),
        ("payment-error.log", 88, "PAN",          "CRITICAL", "378282******0005", 1),
        # 严重：CVV 存储（SAD 红线）
        ("checkout-debug.log", 5, "CVV_FULL_CARD", "CRITICAL", "****-****-***-*** [CVV:123]", 0),
        # 中：过期日
        ("db-backup.log",    201, "EXPIRY",        "HIGH",    "exp: 12/27",       0),
        ("db-backup.log",    202, "EXPIRY",        "HIGH",    "exp: 03/29",       0),
        # 低：BIN（合规可保留）
        ("fraud-alerts.log",  14, "CARD_BIN",      "LOW",     "BIN 411111",       1),
        ("analytics-raw.json", 7, "CARD_BIN",      "LOW",     "BIN 555555",       1),
    ]

    inserted = 0
    for src, line, pattern, sev, sample, luhn in findings:
        fid = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO dlp_scan_findings
               (finding_id, source_file, line_number, detected_pattern, severity,
                sample_redacted, luhn_valid, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN')""",
            (fid, src, line, pattern, sev, sample, 1 if luhn else 0)
        )
        inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} DLP findings")
    return inserted


def seed_demo_tokens(verbose: bool = False) -> int:
    """10 个 token vault 条目（仅 masked_pan，token_value 在 collector 中生成）"""
    conn = get_conn()
    tokens = [
        ("411111", "1111", "Visa"),
        ("555555", "4444", "MasterCard"),
        ("378282", "0005", "Amex"),
        ("401288", "8888", "Visa"),
        ("601111", "1117", "Discover"),
        ("510510", "5100", "MasterCard"),
        ("422222", "2222", "Visa"),
        ("371449", "6353", "Amex"),
        ("620000", "0000", "UnionPay"),
        ("353011", "3333", "JCB"),
    ]

    inserted = 0
    for bin_, last4, brand in tokens:
        tid = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO token_vault
               (token_id, token_value, masked_pan, pan_bin, pan_last4, card_brand)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (tid, "", f"{bin_}******{last4}", bin_, last4, brand)
        )
        inserted += 1
    conn.commit()
    if verbose:
        print(f"[+] Seeded {inserted} PAN BIN/Last4 (token 需运行 tokenization 后生成)")
    return inserted


def seed_all(verbose: bool = False) -> dict:
    init_db()
    req_n = seed_pci_requirements(verbose=verbose)
    asset_n = seed_demo_assets(verbose=verbose)
    dlp_n = seed_demo_dlp_findings(verbose=verbose)
    tok_n = seed_demo_tokens(verbose=verbose)
    return {"pci_requirements": req_n, "network_assets": asset_n,
            "dlp_findings": dlp_n, "tokens": tok_n}


if __name__ == "__main__":
    stats = seed_all(verbose=True)
    print(f"\n[+] Seed: {stats}")