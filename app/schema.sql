-- PCI DSS v4.0 Scope Reduction & Audit Engine - SQLite schema (v1.0)
-- 来源：PCI DSS v4.0 (March 2022) 公开标准

-- ============================================
-- PCI DSS v4.0 12 大要求（Principle / Requirement）
-- ============================================
CREATE TABLE IF NOT EXISTS pci_requirements (
    req_id          TEXT PRIMARY KEY,                   -- "1", "2", "3.5", "6.4.3", "8.4.2"
    principle       TEXT NOT NULL,                     -- Build & Maintain / Protect / Maintain / Regularly Monitor / Test / Maintain IS Policy
    principle_id    INTEGER NOT NULL,                  -- 1..6
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    sub_requirements TEXT,                              -- JSON 数组（PCI v4.0 子要求）
    is_applicable   INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'NOT_EVALUATED',  -- COMPLIANT / PARTIAL / NON_COMPLIANT / NOT_APPLICABLE / NOT_EVALUATED
    last_assessed_at TEXT,
    owner           TEXT NOT NULL DEFAULT 'IT Security',
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_pci_principle ON pci_requirements(principle_id);
CREATE INDEX IF NOT EXISTS idx_pci_status ON pci_requirements(status);

-- ============================================
-- 网络资产清单（CDE inventory）
-- ============================================
CREATE TABLE IF NOT EXISTS network_assets (
    asset_id        TEXT PRIMARY KEY,
    asset_name      TEXT NOT NULL,
    asset_type      TEXT NOT NULL,                      -- Web Server / App Server / DB / WAF / VPN / KMS
    ip_address      TEXT,
    cde_zone        TEXT NOT NULL,                      -- CDE / CONNECTED / OUT_OF_SCOPE
    in_cde_scope    INTEGER NOT NULL DEFAULT 0,
    encryption_at_rest INTEGER NOT NULL DEFAULT 0,
    tls_version     TEXT,                               -- TLS 1.2 / TLS 1.3
    security_group_rules TEXT,                          -- JSON
    last_scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_asset_cde ON network_assets(cde_zone);
CREATE INDEX IF NOT EXISTS idx_asset_scope ON network_assets(in_cde_scope);

-- ============================================
-- Token Vault（加密令牌库）
-- ============================================
CREATE TABLE IF NOT EXISTS token_vault (
    token_id        TEXT PRIMARY KEY,                   -- UUID
    token_value     TEXT NOT NULL,                     -- 加密后
    masked_pan      TEXT NOT NULL,                     -- 前 6 + 后 4（BIN + last4）
    pan_bin         TEXT NOT NULL,                     -- 前 6 位
    pan_last4       TEXT NOT NULL,                     -- 后 4 位
    card_brand      TEXT NOT NULL,                     -- Visa/MasterCard/Amex/JCB/UnionPay
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT,
    is_revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_token_bin ON token_vault(pan_bin);
CREATE INDEX IF NOT EXISTS idx_token_brand ON token_vault(card_brand);

-- ============================================
-- DLP 扫描结果（PanHunter findings）
-- ============================================
CREATE TABLE IF NOT EXISTS dlp_scan_findings (
    finding_id      TEXT PRIMARY KEY,
    source_file     TEXT NOT NULL,
    line_number     INTEGER,
    detected_pattern TEXT NOT NULL,                    -- PAN/CVV_FULL_CARD/CARD_BIN/EXPIRY/SAD
    severity        TEXT NOT NULL,                     -- CRITICAL / HIGH / MEDIUM / LOW
    sample_redacted TEXT NOT NULL,                     -- '411111******1111'
    luhn_valid       INTEGER NOT NULL,                  -- 0/1
    matched_at      TEXT NOT NULL DEFAULT (datetime('now')),
    status          TEXT NOT NULL DEFAULT 'OPEN'       -- OPEN / REMEDIATED / FALSE_POSITIVE
);

CREATE INDEX IF NOT EXISTS idx_dlp_severity ON dlp_scan_findings(severity);
CREATE INDEX IF NOT EXISTS idx_dlp_status ON dlp_scan_findings(status);
CREATE INDEX IF NOT EXISTS idx_dlp_pattern ON dlp_scan_findings(detected_pattern);

-- ============================================
-- SAQ-D 自评答案（PCI DSS v4.0 Self-Assessment Questionnaire - D）
-- ============================================
CREATE TABLE IF NOT EXISTS saq_d_answers (
    answer_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    req_id           TEXT NOT NULL,
    question         TEXT NOT NULL,
    response         TEXT NOT NULL,                     -- YES / NO / N/A / PARTIAL
    evidence_summary TEXT,
    assessed_by      TEXT NOT NULL DEFAULT 'GRC Team',
    assessed_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_saq_req ON saq_d_answers(req_id);

-- ============================================
-- Evidence Items（含 SHA-256 防篡改）
-- ============================================
CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_id      TEXT PRIMARY KEY,
    req_id           TEXT,
    source_name      TEXT NOT NULL,
    collected_at     TEXT NOT NULL DEFAULT (datetime('now')),
    content_payload  TEXT NOT NULL,
    sha256_hash      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_req ON evidence_items(req_id);

-- ============================================
-- 审计 trail
-- ============================================
CREATE TABLE IF NOT EXISTS audit_trail (
    audit_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    entity_type   TEXT,
    entity_id     TEXT,
    details       TEXT,
    occurred_at   TEXT NOT NULL DEFAULT (datetime('now'))
);