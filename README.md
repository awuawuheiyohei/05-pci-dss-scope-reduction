# PCI DSS v4.0 Scope Reduction & Audit Engine

> **一句话**：FastAPI + 12 PCI DSS v4.0 原则 + CDE 网络隔离检查 + PanHunter (Luhn+Regex) + AES-256-GCM Tokenization
> 对齐 **Senior IT GRC Specialist** / **Senior Cyber Security Analyst** 岗位。

---

## ✨ 状态

**v1.0 端到端已上线**（2026-09-23）— **30/30 测试通过**。

---

## 🎯 解决什么问题

**典型场景**：Trip.Biz / 跨境 SaaS 接受 Visa/MasterCard/Amex 等国际信用卡，必须通过 **PCI DSS v4.0** 审计。

**痛点**：
1. **CDE 范围蔓延**：前端页/订单微服务/报表库任何触碰 PAN，全部企业云落入审计范围（成本几何级数）
2. **SAD 存储红线**：CVV/CVC 即使加密也禁止存储；日志无意记录明文卡号 = 重大违规 + 高额罚款
3. **PCI DSS v4.0 新规强制**：Req 6.4.3 / 11.6.1（前端防篡改监测）、Req 8.4.2（**所有 CDE 访问必须 MFA**）

**本项目交付**：
- ✅ PCI DSS v4.0 **12 项 top-level requirements**（6 大原则）
- ✅ **CDE Network Isolation Checker**：扫描 15 个网络资产 + TLS + encryption + 范围缩减可视化
- ✅ **PanHunter DLP Engine**：Luhn + Regex 检测 PAN/CVV/Expiry 泄漏（敏感鉴别数据 SAD 红线）
- ✅ **AES-256-GCM Tokenization Gateway**：PAN → token（合规存储 + 反向解密用于审计）
- ✅ **SAQ-D Rulebook**：12 req 自评 + 加权得分（YES=1.0 / PARTIAL=0.5 / NO=0.0）
- ✅ **SHA-256 防篡改证据**：每条 evidence 立即 hash，verify 独立可重算

---

## 📁 项目结构

```
05-pci-dss-scope-reduction/
├── README.md
├── pyproject.toml
├── .env.example
├── .gitignore
├── main.py                     # CLI 入口
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI 入口（端口 5032）
│   ├── schema.sql             # 7 张表
│   ├── models/
│   │   ├── db.py
│   │   ├── pci_requirements.py   # 12 项 PCI DSS v4.0 + 6 原则
│   │   └── seed.py               # 12 reqs + 15 网络资产 + 8 DLP + 10 tokens
│   ├── collectors/
│   │   └── engine.py             # 4 engines + Luhn + Tokenization + SHA-256
│   └── api/
│       └── routes.py             # 18 个 REST 端点
├── static/
│   └── index.html                # Dashboard UI（6 tab，28KB）
├── tests/
│   └── test_pci.py               # 30 个测试
├── data/
└── docs/
    └── PRD.md                    # 完整需求文档
```

---

## 🚀 快速开始

```bash
cd /Users/jiangwenrui/Downloads/mass/05-pci-dss-scope-reduction
python3 main.py serve
# → http://localhost:5032  (Dashboard)
# → http://localhost:5032/docs  (Swagger)
```

---

## 📊 Dashboard 6 个 Tab

| Tab | 内容 |
|---|---|
| 📋 **12 Requirements** | PCI v4.0 12 项 + 6 原则 + 状态 |
| 🌐 **CDE Network** | 15 个资产可视化（Scope Reduction 33.3%） |
| 🔍 **PanHunter DLP** | 8 条 finding + 临时文本扫描 |
| 🔐 **Tokenization** | 10 个已 token + 手动 Tokenize 新 PAN |
| 📝 **SAQ-D** | 12 req 自评 + 加权得分 |
| ⚙️ **Engines** | 4 个引擎手动/批量运行 |

---

## 🛡️ 4 个 Collector Engine 详解

### Engine 1: CDE Network Isolation Checker (Req 1 + 2)
- 扫描 `network_assets` 表 15 个资产
- 校验 CDE 资产 **必须 TLS 1.3 + encryption_at_rest**
- 校验 CONNECTED 资产必须 TLS ≥ 1.2
- **Scope Reduction 目标**: CDE ≤ 20% / CONNECTED ≤ 30% / OUT_OF_SCOPE ≥ 50%

### Engine 2: PanHunter DLP (Req 3 + 10)
- **Luhn Check** 验证 PAN 真实性（业界标准）
- **Regex 检测** CVV_FULL_CARD / EXPIRY / CARD_BIN
- **SAD 红线检测**：PCI v4.0 禁止 CVV/CVC 任何形式存储（包括 log）
- **临时扫描**：POST `/collectors/scan-text` adhoc 扫描任意文本

### Engine 3: Tokenization Gateway (Req 3.5 + 3.6)
- **AES-256-GCM** 加密 PAN
- BIN 检测（Visa/MasterCard/Amex/JCB/UnionPay/Discover）
- 返回 masked_pan + token preview
- Key rotation 季度强制（PCI Req 3.6.4）

### Engine 4: SAQ-D Rulebook (Req 1-12)
- 12 req 完整自评
- 加权得分：YES=1.0 / PARTIAL=0.5 / NO=0.0
- 满分 100% (N/A 排除)
- 自动写入 `saq_d_answers` 表

---

## 🧪 测试

```bash
python3 -m pytest tests/ -v
# 30 passed in 0.33s
```

**覆盖范围**：
- ✅ 12 项 PCI v4.0 完整性 + 6 原则分布
- ✅ v4.0 新增要求（Req 6.4.3 / 8.4.2 / 11.6.1）
- ✅ Luhn 校验 + 6 卡组织识别
- ✅ Tokenization 加密/解密 roundtrip
- ✅ PanHunter PAN/CVV/Expiry 检测
- ✅ 4 个引擎全部跑通 + SHA-256 篡改检测
- ✅ CDE 网络隔离验证（TLS + encryption）
- ✅ 端到端 smoke：seed → 4 engines → tamper → fail

---

## 🌐 REST API 摘要

| Method | Path | 说明 |
|---|---|---|
| GET | `/api/health` `/stats` | 健康 + KPI |
| GET | `/api/requirements` `/requirements/{id}` | 12 项 PCI 列表 + 详情 |
| PUT | `/api/requirements/{id}` | 更新 PCI status |
| GET | `/api/assets` | CDE 网络资产（按 zone 过滤） |
| GET | `/api/dlp-findings` | PanHunter findings |
| PUT | `/api/dlp-findings/{id}` | 标记 REMEDIATED / FALSE_POSITIVE |
| GET | `/api/tokens` | Token Vault |
| POST | `/api/tokens/tokenize` | 新 PAN → Token |
| GET | `/api/saq-d` | SAQ-D 自评答案 |
| POST | `/api/collectors/run-all` | 一键跑 4 引擎 |
| POST | `/api/collectors/{name}` | 单引擎 |
| POST | `/api/collectors/scan-text` | adhoc PanHunter 扫描 |
| POST | `/api/evidence/{id}/verify` | 验证 SHA-256 |
| GET | `/api/audit/export?format=csv` | 导出 CSV |

---

## 🎤 面试讲法

**故事 1 · 为什么 CDE Scope Reduction 是关键？**
> "**CDE 范围**决定了 PCI DSS 审计成本。如果前端 web 页 + 订单微服务 + 报表库都触碰 PAN，**整个企业云**都要审计（几百台服务器）—— 成本几何级数。
> 
> 我的设计：把 15 个资产分成 3 个 zone：
> - **CDE** (5 个) —— 必须 TLS 1.3 + encryption + QSA 现场审
> - **CONNECTED** (5 个) —— 连接 CDE 但不存 PAN，应 WAF + 网关隔离
> - **OUT_OF_SCOPE** (5 个) —— 严格隔离，零 PCI 审计成本
> 
> 当前 scope reduction **33.3%**（5/15 OUT_OF_SCOPE）。业内最佳实践是 ≥ 50%。"

**故事 2 · PAN 加密存储 ≠ SAD 可以存储**
> "**PCI v3.2.1 → v4.0 最重要变化**：CVV/CVC **即使加密也禁止存储**（Req 3.3.1）。
> 
> 这意味着：
> 1. 任何日志系统记录请求体 → 自动违规
> 2. 任何 cache 写明文卡号 → 自动违规
> 3. 任何 backup 含 PAN → 必须 AES-256 + 季度 key rotation
> 
> **PanHunter DLP 引擎**专门检测这种 SAD 泄漏：CVV regex + 过期日 regex + Luhn 校验 —— 找出真正高风险的 finding，不是只数 PAN 字串。"

**故事 3 · Tokenization vs Encryption 区别？**
> "**Encryption（加密）**：双向，原文可还原。**用于 backup / audit / 数据交换**。
> 
> **Tokenization（令牌化）**：**单向 / 双因子**，原文不存储。**用于生产数据库**（即使 DB 被拖，原文也找不回）。
> 
> 我的设计用 **AES-256-GCM**（带认证标签），符合 PCI Req 3.6：
> - nonce + ciphertext 一起 → 防止重放
> - 仅 token vault 服务持有 master key（演示用 key，生产应来自 HashiCorp Vault / AWS KMS）
> - 季度强制 key rotation（Req 3.6.4）"

**故事 4 · PCI v4.0 三个最关键新要求**
> "1. **Req 6.4.3** —— 所有支付页 JS 必须 inventoried + integrity-checked（防 Magecart 攻击）
> 2. **Req 8.4.2** —— **所有** CDE 访问必须 MFA（v3.2.1 只要求远程）
> 3. **Req 11.6.1** —— 支付页必须 change/tamper detection mechanism
> 
> 这 3 个反映 PCI v4.0 的核心精神：**从静态合规 → 持续监测 + 主动防御**。"

---

## 📜 License

MIT — 自由使用、修改、二次分发。

## 📝 PRD 来源

本项目基于 `Interview/Security_and_GRC_14_Projects_Plan/05_PCIDSS_Scope_Reduction_and_Audit_Prep.md` 完整规划。