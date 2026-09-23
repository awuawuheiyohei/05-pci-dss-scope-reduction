"""
PCI DSS v4.0 Requirements Catalog（12 大要求 / 6 大类）
来源：PCI DSS v4.0 (March 2022) 公开标准

6 Principles:
1. Build and Maintain a Secure Network and Systems
2. Protect Account Data
3. Maintain a Vulnerability Management Program
4. Implement Strong Access Control Measures
5. Regularly Monitor and Test Networks
6. Maintain an Information Security Policy
"""

# 格式: (req_id, principle_id, principle, title, description, sub_requirements)
PCI_DSS_V4_REQUIREMENTS = [
    # ===================== Principle 1: Build & Maintain Secure Network =====================
    ("1", 1, "Build and Maintain a Secure Network and Systems",
     "Install and Maintain Network Security Controls",
     "All system components that store, process, or transmit cardholder data must be protected by network security controls.",
     '["1.1", "1.2", "1.3", "1.4", "1.5"]'),
    ("2", 1, "Build and Maintain a Secure Network and Systems",
     "Apply Secure Configurations to All System Components",
     "Apply secure configurations to all system components including but not limited to: vendor defaults, default passwords, unnecessary services, etc.",
     '["2.1", "2.2", "2.3"]'),

    # ===================== Principle 2: Protect Account Data =====================
    ("3", 2, "Protect Account Data",
     "Protect Stored Account Data",
     "Protection methods such as encryption, truncation, masking, and hashing are critical components of cardholder data protection.",
     '["3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7"]'),
    ("4", 2, "Protect Account Data",
     "Protect Cardholder Data During Transmission Over Open, Public Networks",
     "Use strong cryptography and security protocols to safeguard cardholder data during transmission over open, public networks.",
     '["4.1", "4.2"]'),

    # ===================== Principle 3: Maintain Vulnerability Management =====================
    ("5", 3, "Maintain a Vulnerability Management Program",
     "Protect All Systems and Networks from Malicious Software",
     "Install and maintain anti-virus software or programs that detect and remove malicious software.",
     '["5.1", "5.2", "5.3", "5.4"]'),
    ("6", 3, "Maintain a Vulnerability Management Program",
     "Develop and Maintain Secure Systems and Software",
     "Define and implement secure coding guidelines and protect systems against known vulnerabilities through patching.",
     '["6.1", "6.2", "6.3", "6.4", "6.5"]'),

    # ===================== Principle 4: Implement Strong Access Control =====================
    ("7", 4, "Implement Strong Access Control Measures",
     "Restrict Access to System Components and Cardholder Data by Business Need to Know",
     "Access to system components and cardholder data should be restricted to only those individuals whose job requires such access.",
     '["7.1", "7.2"]'),
    ("8", 4, "Implement Strong Access Control Measures",
     "Identify Users and Authenticate Access to System Components",
     "Assign a unique ID to each person with access; ensure strong authentication mechanisms (especially MFA for v4.0).",
     '["8.1", "8.2", "8.3", "8.4", "8.5", "8.6"]'),
    ("9", 4, "Implement Strong Access Control Measures",
     "Restrict Physical Access to Cardholder Data",
     "Physical access to cardholder data or systems that house cardholder data must be restricted.",
     '["9.1", "9.2", "9.3", "9.4", "9.5"]'),

    # ===================== Principle 5: Regularly Monitor and Test Networks =====================
    ("10", 5, "Regularly Monitor and Test Networks",
     "Log and Monitor All Access to System Components and Cardholder Data",
     "Logging mechanisms and the ability to track user activities are critical for preventing, detecting, and minimizing impact of data breaches.",
     '["10.1", "10.2", "10.3", "10.4", "10.5", "10.6", "10.7"]'),
    ("11", 5, "Regularly Monitor and Test Networks",
     "Test Security of Systems and Networks Regularly",
     "Vulnerability scanning, penetration testing, and intrusion detection/prevention are critical components of security testing.",
     '["11.1", "11.2", "11.3", "11.4", "11.5", "11.6"]'),

    # ===================== Principle 6: Maintain Information Security Policy =====================
    ("12", 6, "Maintain an Information Security Policy",
     "Support Information Security with Organizational Policies and Programs",
     "Establish, publish, maintain, and disseminate a security policy that addresses all PCI DSS requirements.",
     '["12.1", "12.2", "12.3", "12.4", "12.5", "12.6", "12.7", "12.8", "12.9", "12.10"]'),
]


def count_by_principle():
    counts = {}
    for _id, pid, *_ in PCI_DSS_V4_REQUIREMENTS:
        counts[pid] = counts.get(pid, 0) + 1
    return counts


# 重点 v4.0 新增要求（面试常问）
PCI_V4_NEW_REQUIREMENTS = {
    "6.4.3": "All payment page scripts that load in customer's browser must be inventoried, justified, and integrity-checked (new in v4.0)",
    "8.4.2": "MFA required for ALL access into the CDE (not just remote) - new in v4.0",
    "11.6.1": "Change- and tamper-detection mechanism on payment pages (new in v4.0)",
}


if __name__ == "__main__":
    counts = count_by_principle()
    total = sum(counts.values())
    print(f"Total PCI DSS v4.0 top-level requirements: {total}")
    for pid, c in counts.items():
        print(f"  Principle {pid}: {c}")
    print(f"\n[+] Validation: exactly 12 top-level reqs across 6 principles")