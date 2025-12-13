import re
from typing import List, Tuple

import pandas as pd

# ===========================
#  TLS / JA3 helper constants
# ===========================

# Map TLS version string -> enum
# theo spec trong report: TLS1.0→1, 1.1→2, 1.2→3, 1.3→4
VERSION_ENUM = {
    "TLS 1.0": 1,
    "TLS 1.1": 2,
    "TLS 1.2": 3,
    "TLS 1.3": 4,
}

# Bộ mã nhóm elliptic curve / DH groups hiện đại
# (JA3 field 4 - Supported Groups)
MODERN_GROUPS = {
    29,  # x25519
    23,  # secp256r1 (P-256)
    24,  # secp384r1 (P-384)
    25,  # secp521r1 (coi như modern luôn)
}

# Bảng gắn nhãn cipher theo "bảng nội bộ"
# Mỗi entry:
#   cipher_id: {
#       "name": "...",
#       "strong": True/False,
#       "weak": True/False,
#       "pfs": True/False,   # có Perfect Forward Secrecy (DHE/ECDHE/TLS1.3)
#       "aead": True/False,  # AEAD (GCM/CHACHA/CCM)
#       "kx": "ECDHE"/"DHE"/"RSA"/"ECDH"/"DH"/"TLS13"/"UNKNOWN"
#   }
CIPHER_POLICIES = {
    # TLS 1.3 AEAD ciphers (tất cả đều mạnh + PFS)
    4865: {"name": "TLS_AES_128_GCM_SHA256",        "strong": True, "weak": False, "pfs": True,  "aead": True,  "kx": "TLS13"},
    4866: {"name": "TLS_AES_256_GCM_SHA384",        "strong": True, "weak": False, "pfs": True,  "aead": True,  "kx": "TLS13"},
    4867: {"name": "TLS_CHACHA20_POLY1305_SHA256",  "strong": True, "weak": False, "pfs": True,  "aead": True,  "kx": "TLS13"},
    4868: {"name": "TLS_AES_128_CCM_SHA256",        "strong": True, "weak": False, "pfs": True,  "aead": True,  "kx": "TLS13"},
    4869: {"name": "TLS_AES_128_CCM_8_SHA256",      "strong": True, "weak": False, "pfs": True,  "aead": True,  "kx": "TLS13"},

    # Một số ECDHE + GCM (mạnh, PFS, AEAD)
    49195: {"name": "ECDHE_RSA_AES_128_GCM_SHA256", "strong": True, "weak": False, "pfs": True,  "aead": True,  "kx": "ECDHE"},
    49196: {"name": "ECDHE_RSA_AES_256_GCM_SHA384", "strong": True, "weak": False, "pfs": True,  "aead": True,  "kx": "ECDHE"},
    49199: {"name": "ECDHE_ECDSA_AES_128_GCM_SHA256","strong": True,"weak": False, "pfs": True,  "aead": True,  "kx": "ECDHE"},
    49200: {"name": "ECDHE_ECDSA_AES_256_GCM_SHA384","strong": True,"weak": False, "pfs": True,  "aead": True,  "kx": "ECDHE"},

    # Một số ECDHE + CBC (PFS nhưng không AEAD)
    49171: {"name": "ECDHE_RSA_AES_128_CBC_SHA256", "strong": False, "weak": False, "pfs": True, "aead": False, "kx": "ECDHE"},
    49172: {"name": "ECDHE_RSA_AES_256_CBC_SHA384", "strong": False, "weak": False, "pfs": True, "aead": False, "kx": "ECDHE"},

    # RSA + CBC (không PFS, xem là yếu/legacy hơn)
    47:  {"name": "RSA_AES_128_CBC_SHA",            "strong": False, "weak": True,  "pfs": False, "aead": False, "kx": "RSA"},
    53:  {"name": "RSA_AES_256_CBC_SHA",            "strong": False, "weak": True,  "pfs": False, "aead": False, "kx": "RSA"},
    10:  {"name": "RSA_3DES_EDE_CBC_SHA",           "strong": False, "weak": True,  "pfs": False, "aead": False, "kx": "RSA"},  # 3DES
    5:   {"name": "RSA_RC4_128_SHA",                "strong": False, "weak": True,  "pfs": False, "aead": False, "kx": "RSA"},  # RC4
    4:   {"name": "RSA_RC4_128_MD5",                "strong": False, "weak": True,  "pfs": False, "aead": False, "kx": "RSA"},  # RC4
    # ... (tự mở rộng thêm nếu cần)
}

# ==================
#  Helper functions
# ==================

def normalize_version_string(version: str) -> str:
    """Chuẩn hóa version về dạng 'TLS 1.2', 'SSL 3.0', ..."""
    if not isinstance(version, str):
        return ""
    s = version.strip().upper()
    # Bắt (TLS|SSL) + optional 'v' + số version
    m = re.search(r"(TLS|SSL)\s*v? ?(\d(?:\.\d)?)", s)
    if not m:
        return s
    proto = m.group(1)
    ver = m.group(2)
    return f"{proto} {ver}"


def compute_tls_version_features(version: str):
    """Tính tls_version_enum, is_legacy_version, RULE_DEPRECATED_VERSION."""
    norm = normalize_version_string(version)
    enum_val = VERSION_ENUM.get(norm, 0 if norm.startswith("SSL") else -1)

    # is_legacy_version: 1 nếu TLS version < 1.2
    is_legacy = 0
    if enum_val != -1 and enum_val < VERSION_ENUM.get("TLS 1.2"):
        is_legacy = 1
    if norm.startswith("SSL"):
        is_legacy = 1

    # RULE_DEPRECATED_VERSION: SSLv2/SSLv3/TLS1.0/TLS1.1
    deprecated = {
        "SSL 2.0", "SSL 2", "SSL 3.0", "SSL 3",
        "TLS 1.0", "TLS 1.1",
    }
    rule_deprecated = 1 if norm in deprecated else 0

    return enum_val, is_legacy, rule_deprecated


def parse_ja3_string(ja3_string: str):
    """
    Tách JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    Trả về: (list_ciphers, list_extensions, list_groups, list_ec_formats)
    """
    if not isinstance(ja3_string, str) or not ja3_string:
        return [], [], [], []

    parts = ja3_string.strip().split(",")
    # đảm bảo đủ 5 field
    while len(parts) < 5:
        parts.append("")

    _, ciphers_field, exts_field, groups_field, ec_formats_field = parts

    def parse_int_list(field: str):
        if not field:
            return []
        return [int(x) for x in field.split("-") if x]

    ciphers = parse_int_list(ciphers_field)
    exts = parse_int_list(exts_field)
    groups = parse_int_list(groups_field)
    ec_formats = parse_int_list(ec_formats_field)
    return ciphers, exts, groups, ec_formats


def parse_ja3s_string(ja3s_string: str):
    """
    JA3S string: SSLVersion,Cipher,Extensions
    Trả về: (server_version_id, server_cipher_id, extensions_list)
    """
    if not isinstance(ja3s_string, str) or not ja3s_string:
        return None, None, []

    parts = ja3s_string.strip().split(",")
    while len(parts) < 3:
        parts.append("")

    version_field, cipher_field, exts_field = parts

    try:
        version_id = int(version_field) if version_field else None
    except ValueError:
        version_id = None

    try:
        cipher_id = int(cipher_field) if cipher_field else None
    except ValueError:
        cipher_id = None

    exts = [int(x) for x in exts_field.split("-") if x] if exts_field else []
    return version_id, cipher_id, exts


def classify_cipher(cipher_id: int):
    """Trả về thông tin cipher; nếu không biết thì cho UNKNOWN."""
    props = CIPHER_POLICIES.get(cipher_id)
    if props is None:
        return {
            "name": "UNKNOWN",
            "strong": False,
            "weak": False,
            "pfs": False,
            "aead": False,
            "kx": "UNKNOWN",
        }
    return props


def compute_feature_row(row: pd.Series) -> pd.Series:
    """
    Tính toàn bộ feature/rule đúng như trong report cho 1 bản ghi TLS.
    row cần có: 'version', 'ja3_string', 'ja3s_string'
    """
    version = row.get("version", "")
    ja3_string = row.get("ja3_string", "")
    ja3s_string = row.get("ja3s_string", "")

    # --- Parse JA3 ---
    ciphers, exts, groups, ec_formats = parse_ja3_string(ja3_string)
    num_ciphers = len(ciphers)
    num_groups = len(groups)

    num_strong = 0
    num_weak = 0
    num_pfs = 0
    num_aead = 0

    for cid in ciphers:
        props = classify_cipher(cid)
        if props["strong"]:
            num_strong += 1
        if props["weak"]:
            num_weak += 1
        if props["pfs"]:
            num_pfs += 1
        if props["aead"]:
            num_aead += 1

    weak_cipher_ratio = (num_weak / num_ciphers) if num_ciphers > 0 else 0.0
    pfs_cipher_ratio = (num_pfs / num_ciphers) if num_ciphers > 0 else 0.0
    supports_pfs = 1 if num_pfs > 0 else 0

    prefers_pfs = 0
    if num_ciphers > 0:
        first_props = classify_cipher(ciphers[0])
        prefers_pfs = 1 if first_props["pfs"] else 0

    # --- Elliptic curve / DH group features ---
    num_modern = len([g for g in groups if g in MODERN_GROUPS])
    uses_modern_group = 1 if num_modern > 0 else 0
    legacy_group_ratio = (
        (num_groups - num_modern) / num_groups if num_groups > 0 else 0.0
    )

    # --- TLS version features ---
    tls_version_enum, is_legacy_version, rule_deprecated_version = compute_tls_version_features(version)

    # --- Server side rules (JA3S) ---
    _, server_cipher_id, _ = parse_ja3s_string(ja3s_string)
    rule_weak_cipher = 0
    rule_no_pfs = 0

    if server_cipher_id is not None:
        sp = classify_cipher(server_cipher_id)
        # RULE_WEAK_CIPHER: server chọn RC4/3DES/... (cipher weak)
        if sp["weak"]:
            rule_weak_cipher = 1

        # RULE_NO_PFS: server chọn RSA/ECDH/DH (KHÔNG DHE/ECDHE/TLS1.3) và version != TLS1.3
        norm_version = normalize_version_string(version)
        if sp["kx"] in {"RSA", "ECDH", "DH"} and norm_version not in {"TLS 1.3"}:
            rule_no_pfs = 1

    # RULE_CBC_ONLY: tls.version >= TLS1.2 và không có cipher AEAD
    rule_cbc_only = 0
    if tls_version_enum >= VERSION_ENUM.get("TLS 1.2", 3) and num_aead == 0:
        rule_cbc_only = 1

    return pd.Series(
        {
            "tls_version_enum": tls_version_enum,
            "is_legacy_version": is_legacy_version,
            "RULE_DEPRECATED_VERSION": rule_deprecated_version,
            "num_ciphers": num_ciphers,
            "num_strong_ciphers": num_strong,
            "num_weak_ciphers": num_weak,
            "weak_cipher_ratio": weak_cipher_ratio,
            "supports_pfs": supports_pfs,
            "prefers_pfs": prefers_pfs,
            "pfs_cipher_ratio": pfs_cipher_ratio,
            "num_groups": num_groups,
            "uses_modern_group": uses_modern_group,
            "legacy_group_ratio": legacy_group_ratio,
            "RULE_WEAK_CIPHER": rule_weak_cipher,
            "RULE_NO_PFS": rule_no_pfs,
            "RULE_CBC_ONLY": rule_cbc_only,
        }
    )


# ==========================================
#  Runtime helper: TLS event -> feature vec
# ==========================================

def build_feature_vector_from_event(evt: dict) -> List[float]:
    """
    Nhận 1 event TLS (dict đọc từ eve.json) và trả về list feature số
    theo đúng thứ tự mà compute_feature_row sử dụng khi training.

    Dùng trong python-real-time-service:
        - log_utils.parse_tls_event(...) -> evt
        - features = build_feature_vector_from_event(evt)
        - scaler.transform([features]) -> đưa vào model
    """
    tls = evt.get("tls", {}) or {}

    version = tls.get("version", "UNKNOWN")
    ja3_obj = tls.get("ja3") or {}
    ja3s_obj = tls.get("ja3s") or {}

    row = pd.Series(
        {
            "version": version,
            "ja3_string": ja3_obj.get("string", ""),
            "ja3s_string": ja3s_obj.get("string", ""),
        }
    )

    features_series = compute_feature_row(row)

    # đảm bảo kiểu float, trả về dạng list để feed vào numpy/scaler
    return features_series.astype("float64").tolist()
