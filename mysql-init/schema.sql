-- ==========================================
--  TLS Anomaly Detection - MySQL schema
--  (rút gọn cho đồ án không có Front-end)
--  Chỉ giữ:
--   - tls_events: log TLS + kết quả ML
--   - request_nonces: (tuỳ chọn) chống replay cho ingest HMAC

CREATE DATABASE IF NOT EXISTS tls_ids
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE tls_ids;

--  1. Bảng tls_events
--    - Lưu log TLS + kết quả ML
CREATE TABLE tls_events (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Thời gian
    event_time      DATETIME(6) NOT NULL,                 -- timestamp từ Suricata
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    -- Thông tin mạng
    sensor_name     VARCHAR(255) NULL,
    flow_id         BIGINT UNSIGNED NULL,
    src_ip          VARCHAR(45) NOT NULL,                 -- IPv4/IPv6
    src_port        INT UNSIGNED NULL,
    dst_ip          VARCHAR(45) NOT NULL,
    dst_port        INT UNSIGNED NULL,
    proto           VARCHAR(16) NULL,                     -- tcp/udp...

    -- Thông tin TLS / JA3 (raw)
    tls_version     VARCHAR(16) NULL,                     -- ví dụ: "TLS 1.2"
    ja3_hash        CHAR(32) NULL,                        -- MD5 hex
    ja3_string      TEXT NULL,
    ja3s_string     TEXT NULL,                            -- JA3S (server) nếu muốn debug
    sni             TEXT NULL,
    cipher_suites   TEXT NULL,
    tls_groups      TEXT NULL,

    --  Feature từ feature_extractor.py
    -- TLS version features
    tls_version_enum        TINYINT      NULL,            -- 1,2,3,4...
    is_legacy_version       TINYINT(1)   NULL,            -- 1 nếu < TLS1.2 hoặc SSL
    rule_deprecated_version TINYINT(1)   NULL,            -- RULE_DEPRECATED_VERSION

    -- Cipher list features
    num_ciphers             SMALLINT     NULL,
    num_strong_ciphers      SMALLINT     NULL,
    num_weak_ciphers        SMALLINT     NULL,
    weak_cipher_ratio       DOUBLE       NULL,
    supports_pfs            TINYINT(1)   NULL,
    prefers_pfs             TINYINT(1)   NULL,
    pfs_cipher_ratio        DOUBLE       NULL,

    -- Group (elliptic curve / DH) features
    num_groups              SMALLINT     NULL,
    uses_modern_group       TINYINT(1)   NULL,
    legacy_group_ratio      DOUBLE       NULL,

    -- Rule flags
    rule_weak_cipher        TINYINT(1)   NULL,            -- RULE_WEAK_CIPHER
    rule_no_pfs             TINYINT(1)   NULL,            -- RULE_NO_PFS
    rule_cbc_only           TINYINT(1)   NULL,            -- RULE_CBC_ONLY


    --  Kết quả model realtime (main.py)
    ae_error        DOUBLE       NULL,
    ae_anom         TINYINT(1)   NULL,                    -- 1 nếu ae_error > AE_THRESHOLD
    iso_score       DOUBLE       NULL,
    iso_anom        TINYINT(1)   NULL,                    -- 1 nếu iso_score < ISO_THRESHOLD
    is_anomaly      TINYINT(1)   NOT NULL DEFAULT 0,      -- anomaly tổng (OR)

    verdict         ENUM('NORMAL', 'ANOMALOUS')
                        NOT NULL DEFAULT 'NORMAL',        -- mapping từ is_anomaly

    -- (tuỳ chọn) vẫn giữ 1 cột JSON để future-proof
    features_json   JSON NULL,

    PRIMARY KEY (id),

    -- Index cơ bản
    INDEX idx_tls_events_event_time (event_time),
    INDEX idx_tls_events_src_ip (src_ip),
    INDEX idx_tls_events_dst_ip (dst_ip),
    INDEX idx_tls_events_ja3_hash (ja3_hash),
    INDEX idx_tls_events_verdict_time (verdict, event_time),

    -- Index cho truy vấn policy / rule
    INDEX idx_tls_events_legacy (is_legacy_version, tls_version_enum),
    INDEX idx_tls_events_rules  (rule_deprecated_version, rule_weak_cipher, rule_no_pfs, rule_cbc_only),
    INDEX idx_tls_events_anom   (is_anomaly)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


--  2. Bảng request_nonces
--    - Lưu nonce đã dùng để chống replay (HMAC + nonce + timestamp)
CREATE TABLE request_nonces (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scope           VARCHAR(64) NOT NULL,
    nonce           VARCHAR(64) NOT NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at      DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_scope_nonce (scope, nonce),
    INDEX idx_nonces_expires (expires_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


--  3. Bảng firewall_actions
--    - Lưu yêu cầu BLOCK/UNBLOCK IP để firewall-controller polling và apply iptables
CREATE TABLE firewall_actions (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    src_ip          VARCHAR(45) NOT NULL,
    action_type     ENUM('BLOCK', 'UNBLOCK') NOT NULL,

    target          VARCHAR(64) NULL,           -- vd: 'iptables'
    description     TEXT NULL,

    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    executed_at     DATETIME(6) NULL,
    expires_at      DATETIME(6) NULL,

    -- Integrity (backend -> firewall-controller)
    hmac_ts         BIGINT NULL,
    hmac_nonce      VARCHAR(64) NULL,
    hmac_sig        CHAR(64) NULL,

    status          ENUM('PENDING', 'EXECUTED', 'FAILED', 'CANCELLED')
                        NOT NULL DEFAULT 'PENDING',
    error_message   TEXT NULL,

    PRIMARY KEY (id),

    INDEX idx_fw_actions_status (status),
    INDEX idx_fw_actions_created_at (created_at),
    INDEX idx_fw_actions_src_ip (src_ip),
    UNIQUE KEY uniq_fw_hmac_nonce (hmac_nonce)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;
