-- ==========================================
--  Flow Anomaly Detection (CICFlowMeter) - MySQL schema (minimal)
--  Chốt: chỉ lưu đúng feature-set dùng để train trong 1 cột JSON (features_json)
--   - flow_events: flow metadata + features_json + ML verdict
--   - firewall_actions: commands enforced by firewall-controller
--   - request_nonces: anti-replay store for HMAC-signed ingest
-- ==========================================

CREATE DATABASE IF NOT EXISTS tls_ids
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE tls_ids;

-- 1) flow_events
CREATE TABLE IF NOT EXISTS flow_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,

    event_time DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    sensor_name VARCHAR(64) NULL,
    flow_id BIGINT NULL,

    src_ip VARCHAR(45) NOT NULL,
    src_port INT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    dst_port INT NULL,
    proto VARCHAR(16) NULL,

    -- Exact training feature set (CIC-style names) stored as JSON
    features_json JSON NOT NULL,

    -- ML outputs
    ae_error DOUBLE NULL,
    ae_anom TINYINT(1) NOT NULL DEFAULT 0,
    iso_score DOUBLE NULL,
    iso_anom TINYINT(1) NULL,

    is_anomaly TINYINT(1) NOT NULL DEFAULT 0,
    verdict VARCHAR(16) NOT NULL DEFAULT 'normal',

    INDEX idx_time (event_time),
    INDEX idx_src (src_ip),
    INDEX idx_anom (is_anomaly)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2) firewall_actions
CREATE TABLE IF NOT EXISTS firewall_actions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(45) NOT NULL,
    action_type VARCHAR(16) NOT NULL, -- BLOCK / UNBLOCK
    target VARCHAR(64) NULL,
    description TEXT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    INDEX idx_fw_time (created_at),
    INDEX idx_fw_src (src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3) request_nonces (anti-replay)
CREATE TABLE IF NOT EXISTS request_nonces (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scope VARCHAR(32) NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,

    UNIQUE KEY uq_scope_nonce (scope, nonce),
    INDEX idx_nonce_exp (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
