-- Khoi tao co so du lieu cho he thong phat hien xam nhap TLS-IDS
CREATE DATABASE IF NOT EXISTS tls_ids
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE tls_ids;

-- Bang flow_events: Luu tru metadata cua luu luong mang va ket qua phan loai tu AI
CREATE TABLE IF NOT EXISTS flow_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,

    -- Thoi gian xay ra su kien mang va thoi gian ghi vao he thong
    event_time DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    -- Thong tin nguon thu thap (Sensor)
    sensor_name VARCHAR(64) NULL,
    flow_id BIGINT NULL,

    -- Thong tin mang 5-tuple (IP nguon/dich, Port nguon/dich, Giao thuc)
    src_ip VARCHAR(45) NOT NULL,
    src_port INT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    dst_port INT NULL,
    proto VARCHAR(16) NULL,

    -- Luu tru toan bo 34 dac trung CICFlowMeter duoi dang JSON de toi uu cau truc
    features_json JSON NOT NULL,

    -- Ket qua tinh toan tu mo hinh MLP (Diem so va nhan bat thuong)
    mlp_score DOUBLE NULL,
    mlp_anom TINYINT(1) NOT NULL DEFAULT 0,
    -- Ket qua tu mo hinh Isolation Forest de doi chieu (neu co)
    iso_score DOUBLE NULL,
    iso_anom TINYINT(1) NULL,

    -- Ket luan cuoi cung cua he thong ve luong du lieu
    is_anomaly TINYINT(1) NOT NULL DEFAULT 0,
    verdict VARCHAR(16) NOT NULL DEFAULT 'normal',

    -- Danh chi muc (Index) de tang toc do truy van khi hien thi len Dashboard
    INDEX idx_time (event_time),
    INDEX idx_src (src_ip),
    INDEX idx_anom (is_anomaly)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bang firewall_actions: Luu tru cac yeu cau chan/mo IP cho module Firewall thuc thi
CREATE TABLE IF NOT EXISTS firewall_actions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(45) NOT NULL,
    action_type VARCHAR(16) NOT NULL, -- Loai hanh dong: BLOCK hoac UNBLOCK
    target VARCHAR(64) NULL,         -- Muc tieu thuc thi (vi du: iptables)
    description TEXT NULL,           -- Ly do chan (vi du: phat hien tan cong tu mo hinh MLP)
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    INDEX idx_fw_time (created_at),
    INDEX idx_fw_src (src_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bang request_nonces: Luu tru ma dung mot lan de chong tan cong phat lai (Replay Attack)
CREATE TABLE IF NOT EXISTS request_nonces (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scope VARCHAR(32) NOT NULL,      -- Pham vi su dung (vi du: ingest du lieu)
    nonce VARCHAR(128) NOT NULL,     -- Ma ngau nhien duy nhat cho moi request
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL, -- Thoi gian het han cua ma Nonce

    -- Rang buoc duy nhat de dam bao mot ma Nonce khong bi su dung lai
    UNIQUE KEY uq_scope_nonce (scope, nonce),
    INDEX idx_nonce_exp (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;