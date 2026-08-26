-- LKS Notary -- schema for MariaDB 10.5+.
--
-- Digests are VARBINARY, never hex strings: half the storage and a case
-- mismatch becomes impossible. UUIDs are CHAR(36) for readability in logs.

CREATE TABLE IF NOT EXISTS api_keys (
    id          CHAR(36)     NOT NULL PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    key_hash    VARBINARY(32) NOT NULL UNIQUE,  -- SHA-256 of the key; the key itself is never stored
    rate_limit  INT          NOT NULL DEFAULT 60,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS batches (
    id              CHAR(36)      NOT NULL PRIMARY KEY,
    merkle_root     VARBINARY(32) NOT NULL,
    leaf_count      INT           NOT NULL,
    txid            VARBINARY(32),
    block_hash      VARBINARY(32),
    block_height    INT,
    confirmations   INT           NOT NULL DEFAULT 0,
    chainlocked     BOOLEAN       NOT NULL DEFAULT FALSE,
    ots_proof       LONGBLOB,
    ots_upgraded_at DATETIME(6),
    created_at      DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX batches_open_idx (block_hash, created_at),
    INDEX batches_root_idx (merkle_root)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS notarizations (
    id              CHAR(36)      NOT NULL PRIMARY KEY,
    document_hash   VARBINARY(32) NOT NULL,
    hash_algo       VARCHAR(16)   NOT NULL DEFAULT 'sha256',
    idempotency_key VARCHAR(128)  UNIQUE,
    requester_id    CHAR(36),
    metadata_json   LONGTEXT      CHECK (metadata_json IS NULL OR JSON_VALID(metadata_json)),
    leaf_hash       VARBINARY(32) NOT NULL,
    leaf_index      INT,                        -- position inside the batch tree
    received_at     DATETIME(6)   NOT NULL,
    batch_id        CHAR(36),
    status          ENUM('pending','batched','confirmed','anchored') NOT NULL DEFAULT 'pending',
    INDEX notarizations_pending_idx (status, received_at, leaf_hash),
    INDEX notarizations_document_idx (document_hash),
    INDEX notarizations_batch_idx (batch_id, leaf_index),
    CONSTRAINT notarizations_batch_fk FOREIGN KEY (batch_id) REFERENCES batches(id),
    CONSTRAINT notarizations_requester_fk FOREIGN KEY (requester_id) REFERENCES api_keys(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Append-only audit trail, chained by hash: any retroactive edit of the
-- database becomes detectable. It answers disputes about how the service
-- behaved, which is a separate question from the on-chain proof.
CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts         DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    actor      VARCHAR(128),
    action     VARCHAR(64)   NOT NULL,
    payload    LONGTEXT      CHECK (payload IS NULL OR JSON_VALID(payload)),
    prev_hash  VARBINARY(32),
    entry_hash VARBINARY(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The trigger bodies are single statements on purpose: a BEGIN...END block
-- would need DELIMITER, which is a command of the `mysql` client and is not
-- understood by Navicat, DBeaver or a driver executing the file.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
