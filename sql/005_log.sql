-- LKS Log — streams and seals.
-- Apply after 001_schema_mariadb.sql and 003_selfservice.sql.
--
-- A seal is notarised like any other proof: its canonical record is hashed and
-- the digest becomes a row in `notarizations`. Log lines never reach this
-- database; the only thing that arrives is the root of a tree built over salted
-- fingerprints on the customer's machine.

CREATE TABLE IF NOT EXISTS `log_streams` (
  `id`               char(36)     NOT NULL,
  `name`             varchar(120) NOT NULL,
  `requester_id`     char(36)     NOT NULL,      -- only this key may append
  `interval_seconds` int(11)      NOT NULL,
  `last_sequence`    bigint(20)   NOT NULL DEFAULT 0,
  `last_seal_hash`   varbinary(32) DEFAULT NULL,
  `created_at`       datetime(6)  NOT NULL,
  `updated_at`       datetime(6)  NOT NULL,
  PRIMARY KEY (`id`),
  KEY `requester_idx` (`requester_id`),
  CONSTRAINT `log_streams_requester_fk` FOREIGN KEY (`requester_id`) REFERENCES `api_keys` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `log_seals` (
  `id`               char(36)     NOT NULL,
  `stream_id`        char(36)     NOT NULL,
  `sequence`         bigint(20)   NOT NULL,
  `entries_root`     varbinary(32) DEFAULT NULL,  -- NULL on an empty batch
  `entry_count`      int(11)      NOT NULL,
  `window_start`     datetime(6)  NOT NULL,       -- declared by the agent
  `window_end`       datetime(6)  NOT NULL,
  `canonical_record` text         NOT NULL,       -- exactly what was hashed
  `seal_hash`        varbinary(32) NOT NULL,
  `previous_hash`    varbinary(32) DEFAULT NULL,  -- chains the seals of one stream
  `notarization_id`  char(36)     NOT NULL,       -- the proof carrying this seal
  `recorded_at`      datetime(6)  NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `stream_sequence` (`stream_id`, `sequence`),
  UNIQUE KEY `seal_hash` (`seal_hash`),
  CONSTRAINT `log_seals_stream_fk` FOREIGN KEY (`stream_id`) REFERENCES `log_streams` (`id`),
  CONSTRAINT `log_seals_notarization_fk` FOREIGN KEY (`notarization_id`)
      REFERENCES `notarizations` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
