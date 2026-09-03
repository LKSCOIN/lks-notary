-- LKS Trace — lots, events and genealogy.
-- Apply after 001_schema_mariadb.sql and 003_selfservice.sql.
--
-- A traceability event is notarised like any other proof: its canonical record
-- is hashed and the digest becomes a row in `notarizations`, so it travels in
-- the same Merkle batch and inherits the same chain and Bitcoin anchoring.
-- These tables hold what the batch cannot: the meaning of the event.

CREATE TABLE IF NOT EXISTS `trace_lots` (
  `lot_id`       varchar(120) NOT NULL,
  `gtin`         varchar(14)  DEFAULT NULL,
  `batch`        varchar(20)  DEFAULT NULL,
  `serial`       varchar(20)  DEFAULT NULL,
  `product_code` varchar(64)  DEFAULT NULL,
  `organization` varchar(160) NOT NULL,
  `requester_id` char(36)     DEFAULT NULL,
  `status`       enum('active','recalled') NOT NULL DEFAULT 'active',
  `created_at`   datetime(6)  NOT NULL,
  `updated_at`   datetime(6)  NOT NULL,
  PRIMARY KEY (`lot_id`),
  KEY `gtin_idx` (`gtin`, `batch`),
  KEY `org_idx` (`organization`),
  CONSTRAINT `trace_lots_requester_fk` FOREIGN KEY (`requester_id`) REFERENCES `api_keys` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `trace_events` (
  `id`              char(36)     NOT NULL,
  `lot_id`          varchar(120) NOT NULL,
  `event_type`      varchar(16)  NOT NULL,
  `occurred_at`     datetime(6)  NOT NULL,
  `recorded_at`     datetime(6)  NOT NULL,
  `organization`    varchar(160) NOT NULL,
  `facility`        varchar(160) DEFAULT NULL,
  `quantity`        varchar(32)  DEFAULT NULL,   -- string: JCS refuses floats
  `unit`            varchar(16)  DEFAULT NULL,
  `metadata_hash`   varbinary(32) DEFAULT NULL,  -- commitment to off-chain data
  `canonical_record` text        NOT NULL,       -- exactly what was hashed
  `event_hash`      varbinary(32) NOT NULL,
  `previous_hash`   varbinary(32) DEFAULT NULL,  -- chains events of one lot
  `notarization_id` char(36)     DEFAULT NULL,   -- the proof carrying this event
  PRIMARY KEY (`id`),
  UNIQUE KEY `event_hash` (`event_hash`),
  KEY `lot_time_idx` (`lot_id`, `occurred_at`),
  KEY `type_idx` (`event_type`),
  CONSTRAINT `trace_events_lot_fk` FOREIGN KEY (`lot_id`) REFERENCES `trace_lots` (`lot_id`),
  CONSTRAINT `trace_events_notarization_fk` FOREIGN KEY (`notarization_id`)
      REFERENCES `notarizations` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Parent/child relations, one row per edge. Kept separate from the events so a
-- recall can walk the graph without parsing JSON, and so a lot can have several
-- parents (MERGE) or several children (SPLIT) without duplicating rows.
CREATE TABLE IF NOT EXISTS `trace_links` (
  `id`         bigint(20)   NOT NULL AUTO_INCREMENT,
  `parent_lot` varchar(120) NOT NULL,
  `child_lot`  varchar(120) NOT NULL,
  `event_id`   char(36)     NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `edge` (`parent_lot`, `child_lot`, `event_id`),
  KEY `parent_idx` (`parent_lot`),
  KEY `child_idx` (`child_lot`),
  CONSTRAINT `trace_links_event_fk` FOREIGN KEY (`event_id`) REFERENCES `trace_events` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
