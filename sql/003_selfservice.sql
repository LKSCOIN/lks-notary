-- Self-service API keys and the anonymous quota counter.
-- Apply after 001_schema_mariadb.sql.

-- Daily counter for anonymous submissions. The IP address is never stored:
-- only a salted SHA-256 of it, which is enough to count and useless as a log.
-- Change ANON_IP_SALT and every counter resets — the cheapest possible purge.
CREATE TABLE IF NOT EXISTS `anon_quota` (
  `id`      bigint(20)    NOT NULL AUTO_INCREMENT,
  `ip_hash` varbinary(32) NOT NULL,
  `day`     date          NOT NULL,
  `count`   int(11)       NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_day` (`ip_hash`, `day`),
  KEY `day_idx` (`day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Pending key requests. The email is kept on purpose: knowing who submitted
-- what is the reason this flow exists. The token is stored hashed, like the
-- key, so a copy of the database cannot be used to claim a pending request.
CREATE TABLE IF NOT EXISTS `key_requests` (
  `id`           char(36)      NOT NULL,
  `email`        varchar(254)  NOT NULL,
  `organisation` varchar(160)  DEFAULT NULL,
  `token_hash`   varbinary(32) NOT NULL,
  `ip_hash`      varbinary(32) DEFAULT NULL,
  `requested_at` datetime(6)   NOT NULL,
  `expires_at`   datetime(6)   NOT NULL,
  `confirmed_at` datetime(6)   DEFAULT NULL,
  `api_key_id`   char(36)      DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token_hash`),
  KEY `email_idx` (`email`),
  KEY `ip_recent_idx` (`ip_hash`, `requested_at`),
  CONSTRAINT `key_requests_api_key_fk` FOREIGN KEY (`api_key_id`) REFERENCES `api_keys` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- The worker deletes expired quota rows, so the application user needs DELETE
-- on that one table only:
--   GRANT DELETE ON lks_notary.anon_quota TO 'notary'@'localhost';
