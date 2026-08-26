-- Public index of every LKS Notary payload found on chain.
--
-- Lives in the explorer database (db_lkschain), NOT in lks_notary, and is
-- filled by scripts/scan_chain.py reading the blockchain directly. It is
-- deliberately independent of the notary service: if the service disappeared
-- tomorrow, this table could still be rebuilt from the chain by anyone, which
-- is the property that makes the proofs credible.
--
-- The explorer's own `vout` table cannot be used for this: it stores only
-- address and amount, and an OP_RETURN output has neither.

CREATE TABLE IF NOT EXISTS `notary_onchain` (
  `ID`          bigint(20)    NOT NULL AUTO_INCREMENT,
  `TxID`        varchar(64)   NOT NULL,
  `BlockNum`    bigint(20)    NOT NULL,
  `BlockHash`   varchar(64)   NOT NULL,
  `BlockTime`   datetime      NOT NULL,
  `Version`     tinyint(4)    NOT NULL,
  `Type`        tinyint(4)    NOT NULL,   -- 1 = batch Merkle root, 2 = single document
  `Digest`      varchar(64)   NOT NULL,   -- hex, 32 bytes
  `SeenAt`      datetime      NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`ID`),
  UNIQUE KEY `tx_digest` (`TxID`, `Digest`),
  KEY `digest_idx` (`Digest`),
  KEY `block_idx` (`BlockNum`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Scanner bookmark, so a restart resumes instead of rescanning a million blocks.
CREATE TABLE IF NOT EXISTS `notary_scan_state` (
  `ID`              tinyint(4) NOT NULL PRIMARY KEY,
  `LastScannedNum`  bigint(20) NOT NULL,
  `UpdatedAt`       datetime   NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
