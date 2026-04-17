CREATE TABLE IF NOT EXISTS users (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  apple_sub VARCHAR(255) UNIQUE NOT NULL,
  tz VARCHAR(64) NOT NULL DEFAULT 'UTC',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocks (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  start_ts DATETIME NOT NULL,
  end_ts   DATETIME NOT NULL,
  source   ENUM('phone','checkin','manual','plan') NOT NULL,
  app      VARCHAR(128) NULL,
  activity VARCHAR(255) NULL,
  category VARCHAR(64)  NULL,
  client_id VARCHAR(64) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_user_client (user_id, client_id),
  INDEX idx_user_start (user_id, start_ts),
  INDEX idx_user_end (user_id, end_ts),
  CONSTRAINT fk_blocks_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS minutes (
  user_id BIGINT NOT NULL,
  ts DATETIME NOT NULL,
  source   ENUM('phone','checkin','manual','gap') NOT NULL,
  app      VARCHAR(128) NULL,
  activity VARCHAR(255) NULL,
  category VARCHAR(64)  NULL,
  PRIMARY KEY (user_id, ts)
);

CREATE TABLE IF NOT EXISTS categories (
  user_id BIGINT NOT NULL,
  keyword VARCHAR(64) NOT NULL,
  category VARCHAR(64) NOT NULL,
  color    VARCHAR(16) NULL,
  PRIMARY KEY (user_id, keyword)
);

CREATE TABLE IF NOT EXISTS planned_blocks (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL,
  day DATE NOT NULL,
  start_ts DATETIME NOT NULL,
  end_ts   DATETIME NOT NULL,
  category VARCHAR(64) NULL,
  note     VARCHAR(255) NULL,
  INDEX idx_user_day (user_id, day)
);
