-- Uniquement si vous choisissez MySQL : à exécuter une fois dans phpMyAdmin (onglet SQL).
-- Avec SQLite (réglage par défaut), les tables sont créées automatiquement.
-- Aucune adresse e-mail n'est stockée en clair : seulement des empreintes (email_hash) et des données chiffrées dans le navigateur.

CREATE TABLE IF NOT EXISTS vpc_users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  email_hash CHAR(64) NOT NULL UNIQUE,
  pub TEXT NULL,
  keys_json TEXT NULL,
  check_hash CHAR(64) NULL,
  auth_hash VARCHAR(255) NULL,
  fails SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  session_gen INT UNSIGNED NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpc_codes (
  email_hash CHAR(64) NOT NULL PRIMARY KEY,
  code_hash VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  sent_at DATETIME NOT NULL,
  ip_hash CHAR(32) NOT NULL DEFAULT '',
  INDEX idx_ip (ip_hash, sent_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vpc_canvases (
  id CHAR(12) NOT NULL PRIMARY KEY,
  owner_id INT UNSIGNED NOT NULL,
  owner_wrap TEXT NOT NULL,
  meta_ct TEXT NOT NULL,
  data_ct MEDIUMTEXT NOT NULL,
  rev INT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_owner (owner_id, updated_at),
  CONSTRAINT fk_vpc_owner FOREIGN KEY (owner_id) REFERENCES vpc_users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Partages : role 'view' (lecture seule) ou 'edit' ; wrap vide tant que la personne invitée n'a pas créé son compte.
CREATE TABLE IF NOT EXISTS vpc_shares (
  canvas_id CHAR(12) NOT NULL,
  email_hash CHAR(64) NOT NULL,
  role VARCHAR(8) NOT NULL DEFAULT 'view',
  label_ct TEXT NOT NULL,
  wrap TEXT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (canvas_id, email_hash),
  INDEX idx_share_email (email_hash),
  CONSTRAINT fk_vpc_share_canvas FOREIGN KEY (canvas_id) REFERENCES vpc_canvases (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
