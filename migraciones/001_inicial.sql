CREATE TABLE usuarios (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  nombre TEXT NOT NULL CHECK (length(nombre) BETWEEN 1 AND 80),
  email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 254 AND email = lower(email)),
  clave_hash TEXT NOT NULL CHECK (clave_hash LIKE 'scrypt$%'),
  creado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
  clave_cambiada_en TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX usuarios_email_unico ON usuarios (email);

-- Cada inicio de sesión abre una "familia". Cada renovación agrega una fila nueva
-- a la familia y marca la anterior como usada. Si llega un token ya usado, alguien
-- lo copió: se revoca la familia entera.
CREATE TABLE sesiones (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  usuario_id BIGINT NOT NULL REFERENCES usuarios (id) ON DELETE CASCADE,
  familia UUID NOT NULL,
  token_hash BYTEA NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  creada_en TIMESTAMPTZ NOT NULL DEFAULT now(),
  expira_en TIMESTAMPTZ NOT NULL,
  usada_en TIMESTAMPTZ,
  revocada_en TIMESTAMPTZ,
  motivo_revocacion TEXT CHECK (motivo_revocacion IN ('salida', 'salida_total', 'reutilizacion', 'cambio_clave')),
  ip TEXT CHECK (length(ip) <= 64),
  agente TEXT CHECK (length(agente) <= 300)
);
CREATE INDEX sesiones_familia ON sesiones (familia);
CREATE INDEX sesiones_activas_usuario ON sesiones (usuario_id) WHERE revocada_en IS NULL AND usada_en IS NULL;

CREATE TABLE intentos_login (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email TEXT NOT NULL CHECK (length(email) <= 254),
  ip TEXT CHECK (length(ip) <= 64),
  exito BOOLEAN NOT NULL,
  creado_en TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX intentos_login_email ON intentos_login (email, creado_en DESC);
CREATE INDEX intentos_login_ip ON intentos_login (ip, creado_en DESC);
