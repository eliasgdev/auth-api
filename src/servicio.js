import { randomUUID } from 'node:crypto';
import { hashear, verificar, verificarFalso } from './claves.js';
import { firmarAcceso, nuevoTokenRenovacion, hashToken } from './tokens.js';

export class ErrorAuth extends Error {
  constructor(status, mensaje, extra = {}) {
    super(mensaje);
    this.status = status;
    Object.assign(this, extra);
  }
}

const VENTANA_MIN = 15;
const MAX_FALLOS_CORREO = 5;
const MAX_FALLOS_IP = 20;

export function crearServicio({ pool, config }) {
  async function emitir(cliente, { usuarioId, familia, ip, agente }) {
    const { token, hash } = nuevoTokenRenovacion();
    await cliente.query(
      `INSERT INTO sesiones (usuario_id, familia, token_hash, expira_en, ip, agente)
       VALUES ($1, $2, $3, now() + make_interval(days => $4), $5, $6)`,
      [usuarioId, familia, hash, config.renovacionDias, ip?.slice(0, 64) ?? null, agente?.slice(0, 300) ?? null],
    );
    return {
      acceso: firmarAcceso(config, { usuarioId, familia }),
      renovacion: token,
      tipo: 'Bearer',
      expira_en_segundos: config.accesoMinutos * 60,
    };
  }

  async function enTransaccion(fn) {
    const cliente = await pool.connect();
    try {
      await cliente.query('BEGIN');
      const r = await fn(cliente);
      await cliente.query('COMMIT');
      return r;
    } catch (err) {
      await cliente.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      cliente.release();
    }
  }

  return {
    async registrar({ nombre, email, clave }) {
      const hash = await hashear(clave);
      try {
        const { rows } = await pool.query(
          'INSERT INTO usuarios (nombre, email, clave_hash) VALUES ($1, $2, $3) RETURNING id, nombre, email, creado_en',
          [nombre, email, hash],
        );
        return rows[0];
      } catch (err) {
        if (err.code === '23505') throw new ErrorAuth(409, 'Ya existe una cuenta con ese correo. Inicia sesión o recupera tu clave.');
        throw err;
      }
    },

    async iniciarSesion({ email, clave, ip, agente }) {
      // Bloqueo por intentos fallidos desde el último acceso correcto (por correo y por IP).
      const { rows: [conteo] } = await pool.query(
        `SELECT
           (SELECT count(*) FROM intentos_login WHERE email = $1 AND NOT exito
              AND creado_en > greatest(now() - make_interval(mins => $3),
                coalesce((SELECT max(creado_en) FROM intentos_login WHERE email = $1 AND exito), '-infinity'))) AS por_correo,
           (SELECT count(*) FROM intentos_login WHERE ip = $2 AND NOT exito
              AND creado_en > now() - make_interval(mins => $3)) AS por_ip`,
        [email, ip ?? null, VENTANA_MIN],
      );
      if (Number(conteo.por_correo) >= MAX_FALLOS_CORREO || Number(conteo.por_ip) >= MAX_FALLOS_IP) {
        throw new ErrorAuth(429, `Demasiados intentos fallidos. Espera ${VENTANA_MIN} minutos e intenta de nuevo.`,
          { reintentar: VENTANA_MIN * 60 });
      }

      const { rows: [usuario] } = await pool.query('SELECT id, clave_hash FROM usuarios WHERE email = $1', [email]);
      const valida = usuario ? await verificar(clave, usuario.clave_hash) : await verificarFalso(clave);
      await pool.query('INSERT INTO intentos_login (email, ip, exito) VALUES ($1, $2, $3)', [email, ip ?? null, valida]);
      // Mismo mensaje si el correo no existe o si la clave está mal.
      if (!valida) throw new ErrorAuth(401, 'Correo o clave incorrectos.');

      return enTransaccion(c => emitir(c, { usuarioId: usuario.id, familia: randomUUID(), ip, agente }));
    },

    async renovar({ renovacion, ip, agente }) {
      const hash = hashToken(renovacion);
      return enTransaccion(async c => {
        const { rows: [s] } = await c.query(
          `SELECT id, usuario_id, familia, usada_en, revocada_en, expira_en <= now() AS vencida
             FROM sesiones WHERE token_hash = $1 FOR UPDATE`,
          [hash],
        );
        if (!s) throw new ErrorAuth(401, 'Sesión no válida. Inicia sesión de nuevo.');
        if (s.usada_en || s.revocada_en) {
          if (s.usada_en && !s.revocada_en) {
            // Un token ya cambiado volvió a llegar: alguien más lo tiene. Se cierra toda la familia.
            await c.query(
              `UPDATE sesiones SET revocada_en = now(), motivo_revocacion = 'reutilizacion'
                WHERE familia = $1 AND revocada_en IS NULL`,
              [s.familia],
            );
            return { reutilizado: true };
          }
          throw new ErrorAuth(401, 'Sesión cerrada. Inicia sesión de nuevo.');
        }
        if (s.vencida) throw new ErrorAuth(401, 'La sesión venció. Inicia sesión de nuevo.');
        await c.query('UPDATE sesiones SET usada_en = now() WHERE id = $1', [s.id]);
        return emitir(c, { usuarioId: Number(s.usuario_id), familia: s.familia, ip, agente });
      }).then(r => {
        // La revocación por reutilización se confirma antes de responder con el error.
        if (r.reutilizado) throw new ErrorAuth(401, 'Detectamos un uso extraño de tu sesión y la cerramos por seguridad. Inicia sesión de nuevo.');
        return r;
      });
    },

    // ¿La sesión (familia) del token de acceso sigue abierta? Así cerrar sesión surte efecto de inmediato.
    async sesionActiva({ usuarioId, familia }) {
      const { rowCount } = await pool.query(
        `SELECT 1 FROM sesiones WHERE familia = $1 AND usuario_id = $2
            AND revocada_en IS NULL AND usada_en IS NULL AND expira_en > now() LIMIT 1`,
        [familia, usuarioId],
      );
      return rowCount > 0;
    },

    async perfil(usuarioId) {
      const { rows: [u] } = await pool.query('SELECT id, nombre, email, creado_en FROM usuarios WHERE id = $1', [usuarioId]);
      return u ?? null;
    },

    async listarSesiones({ usuarioId, familia }) {
      const { rows } = await pool.query(
        `SELECT s.familia AS id, s.ip, s.agente, inicio.creada_en AS iniciada_en, s.creada_en AS ultima_renovacion
           FROM sesiones s
           JOIN LATERAL (SELECT min(creada_en) AS creada_en FROM sesiones WHERE familia = s.familia) inicio ON true
          WHERE s.usuario_id = $1 AND s.revocada_en IS NULL AND s.usada_en IS NULL AND s.expira_en > now()
          ORDER BY s.creada_en DESC`,
        [usuarioId],
      );
      return rows.map(r => ({ ...r, actual: r.id === familia }));
    },

    async cerrarSesion({ usuarioId, familia }) {
      await pool.query(
        `UPDATE sesiones SET revocada_en = now(), motivo_revocacion = 'salida'
          WHERE familia = $1 AND usuario_id = $2 AND revocada_en IS NULL`,
        [familia, usuarioId],
      );
    },

    async cerrarSesionPorId({ usuarioId, id }) {
      const { rowCount } = await pool.query(
        `UPDATE sesiones SET revocada_en = now(), motivo_revocacion = 'salida'
          WHERE familia = $1 AND usuario_id = $2 AND revocada_en IS NULL`,
        [id, usuarioId],
      );
      return rowCount > 0;
    },

    async cerrarTodas({ usuarioId, excepto = null, motivo = 'salida_total' }) {
      await pool.query(
        `UPDATE sesiones SET revocada_en = now(), motivo_revocacion = $3
          WHERE usuario_id = $1 AND revocada_en IS NULL AND ($2::uuid IS NULL OR familia <> $2::uuid)`,
        [usuarioId, excepto, motivo],
      );
    },

    async cambiarClave({ usuarioId, familia, actual, nueva }) {
      const { rows: [u] } = await pool.query('SELECT clave_hash FROM usuarios WHERE id = $1', [usuarioId]);
      if (!u || !(await verificar(actual, u.clave_hash))) {
        throw new ErrorAuth(400, 'Datos inválidos.', { campos: { actual: 'La clave actual no coincide.' } });
      }
      const hash = await hashear(nueva);
      await enTransaccion(async c => {
        await c.query('UPDATE usuarios SET clave_hash = $2, clave_cambiada_en = now() WHERE id = $1', [usuarioId, hash]);
        await c.query(
          `UPDATE sesiones SET revocada_en = now(), motivo_revocacion = 'cambio_clave'
            WHERE usuario_id = $1 AND revocada_en IS NULL AND familia <> $2`,
          [usuarioId, familia],
        );
      });
    },
  };
}
