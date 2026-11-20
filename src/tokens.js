import jwt from 'jsonwebtoken';
import { randomBytes, createHash } from 'node:crypto';

const EMISOR = 'auth-api';

export function firmarAcceso(config, { usuarioId, familia }) {
  return jwt.sign({ sid: familia }, config.jwtSecreto, {
    algorithm: 'HS256',
    subject: String(usuarioId),
    issuer: EMISOR,
    audience: EMISOR,
    expiresIn: `${config.accesoMinutos}m`,
  });
}

// Algoritmo, emisor y audiencia fijos: un token firmado de otra forma no pasa.
export function verificarAcceso(config, token) {
  const datos = jwt.verify(token, config.jwtSecreto, { algorithms: ['HS256'], issuer: EMISOR, audience: EMISOR });
  if (typeof datos.sub !== 'string' || typeof datos.sid !== 'string') throw new Error('token incompleto');
  return { usuarioId: Number(datos.sub), familia: datos.sid };
}

// Token de renovación opaco: 256 bits aleatorios. En la base solo se guarda su SHA-256.
export function nuevoTokenRenovacion() {
  const token = randomBytes(32).toString('base64url');
  return { token, hash: hashToken(token) };
}

export function hashToken(token) {
  return createHash('sha256').update(token).digest();
}
