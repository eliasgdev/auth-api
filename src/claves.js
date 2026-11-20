import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
// Una de las configuraciones equivalentes que recomienda OWASP para scrypt
// (N=2^15, r=8, p=3): 32 MiB por hash, apto para servidores pequeños.
const N = 2 ** 15, R = 8, P = 3, LARGO = 32;
const MAXMEM = 256 * N * R;

export async function hashear(clave) {
  const sal = randomBytes(16);
  const hash = await scryptAsync(clave.normalize('NFKC'), sal, LARGO, { N, r: R, p: P, maxmem: MAXMEM });
  return `scrypt$${N}$${R}$${P}$${sal.toString('base64url')}$${hash.toString('base64url')}`;
}

export async function verificar(clave, guardado) {
  const partes = String(guardado).split('$');
  if (partes.length !== 6 || partes[0] !== 'scrypt') return false;
  const [, n, r, p, salB64, hashB64] = partes;
  const esperado = Buffer.from(hashB64, 'base64url');
  const calculado = await scryptAsync(clave.normalize('NFKC'), Buffer.from(salB64, 'base64url'), esperado.length, {
    N: Number(n), r: Number(r), p: Number(p), maxmem: 256 * Number(n) * Number(r),
  });
  return calculado.length === esperado.length && timingSafeEqual(calculado, esperado);
}

// Hash de una clave que nadie conoce. Se verifica contra él cuando el correo no existe,
// para que la respuesta tarde lo mismo y no revele qué correos están registrados.
let hashFalso;
export async function verificarFalso(clave) {
  hashFalso ??= await hashear(randomBytes(24).toString('base64url'));
  await verificar(clave, hashFalso);
  return false;
}

const COMUNES = new Set([
  '1234567890', '12345678910', '0123456789', 'qwertyuiop', 'contraseña', 'contrasena', 'password1', 'password123',
  'iloveyou12', 'colombia123', 'administrador', 'abcdefghij', '1q2w3e4r5t', 'qwerty1234', 'abc1234567',
  'contraseña1', 'contrasena1', 'passw0rd123', 'aaaaaaaaaa', '1111111111', 'bienvenido1', 'teamo12345',
]);

// Devuelve el problema de la clave o null si sirve.
export function problemaDeClave(clave, { email, nombre } = {}) {
  if (typeof clave !== 'string') return 'Debe ser texto.';
  if (clave.length < 10) return 'Debe tener al menos 10 caracteres.';
  if (clave.length > 128) return 'Debe tener como máximo 128 caracteres.';
  const minus = clave.toLowerCase();
  if (COMUNES.has(minus) || /^(.)\1+$/.test(clave)) return 'Es demasiado común. Usa una frase que solo tú conozcas.';
  const local = email?.split('@')[0]?.toLowerCase();
  if (local && local.length >= 4 && minus.includes(local)) return 'No debe contener tu correo.';
  if (nombre && nombre.length >= 4 && minus.includes(nombre.toLowerCase())) return 'No debe contener tu nombre.';
  return null;
}
