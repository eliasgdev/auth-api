import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { crearPool, migrar } from '../src/db.js';
import { crearApp } from '../src/app.js';
import { leerConfig } from '../src/config.js';

const URL_BASE = process.env.DATABASE_URL ?? 'postgres://auth:auth@localhost:55435/auth';
const esquema = `prueba_${randomBytes(4).toString('hex')}`;
let pool, servidor, url, admin;

before(async () => {
  admin = new pg.Client({ connectionString: URL_BASE });
  await admin.connect();
  await admin.query(`CREATE SCHEMA ${esquema}`);
  pool = crearPool(URL_BASE, { options: `-c search_path=${esquema}` });
  await migrar(pool);
  const config = leerConfig({
    DATABASE_URL: URL_BASE,
    JWT_SECRET: randomBytes(48).toString('base64'),
    LIMITE_POR_MINUTO: '1000',
  });
  const app = crearApp({ pool, config });
  await new Promise(r => { servidor = app.listen(0, r); });
  url = `http://127.0.0.1:${servidor.address().port}/api/auth`;
});

after(async () => {
  servidor?.close();
  await pool?.end();
  await admin.query(`DROP SCHEMA ${esquema} CASCADE`);
  await admin.end();
});

async function pedir(metodo, ruta, { cuerpo, token } = {}) {
  const res = await fetch(url + ruta, {
    method: metodo,
    headers: {
      ...(cuerpo !== undefined && { 'Content-Type': 'application/json' }),
      ...(token && { Authorization: `Bearer ${token}` }),
    },
    body: cuerpo === undefined ? undefined : typeof cuerpo === 'string' ? cuerpo : JSON.stringify(cuerpo),
  });
  const texto = await res.text();
  return { status: res.status, cuerpo: texto ? JSON.parse(texto) : null, headers: res.headers };
}

let n = 0;
const nuevoUsuario = () => ({ nombre: 'Ana Pérez', email: `ana${++n}@ejemplo.co`, clave: 'tres perros en la montaña' });
async function registrarYEntrar() {
  const u = nuevoUsuario();
  assert.equal((await pedir('POST', '/registro', { cuerpo: u })).status, 201);
  const login = await pedir('POST', '/login', { cuerpo: { email: u.email, clave: u.clave } });
  assert.equal(login.status, 200);
  return { u, ...login.cuerpo };
}

test('registro: crea la cuenta y no devuelve la clave', async () => {
  const u = nuevoUsuario();
  const r = await pedir('POST', '/registro', { cuerpo: { ...u, email: `  ${u.email.toUpperCase()} ` } });
  assert.equal(r.status, 201);
  assert.equal(r.cuerpo.usuario.email, u.email);
  assert.equal(r.cuerpo.usuario.clave_hash, undefined);
  assert.equal((await pedir('POST', '/registro', { cuerpo: u })).status, 409);
});

test('registro: valida campos, rechaza extras y claves débiles', async () => {
  const r = await pedir('POST', '/registro', { cuerpo: { nombre: '', email: 'no-es-correo', clave: 'x', rol: 'admin' } });
  assert.equal(r.status, 400);
  assert.ok(r.cuerpo.campos.nombre);
  assert.ok(r.cuerpo.campos.email);
  assert.equal(r.cuerpo.campos.rol, 'Campo no permitido.');
  for (const clave of ['corta', '1234567890', 'aaaaaaaaaaaa']) {
    const d = await pedir('POST', '/registro', { cuerpo: { ...nuevoUsuario(), clave } });
    assert.equal(d.status, 400, clave);
    assert.ok(d.cuerpo.campos.clave);
  }
  const conCorreo = nuevoUsuario();
  const d = await pedir('POST', '/registro', { cuerpo: { ...conCorreo, clave: `${conCorreo.email.split('@')[0]}-secreto` } });
  assert.equal(d.cuerpo.campos.clave, 'No debe contener tu correo.');
});

test('login: mismo mensaje si el correo no existe o la clave está mal', async () => {
  const { u } = await registrarYEntrar();
  const malaClave = await pedir('POST', '/login', { cuerpo: { email: u.email, clave: 'otra clave cualquiera' } });
  const noExiste = await pedir('POST', '/login', { cuerpo: { email: 'nadie@ejemplo.co', clave: 'otra clave cualquiera' } });
  assert.equal(malaClave.status, 401);
  assert.equal(noExiste.status, 401);
  assert.equal(malaClave.cuerpo.error, noExiste.cuerpo.error);
  assert.equal(malaClave.headers.get('www-authenticate'), 'Bearer');
});

test('login: bloquea el correo tras 5 fallos y vuelve a contar tras un acceso correcto', async () => {
  const u = nuevoUsuario();
  await pedir('POST', '/registro', { cuerpo: u });
  for (let i = 0; i < 4; i++) await pedir('POST', '/login', { cuerpo: { email: u.email, clave: 'equivocada 123' } });
  assert.equal((await pedir('POST', '/login', { cuerpo: { email: u.email, clave: u.clave } })).status, 200);
  for (let i = 0; i < 5; i++) await pedir('POST', '/login', { cuerpo: { email: u.email, clave: 'equivocada 123' } });
  const bloqueado = await pedir('POST', '/login', { cuerpo: { email: u.email, clave: u.clave } });
  assert.equal(bloqueado.status, 429);
  assert.equal(bloqueado.headers.get('retry-after'), '900');
});

test('acceso: /yo con token, sin token y con token alterado', async () => {
  const { acceso, u } = await registrarYEntrar();
  const yo = await pedir('GET', '/yo', { token: acceso });
  assert.equal(yo.status, 200);
  assert.equal(yo.cuerpo.usuario.email, u.email);
  assert.equal(yo.headers.get('cache-control'), 'no-store');
  assert.equal((await pedir('GET', '/yo')).status, 401);
  const [h, p, f] = acceso.split('.');
  assert.equal((await pedir('GET', '/yo', { token: `${h}.${p}.${f.slice(0, -2)}xx` })).status, 401);
});

test('acceso: rechaza un token con alg "none"', async () => {
  const { acceso } = await registrarYEntrar();
  const [, payload] = acceso.split('.');
  const cabecera = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  assert.equal((await pedir('GET', '/yo', { token: `${cabecera}.${payload}.` })).status, 401);
});

test('renovar: entrega tokens nuevos y el viejo deja de servir', async () => {
  const { renovacion } = await registrarYEntrar();
  const r1 = await pedir('POST', '/renovar', { cuerpo: { renovacion } });
  assert.equal(r1.status, 200);
  assert.notEqual(r1.cuerpo.renovacion, renovacion);
  assert.equal((await pedir('GET', '/yo', { token: r1.cuerpo.acceso })).status, 200);
});

test('renovar: reutilizar un token ya usado cierra toda la sesión', async () => {
  const { renovacion } = await registrarYEntrar();
  const legitimo = await pedir('POST', '/renovar', { cuerpo: { renovacion } });
  const ladron = await pedir('POST', '/renovar', { cuerpo: { renovacion } });
  assert.equal(ladron.status, 401);
  assert.match(ladron.cuerpo.error, /uso extraño/);
  // El token que tenía el usuario legítimo también quedó revocado.
  assert.equal((await pedir('POST', '/renovar', { cuerpo: { renovacion: legitimo.cuerpo.renovacion } })).status, 401);
  assert.equal((await pedir('GET', '/yo', { token: legitimo.cuerpo.acceso })).status, 401);
});

test('renovar: token inventado o mal formado', async () => {
  assert.equal((await pedir('POST', '/renovar', { cuerpo: { renovacion: randomBytes(32).toString('base64url') } })).status, 401);
  assert.equal((await pedir('POST', '/renovar', { cuerpo: { renovacion: 'abc' } })).status, 400);
});

test('salir: el token de acceso deja de servir de inmediato', async () => {
  const { acceso, renovacion } = await registrarYEntrar();
  assert.equal((await pedir('POST', '/salir', { token: acceso })).status, 204);
  assert.equal((await pedir('GET', '/yo', { token: acceso })).status, 401);
  assert.equal((await pedir('POST', '/renovar', { cuerpo: { renovacion } })).status, 401);
});

test('sesiones: listar, cerrar otra y salir de todo', async () => {
  const { u, acceso } = await registrarYEntrar();
  const otra = (await pedir('POST', '/login', { cuerpo: { email: u.email, clave: u.clave } })).cuerpo;
  const lista = await pedir('GET', '/sesiones', { token: acceso });
  assert.equal(lista.cuerpo.sesiones.length, 2);
  assert.equal(lista.cuerpo.sesiones.filter(s => s.actual).length, 1);

  const ajena = lista.cuerpo.sesiones.find(s => !s.actual);
  assert.equal((await pedir('DELETE', `/sesiones/${ajena.id}`, { token: acceso })).status, 204);
  assert.equal((await pedir('GET', '/yo', { token: otra.acceso })).status, 401);
  assert.equal((await pedir('DELETE', '/sesiones/no-es-uuid', { token: acceso })).status, 404);

  assert.equal((await pedir('POST', '/salir-de-todo', { token: acceso })).status, 204);
  assert.equal((await pedir('GET', '/yo', { token: acceso })).status, 401);
});

test('un usuario no puede cerrar sesiones de otro', async () => {
  const a = await registrarYEntrar();
  const b = await registrarYEntrar();
  const idB = (await pedir('GET', '/sesiones', { token: b.acceso })).cuerpo.sesiones[0].id;
  assert.equal((await pedir('DELETE', `/sesiones/${idB}`, { token: a.acceso })).status, 404);
  assert.equal((await pedir('GET', '/yo', { token: b.acceso })).status, 200);
});

test('cambiar clave: exige la actual y cierra las demás sesiones', async () => {
  const { u, acceso } = await registrarYEntrar();
  const otra = (await pedir('POST', '/login', { cuerpo: { email: u.email, clave: u.clave } })).cuerpo;
  const mala = await pedir('PATCH', '/clave', { token: acceso, cuerpo: { actual: 'no es esta clave', nueva: 'una frase nueva y larga' } });
  assert.equal(mala.status, 400);
  assert.ok(mala.cuerpo.campos.actual);
  const igual = await pedir('PATCH', '/clave', { token: acceso, cuerpo: { actual: u.clave, nueva: u.clave } });
  assert.equal(igual.cuerpo.campos.nueva, 'Debe ser distinta de la actual.');

  assert.equal((await pedir('PATCH', '/clave', { token: acceso, cuerpo: { actual: u.clave, nueva: 'una frase nueva y larga' } })).status, 204);
  assert.equal((await pedir('GET', '/yo', { token: acceso })).status, 200);
  assert.equal((await pedir('GET', '/yo', { token: otra.acceso })).status, 401);
  assert.equal((await pedir('POST', '/login', { cuerpo: { email: u.email, clave: u.clave } })).status, 401);
  assert.equal((await pedir('POST', '/login', { cuerpo: { email: u.email, clave: 'una frase nueva y larga' } })).status, 200);
});

test('JSON mal formado y cuerpo enorme', async () => {
  assert.equal((await pedir('POST', '/login', { cuerpo: '{"email":' })).status, 400);
  assert.equal((await pedir('POST', '/login', { cuerpo: { email: 'a@b.co', clave: 'x'.repeat(10000) } })).status, 413);
});

test('la base guarda solo hashes, nunca claves ni tokens', async () => {
  const { u, renovacion } = await registrarYEntrar();
  const { rows: [usr] } = await pool.query('SELECT clave_hash FROM usuarios WHERE email = $1', [u.email]);
  assert.match(usr.clave_hash, /^scrypt\$32768\$8\$3\$/);
  assert.ok(!usr.clave_hash.includes(u.clave));
  const { rows } = await pool.query('SELECT token_hash FROM sesiones');
  assert.ok(rows.every(r => r.token_hash.length === 32));
  assert.ok(!rows.some(r => r.token_hash.toString('base64url') === renovacion));
});
