import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crearLimitador } from '../src/limitador.js';
import { leerConfig } from '../src/config.js';
import { problemaDeClave } from '../src/claves.js';

function simular(limitador, ip) {
  const res = { cabeceras: {}, codigo: 200, setHeader(k, v) { this.cabeceras[k] = v; }, status(c) { this.codigo = c; return this; }, json(b) { this.cuerpo = b; } };
  let siguio = false;
  limitador({ ip }, res, () => { siguio = true; });
  return { ...res, siguio };
}

test('limitador: corta después del límite y se reinicia al minuto', () => {
  let t = 0;
  const lim = crearLimitador({ porMinuto: 3, ahora: () => t });
  for (let i = 0; i < 3; i++) assert.ok(simular(lim, '1.1.1.1').siguio);
  const cuarta = simular(lim, '1.1.1.1');
  assert.equal(cuarta.codigo, 429);
  assert.equal(cuarta.cabeceras['Retry-After'], 60);
  assert.ok(simular(lim, '2.2.2.2').siguio, 'otra IP no se afecta');
  t = 60_000;
  assert.ok(simular(lim, '1.1.1.1').siguio);
});

test('config: no arranca con un secreto corto o sin base', () => {
  assert.throws(() => leerConfig({ DATABASE_URL: 'postgres://x', JWT_SECRET: 'corto' }), /JWT_SECRET/);
  assert.throws(() => leerConfig({ JWT_SECRET: 'x'.repeat(40) }), /DATABASE_URL/);
  const c = leerConfig({ DATABASE_URL: 'postgres://x', JWT_SECRET: 'x'.repeat(40), CORS_ORIGINS: 'https://a.co, https://b.co' });
  assert.deepEqual(c.origenes, ['https://a.co', 'https://b.co']);
  assert.equal(c.accesoMinutos, 15);
});

test('política de claves', () => {
  assert.equal(problemaDeClave('una frase bastante larga'), null);
  assert.match(problemaDeClave('corta'), /10 caracteres/);
  assert.match(problemaDeClave('x'.repeat(129)), /128/);
  assert.match(problemaDeClave('Contraseña1'), /común/);
  assert.match(problemaDeClave('mariaperez2026!', { nombre: 'María', email: 'mariaperez@x.co' }), /correo/);
});
