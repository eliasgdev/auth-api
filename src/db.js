import pg from 'pg';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const CARPETA = fileURLToPath(new URL('../migraciones/', import.meta.url));

export function crearPool(databaseUrl, opciones = {}) {
  return new pg.Pool({ connectionString: databaseUrl, max: 10, ...opciones });
}

// Aplica en orden los .sql que falten, cada uno en su transacción.
// El candado de sesión evita que dos instancias migren a la vez.
export async function migrar(pool) {
  const cliente = await pool.connect();
  try {
    await cliente.query('SELECT pg_advisory_lock(727272)');
    await cliente.query(`CREATE TABLE IF NOT EXISTS esquema_migraciones (
      nombre TEXT PRIMARY KEY, aplicada_en TIMESTAMPTZ NOT NULL DEFAULT now())`);
    const hechas = new Set((await cliente.query('SELECT nombre FROM esquema_migraciones')).rows.map(r => r.nombre));
    const archivos = (await readdir(CARPETA)).filter(f => f.endsWith('.sql')).sort();
    const aplicadas = [];
    for (const archivo of archivos) {
      if (hechas.has(archivo)) continue;
      const sql = await readFile(CARPETA + archivo, 'utf8');
      await cliente.query('BEGIN');
      try {
        await cliente.query(sql);
        await cliente.query('INSERT INTO esquema_migraciones (nombre) VALUES ($1)', [archivo]);
        await cliente.query('COMMIT');
        aplicadas.push(archivo);
      } catch (err) {
        await cliente.query('ROLLBACK');
        throw new Error(`Falló la migración ${archivo}: ${err.message}`);
      }
    }
    return aplicadas;
  } finally {
    await cliente.query('SELECT pg_advisory_unlock(727272)').catch(() => {});
    cliente.release();
  }
}
