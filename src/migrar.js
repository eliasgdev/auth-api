import { crearPool, migrar } from './db.js';

if (!process.env.DATABASE_URL) {
  console.error('Falta DATABASE_URL.');
  process.exit(1);
}
const pool = crearPool(process.env.DATABASE_URL);
try {
  const aplicadas = await migrar(pool);
  console.log(aplicadas.length ? `Migraciones aplicadas: ${aplicadas.join(', ')}` : 'La base ya estaba al día.');
} finally {
  await pool.end();
}
