import { leerConfig } from './config.js';
import { crearPool, migrar } from './db.js';
import { crearApp } from './app.js';

const config = leerConfig();
const pool = crearPool(config.databaseUrl);
await migrar(pool);

const servidor = crearApp({ pool, config }).listen(config.puerto, () => {
  console.log(`auth-api escuchando en el puerto ${config.puerto}`);
});

// Apagado ordenado: deja terminar las peticiones en curso y cierra la base.
for (const senal of ['SIGTERM', 'SIGINT']) {
  process.on(senal, () => servidor.close(() => pool.end().then(() => process.exit(0))));
}
