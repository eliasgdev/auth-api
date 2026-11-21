// Configuración leída una sola vez y validada al arrancar: si falta algo, la API no inicia.
export function leerConfig(env = process.env) {
  const errores = [];
  const secreto = env.JWT_SECRET ?? '';
  if (secreto.length < 32) errores.push('JWT_SECRET debe tener al menos 32 caracteres (usa: openssl rand -base64 48).');
  if (!env.DATABASE_URL) errores.push('Falta DATABASE_URL.');
  if (errores.length) throw new Error(`Configuración inválida:\n- ${errores.join('\n- ')}`);

  const entero = (v, def) => (Number.isInteger(Number(v)) && Number(v) > 0 ? Number(v) : def);
  return Object.freeze({
    produccion: env.NODE_ENV === 'production',
    puerto: entero(env.PORT, 3000),
    databaseUrl: env.DATABASE_URL,
    jwtSecreto: secreto,
    accesoMinutos: entero(env.ACCESO_MINUTOS, 15),
    renovacionDias: entero(env.RENOVACION_DIAS, 30),
    origenes: (env.CORS_ORIGINS ?? '').split(',').map(s => s.trim()).filter(Boolean),
    confiarProxy: env.TRUST_PROXY ? entero(env.TRUST_PROXY, 1) : false,
    limitePorMinuto: entero(env.LIMITE_POR_MINUTO, 30),
  });
}
