// Límite de peticiones por IP en memoria (ventana fija de un minuto).
// Para varias instancias, cambiarlo por uno compartido (Redis o la propia base).
export function crearLimitador({ porMinuto, ahora = () => Date.now() }) {
  const cubetas = new Map();
  let ultimaLimpieza = ahora();

  return function limitador(req, res, next) {
    const t = ahora();
    if (t - ultimaLimpieza > 60_000) {
      for (const [ip, c] of cubetas) if (t - c.inicio >= 60_000) cubetas.delete(ip);
      ultimaLimpieza = t;
    }
    const clave = req.ip ?? 'desconocida';
    let c = cubetas.get(clave);
    if (!c || t - c.inicio >= 60_000) { c = { inicio: t, cuenta: 0 }; cubetas.set(clave, c); }
    c.cuenta++;
    res.setHeader('RateLimit-Limit', porMinuto);
    res.setHeader('RateLimit-Remaining', Math.max(porMinuto - c.cuenta, 0));
    if (c.cuenta > porMinuto) {
      const espera = Math.ceil((c.inicio + 60_000 - t) / 1000);
      res.setHeader('Retry-After', espera);
      return res.status(429).json({ error: `Demasiadas peticiones. Intenta de nuevo en ${espera} s.` });
    }
    next();
  };
}
