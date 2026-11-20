import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { z } from 'zod';
import { problemaDeClave } from './claves.js';
import { verificarAcceso } from './tokens.js';
import { crearServicio, ErrorAuth } from './servicio.js';
import { crearLimitador } from './limitador.js';

const email = z.string({ error: 'Obligatorio.' }).trim().toLowerCase().max(254, 'Máximo 254 caracteres.').email('No es un correo válido.');
const clave = z.string({ error: 'Obligatorio.' }).max(128, 'Máximo 128 caracteres.');

const esquemas = {
  registro: z.strictObject({
    nombre: z.string({ error: 'Obligatorio.' }).trim().min(1, 'Escribe tu nombre.').max(80, 'Máximo 80 caracteres.'),
    email,
    clave,
  }),
  login: z.strictObject({ email, clave: clave.min(1, 'Obligatorio.') }),
  renovar: z.strictObject({ renovacion: z.string({ error: 'Obligatorio.' }).regex(/^[\w-]{43}$/, 'Token mal formado.') }),
  cambiarClave: z.strictObject({ actual: clave.min(1, 'Obligatorio.'), nueva: clave }),
};

// Valida el cuerpo y responde 400 con el problema de cada campo.
function validar(esquema, cuerpo) {
  const r = esquema.safeParse(cuerpo ?? {});
  if (r.success) return r.data;
  const campos = {};
  for (const issue of r.error.issues) {
    const campo = issue.path.join('.') || (issue.code === 'unrecognized_keys' ? issue.keys.join(', ') : 'cuerpo');
    campos[campo] ??= issue.code === 'unrecognized_keys' ? 'Campo no permitido.' : issue.message;
  }
  throw new ErrorAuth(400, 'Datos inválidos.', { campos });
}

export function crearApp({ pool, config }) {
  const servicio = crearServicio({ pool, config });
  const app = express();

  app.disable('x-powered-by');
  if (config.confiarProxy) app.set('trust proxy', config.confiarProxy);
  app.use(helmet());
  app.use(cors({
    origin: (origen, listo) => listo(null, !origen || config.origenes.includes(origen)),
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  }));
  app.use(express.json({ limit: '4kb' }));
  app.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  const datosCliente = req => ({ ip: req.ip, agente: req.get('user-agent') });

  const autenticar = async (req, _res, next) => {
    const [tipo, token] = (req.get('authorization') ?? '').split(' ');
    if (tipo !== 'Bearer' || !token) return next(new ErrorAuth(401, 'Falta el token de acceso.'));
    let datos;
    try {
      datos = verificarAcceso(config, token);
    } catch (err) {
      return next(new ErrorAuth(401, err.name === 'TokenExpiredError' ? 'El token de acceso venció. Renuévalo.' : 'Token de acceso inválido.'));
    }
    if (!(await servicio.sesionActiva(datos))) return next(new ErrorAuth(401, 'La sesión fue cerrada. Inicia sesión de nuevo.'));
    req.sesion = datos;
    next();
  };

  app.get('/salud', async (_req, res) => {
    await pool.query('SELECT 1');
    res.json({ estado: 'ok' });
  });

  const auth = express.Router();
  auth.use(crearLimitador({ porMinuto: config.limitePorMinuto }));

  auth.post('/registro', async (req, res) => {
    const datos = validar(esquemas.registro, req.body);
    const problema = problemaDeClave(datos.clave, datos);
    if (problema) throw new ErrorAuth(400, 'Datos inválidos.', { campos: { clave: problema } });
    const usuario = await servicio.registrar(datos);
    res.status(201).json({ usuario });
  });

  auth.post('/login', async (req, res) => {
    const datos = validar(esquemas.login, req.body);
    res.json(await servicio.iniciarSesion({ ...datos, ...datosCliente(req) }));
  });

  auth.post('/renovar', async (req, res) => {
    const { renovacion } = validar(esquemas.renovar, req.body);
    res.json(await servicio.renovar({ renovacion, ...datosCliente(req) }));
  });

  auth.post('/salir', autenticar, async (req, res) => {
    await servicio.cerrarSesion(req.sesion);
    res.status(204).end();
  });

  auth.post('/salir-de-todo', autenticar, async (req, res) => {
    await servicio.cerrarTodas({ usuarioId: req.sesion.usuarioId });
    res.status(204).end();
  });

  auth.get('/yo', autenticar, async (req, res) => {
    const usuario = await servicio.perfil(req.sesion.usuarioId);
    if (!usuario) throw new ErrorAuth(401, 'La cuenta ya no existe.');
    res.json({ usuario });
  });

  auth.get('/sesiones', autenticar, async (req, res) => {
    res.json({ sesiones: await servicio.listarSesiones(req.sesion) });
  });

  auth.delete('/sesiones/:id', autenticar, async (req, res) => {
    const id = z.uuid().safeParse(req.params.id);
    if (!id.success || !(await servicio.cerrarSesionPorId({ usuarioId: req.sesion.usuarioId, id: id.data }))) {
      throw new ErrorAuth(404, 'No hay una sesión abierta con ese id.');
    }
    res.status(204).end();
  });

  auth.patch('/clave', autenticar, async (req, res) => {
    const datos = validar(esquemas.cambiarClave, req.body);
    const usuario = await servicio.perfil(req.sesion.usuarioId);
    const problema = problemaDeClave(datos.nueva, usuario ?? {}) ?? (datos.nueva === datos.actual ? 'Debe ser distinta de la actual.' : null);
    if (problema) throw new ErrorAuth(400, 'Datos inválidos.', { campos: { nueva: problema } });
    await servicio.cambiarClave({ ...req.sesion, ...datos });
    res.status(204).end();
  });

  app.use('/api/auth', auth);

  app.use((_req, res) => res.status(404).json({ error: 'No encontrado.' }));

  app.use((err, _req, res, _next) => {
    if (err instanceof ErrorAuth) {
      if (err.reintentar) res.setHeader('Retry-After', err.reintentar);
      if (err.status === 401) res.setHeader('WWW-Authenticate', 'Bearer');
      return res.status(err.status).json({ error: err.message, ...(err.campos && { campos: err.campos }) });
    }
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'El cuerpo no es JSON válido.' });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'El cuerpo es demasiado grande.' });
    console.error(err);
    res.status(500).json({ error: 'Error interno.' });
  });

  return app;
}
