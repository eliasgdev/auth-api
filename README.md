# auth-api

[![Pruebas](https://github.com/eliasgdev/auth-api/actions/workflows/pruebas.yml/badge.svg)](https://github.com/eliasgdev/auth-api/actions/workflows/pruebas.yml)
![Node 22+](https://img.shields.io/badge/node-22%2B-339933?logo=node.js&logoColor=white)
![Postgres 15+](https://img.shields.io/badge/postgres-15%2B-336791?logo=postgresql&logoColor=white)

API de autenticación con Express 5 y PostgreSQL, hecha para usarse en producción y no solo como ejemplo. Usa tokens de acceso de 15 minutos y **tokens de renovación que cambian en cada uso**. Si alguien roba uno y lo usa, la API lo detecta y cierra esa sesión. También permite cerrar una sesión o todas, bloquea el login tras varios fallos y no deja saber si un correo está registrado.

## Endpoints

Todos van bajo `/api/auth`. Las rutas marcadas con 🔒 piden `Authorization: Bearer <acceso>`.

| Método | Ruta | Qué hace |
|---|---|---|
| `POST` | `/registro` | Crea la cuenta `{ nombre, email, clave }` |
| `POST` | `/login` | `{ email, clave }` → `{ acceso, renovacion, expira_en_segundos }` |
| `POST` | `/renovar` | `{ renovacion }` → par de tokens nuevo (el anterior deja de servir) |
| `GET` | `/yo` 🔒 | Perfil del usuario |
| `GET` | `/sesiones` 🔒 | Sesiones abiertas: IP, navegador, inicio y cuál es la actual |
| `DELETE` | `/sesiones/:id` 🔒 | Cierra otra sesión, por ejemplo el celular que perdiste |
| `PATCH` | `/clave` 🔒 | `{ actual, nueva }`; cierra todas las demás sesiones |
| `POST` | `/salir` 🔒 | Cierra esta sesión |
| `POST` | `/salir-de-todo` 🔒 | Cierra todas las sesiones |
| `GET` | `/salud` | Comprueba que la API y la base respondan (fuera de `/api/auth`) |

Los errores siempre tienen la misma forma y dicen qué campo falló:

```json
{ "error": "Datos inválidos.", "campos": { "clave": "Debe tener al menos 10 caracteres." } }
```

Los `id` de usuario se devuelven como texto porque son `BIGINT`.

## Decisiones de seguridad

| Riesgo | Cómo se cubre |
|---|---|
| Robo de base de datos | Claves con **scrypt** (N=2¹⁵, r=8, p=3, según OWASP) y sal propia. De los tokens de renovación solo se guarda el **SHA-256**. |
| Token de renovación robado | **Rotación con detección de reutilización**: cada `/renovar` invalida el token usado. Si un token ya usado vuelve a llegar, se revoca toda la familia de la sesión, tanto la del ladrón como la del usuario. |
| Cerrar sesión que no cierra | En cada petición se comprueba que la sesión del token de acceso siga abierta, así que `/salir` y el cambio de clave cortan el acceso **de inmediato**, sin esperar a que venza el JWT. |
| JWT manipulado | Algoritmo fijo `HS256` (se rechaza `alg: none`), con emisor y audiencia verificados, y secreto de al menos 32 caracteres (la API no arranca si es más corto). |
| Fuerza bruta | 5 fallos por correo o 20 por IP en 15 minutos → `429` con `Retry-After`. Además, un límite general de peticiones por IP. |
| Saber qué correos existen | Si el correo no existe o la clave está mal, el mensaje es el mismo y la respuesta tarda lo mismo (se verifica contra un hash falso). |
| Claves débiles | Mínimo 10 caracteres y máximo 128. Se rechazan las claves comunes, las repetidas y las que contienen el correo o el nombre. |
| Asignación masiva | Validación estricta con zod: los campos desconocidos (`rol`, `es_admin`…) se rechazan con `400`. |
| Datos inválidos | Los mismos límites se aplican en la API (zod) y en la base (`CHECK`, índice único del correo en minúsculas). |
| Abuso del servidor | Cuerpo máximo de 4 KB, cabeceras de seguridad con Helmet, CORS con lista de orígenes permitidos, `Cache-Control: no-store` y sin `x-powered-by`. |

**Límites conocidos:** el registro responde `409` si el correo ya existe; sin verificación por correo electrónico no hay forma de evitarlo, así que queda protegido con el límite de peticiones. El límite general por IP vive en memoria, y con varias instancias conviene moverlo a Redis o a la base.

## Correrla

```bash
git clone https://github.com/eliasgdev/auth-api.git && cd auth-api
npm install
npm run db:iniciar        # Postgres 17 en podman, puerto 55435 (o usa el tuyo)
cp .env.example .env      # y pon un JWT_SECRET: openssl rand -base64 48
npm run dev               # migra la base y escucha en http://localhost:3000
```

Con Docker:

```bash
JWT_SECRET=$(openssl rand -base64 48) docker compose up --build
```

### Variables

| Variable | Por defecto | Para qué |
|---|---|---|
| `DATABASE_URL` | obligatoria | Conexión a PostgreSQL |
| `JWT_SECRET` | obligatoria | Mínimo 32 caracteres |
| `CORS_ORIGINS` | vacío | Orígenes permitidos, separados por coma |
| `ACCESO_MINUTOS` | `15` | Vida del token de acceso |
| `RENOVACION_DIAS` | `30` | Vida del token de renovación |
| `LIMITE_POR_MINUTO` | `30` | Peticiones por IP y minuto en `/api/auth` |
| `TRUST_PROXY` | vacío | Número de proxies delante, para leer la IP real |

## Pruebas

```bash
npm test
```

Son 15 pruebas de integración **contra un PostgreSQL real** (cada corrida crea un esquema propio y lo borra al final) y 3 pruebas unitarias del limitador, la configuración y la política de claves. Cubren registro, login, bloqueo por fallos, `alg: none`, tokens alterados, rotación y reutilización de tokens, cierre de sesiones, que un usuario no pueda cerrar sesiones de otro, cambio de clave y que en la base no queden claves ni tokens en claro. El CI las corre en Node 22 y 24 contra Postgres 15 y 17, y además ejecuta `npm audit`.

## Estructura

```
src/
├── servidor.js     # arranque, migraciones y apagado ordenado
├── app.js          # rutas HTTP, validación (zod) y manejo de errores
├── servicio.js     # lógica de cuentas y sesiones
├── tokens.js       # JWT de acceso y tokens de renovación
├── claves.js       # scrypt y política de claves
├── limitador.js    # límite de peticiones por IP
├── config.js       # variables de entorno validadas al arrancar
└── db.js           # pool y migraciones con candado
migraciones/001_inicial.sql
tests/
```

## Licencia

MIT

---

<a href="https://avirexis.com/?utm_source=github&utm_medium=readme&utm_campaign=auth-api"><picture><source media="(prefers-color-scheme: dark)" srcset="https://avirexis.com/avx-logo-nav-white.png"><img src="https://avirexis.com/avx-logo-nav.png" alt="Avirexis" height="22"></picture></a>

Hecho por [Avirexis](https://avirexis.com/?utm_source=github&utm_medium=readme&utm_campaign=auth-api), software de gestión para negocios hecho en Colombia.
