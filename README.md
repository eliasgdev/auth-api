# Auth API 

REST API de autenticación con JWT y PostgreSQL. Registro, login y rutas protegidas.

## Descripción

Backend completo de autenticación — los usuarios se registran, hacen login y reciben un token JWT para acceder a rutas protegidas. Los passwords se guardan encriptados con bcrypt.

## Tecnologías

- Node.js
- Express
- PostgreSQL
- JWT (jsonwebtoken)
- bcryptjs

## Endpoints

| Método | Endpoint | Descripción | Protegido |
|--------|----------|-------------|-----------|
| POST | `/api/auth/register` | Registrar usuario | No |
| POST | `/api/auth/login` | Login y obtener token | No |
| GET | `/api/auth/perfil` | Ver perfil del usuario | Sí |

## Ejemplos de uso

**Registro (POST)**
```json
{
  "nombre": "Elias",
  "email": "elias@gmail.com",
  "password": "123456"
}
```

**Login (POST)**
```json
{
  "email": "elias@gmail.com",
  "password": "123456"
}
```

**Respuesta del login**
```json
{
  "mensaje": "Login exitoso",
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Perfil (GET) — requiere token en Headers**
```
Key:    authorization
Value:  eyJhbGciOiJIUzI1NiIs...
```

## Cómo correrlo

1. Cloná el repositorio
```bash
   git clone https://github.com/eliasgdev/auth-api.git
```
2. Instalá las dependencias
```bash
   npm install
```
3. Creá un archivo `.env` en la raíz
```
   PORT=3000
   DB_USER=postgres
   DB_PASSWORD=tu_contraseña
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=auth_app
   JWT_SECRET=tu_clave_secreta
```
4. Creá la tabla en PostgreSQL
```sql
   CREATE TABLE usuarios (
     id SERIAL PRIMARY KEY,
     nombre TEXT NOT NULL,
     email TEXT UNIQUE NOT NULL,
     password TEXT NOT NULL,
     fecha_registro TIMESTAMP DEFAULT NOW()
   );
```
5. Corrré el servidor
```bash
   node app.js
```
6. El servidor corre en `http://localhost:3000`

## Estructura del proyecto
```
auth-api/
├── controllers/
│   └── authController.js
├── db/
│   └── database.js
├── middleware/
│   └── auth.js
├── routes/
│   └── auth.js
├── .env
└── app.js
```

## Autor

**Elias Gutierrez** — [github.com/eliasgdev](https://github.com/eliasgdev)
