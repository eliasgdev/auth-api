var pool = require("../db/database");
var bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
require("dotenv").config();

async function register(req, res) {
  var email = req.body.email;
  var password = req.body.password;
  var nombre = req.body.nombre;

  if (!email || !password || !nombre) {
    return res.status(400).json({ error: "Todos los campos son obligatorios" });
  }

  try {
    var userExiste = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);
    if (userExiste.rows.length > 0) {
      return res.status(400).json({ error: "El email ya está registrado" });
    }

    var salt = await bcrypt.genSalt(10);
    var passwordHash = await bcrypt.hash(password, salt);

    var result = await pool.query(
      "INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3) RETURNING id, nombre, email",
      [nombre, email, passwordHash]
    );

    res.status(201).json({ mensaje: "Usuario registrado", usuario: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: "Error en el servidor" });
  }
}

async function login(req, res) {
  var email = req.body.email;
  var password = req.body.password;

  if (!email || !password) {
    return res.status(400).json({ error: "Email y password son obligatorios" });
  }

  try {
    var result = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Credenciales incorrectas" });
    }

    var usuario = result.rows[0];
    var passwordValido = await bcrypt.compare(password, usuario.password);
    if (!passwordValido) {
      return res.status(400).json({ error: "Credenciales incorrectas" });
    }

    var token = jwt.sign(
      { id: usuario.id, email: usuario.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ mensaje: "Login exitoso", token: token });
  } catch (error) {
    res.status(500).json({ error: "Error en el servidor" });
  }
}

async function perfil(req, res) {
  try {
    var result = await pool.query(
      "SELECT id, nombre, email FROM usuarios WHERE id = $1",
      [req.usuario.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Error en el servidor" });
  }
}

module.exports = { register, login, perfil };