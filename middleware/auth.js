var jwt = require("jsonwebtoken");
require("dotenv").config();

function verificarToken(req, res, next) {
  var token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  try {
    var decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Token inválido" });
  }
}

module.exports = verificarToken;