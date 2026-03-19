var express = require("express");
var router = express.Router();
var ctrl = require("../controllers/authController");
var verificarToken = require("../middleware/auth");

router.post("/register", ctrl.register);
router.post("/login", ctrl.login);
router.get("/perfil", verificarToken, ctrl.perfil);

module.exports = router;
