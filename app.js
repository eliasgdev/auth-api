var express = require("express");
var authRoutes = require("./routes/auth");
require("dotenv").config();

var app = express();
app.use(express.json());

app.use("/api/auth", authRoutes);

app.get("/", function(req, res) {
  res.json({ mensaje: "Auth API funcionando" });
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log("Servidor corriendo en http://localhost:" + PORT);
});