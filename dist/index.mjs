// src/index.ts
import express from "express";
import cors from "cors";
var app = express();
var PORT = 3e3;
app.use(cors());
app.get("/", (req, res) => {
  res.send("Hello world 123");
});
app.listen(PORT, () => {
  console.log(`App running at port ${PORT}`);
});
