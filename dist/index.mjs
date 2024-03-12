// src/index.ts
import cors from "cors";
import express from "express";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
var app = express();
var httpServer = http.createServer(app);
var io = new SocketIOServer(httpServer);
app.use(cors());
app.get("/", (req, res) => {
  res.send("Hello world 123");
});
io.on("connection", (socket) => {
  console.log("A user connected!");
  socket.on("chat message", (msg) => {
    console.log("message:", msg.message);
    io.emit("chat message", msg);
  });
  socket.on("disconnect", () => {
    console.log("A user disconnected");
  });
});
httpServer.listen(3e3, () => {
  console.log(`Server listening on port 3000`);
});
app.listen(3001, () => {
  console.log("App listening on port 3000");
});
