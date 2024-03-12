import bodyParser from "body-parser";
import cors from "cors";
import express, { Application } from "express";
import http from "http";
import { Server as SocketIOServer, Socket } from "socket.io";
import authRoutes from "./routes/auth-route";
import { initializeChatSocket } from "./socket"; // Import the function

const app: Application = express();
const httpServer = http.createServer(app);
const io: SocketIOServer = new SocketIOServer(httpServer);

const PORT = 4000;
app.use(cors());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("Hello world 123");
});

// Use the imported function to set up Socket.IO chat logic
initializeChatSocket(io);

httpServer.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
