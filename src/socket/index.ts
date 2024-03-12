import { PrismaClient } from "@prisma/client";
import { Server as SocketIOServer, Socket } from "socket.io";
const prisma = new PrismaClient();
interface ChatMessage {
  message: string;
}
interface Group {
  name: string;
  // include other properties of group if needed
}
async function getUserGroups(userId: string) {
  return await prisma.group.findMany({
    where: {
      members: {
        some: {
          userId: userId,
        },
      },
    },
  });
}
``
export const initializeChatSocket = (io: SocketIOServer) => {
  const userSockets = new Map(); // Map to track users and their socket IDs
  io.on("connection", (socket: Socket) => {
    console.log("A user connected!");

    // Event for user registration or identification
    socket.on("register-user", async (userId: string) => {
      userSockets.set(userId, socket.id);

      // Dynamically join user to their groups
      const groups = await getUserGroups(userId); // Implement this function based on your database logic
      groups.forEach((group:Group) => {
        socket.join(group.name);
      });
    });
    // Event for private messaging
    socket.on("private-message", ({ recipientId, message }) => {
      const recipientSocketId = userSockets.get(recipientId);
      if (recipientSocketId) {
        socket
          .to(recipientSocketId)
          .emit("private-message", { message, from: socket.id });
      }
    });

    // Event for joining a group chat
    socket.on("join-group", (groupName) => {
      socket.join(groupName);
    });

    // Event for group messaging
    socket.on("group-message", ({ groupName, message }) => {
      io.to(groupName).emit("group-message", { message, from: socket.id });
    });
    socket.on("disconnect", () => {
      console.log("A user disconnected");
    });
  });
};
