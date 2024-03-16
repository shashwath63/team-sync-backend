import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { secretKey } from "../../utils";
import { io } from "../../index";
import { prisma } from "../../prisma";

export async function sendMessageToGroup(req: Request, res: Response) {
  try {
    const { groupId, message } = req.body;
    const token = req.headers.authorization;

    const decodedToken: any = jwt.verify(token!, secretKey!);

    const user = await prisma.user.findUnique({
      where: { id: decodedToken.userId },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMember = await prisma.userGroup.findFirst({
      where: {
        userId: decodedToken.userId,
        groupId,
      },
    });

    if (!isMember) {
      return res
        .status(401)
        .json({ error: "User is not a member of the group" });
    }

    const savedMessage = await prisma.message.create({
      data: {
        content: message,
        groupId,
        userId: decodedToken.userId,
      },
    });

    io.emit("messageSentToGroup", { groupId, message: savedMessage });

    res.status(200).json({ message: "Message broadcasted successfully" });
  } catch (error) {
    console.error("Error broadcasting message:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}
