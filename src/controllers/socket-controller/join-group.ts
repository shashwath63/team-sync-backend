import { secretKey } from "../../utils";
import jwt from "jsonwebtoken";
import { Request, Response } from "express";
import { io } from "../../index";
import { prisma } from "../../prisma";

export async function joinGroup(req: Request, res: Response) {
  try {
    const { groupId } = req.body;
    const token = req.headers.authorization;

    const decodedToken: any = jwt.verify(token!, secretKey!);

    const user = await prisma.user.findUnique({
      where: { id: decodedToken.userId },
      include: { userGroups: true },
    });

    const isMember = user?.userGroups.some(
      (userGroup) => userGroup.groupId === groupId,
    );

    if (isMember) {
      return res
        .status(400)
        .json({ error: "User is already a member of the group" });
    }

    await prisma.userGroup.create({
      data: {
        userId: decodedToken.userId,
        groupId,
        role: "MEMBER",
      },
    });

    io.emit("userJoinedGroup", { userId: decodedToken.userId, groupId });

    res.status(200).json({ message: "User joined the group successfully" });
  } catch (error) {
    console.error("Error joining group:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

async function getUserGroups(userId: string) {
  return await prisma.group.findMany({
    where: {
      id: userId,
    },
    include: {
      members: true,
    },
  });
}
