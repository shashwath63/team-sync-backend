import { PrismaClient, Role } from '@prisma/client'
import { Server as SocketIOServer, Socket } from 'socket.io'
const prisma = new PrismaClient()

interface ChatMessage {
  message: string
}
interface Group {
  name: string
}

async function getUserGroups(userId: string) {
  return await prisma.group.findMany({
    where: {
      id: userId,
    },
    include: {
      members: true,
    },
  })
}
export const initializeChatSocket = (io: SocketIOServer) => {
  const userSockets = new Map<string, string>() // Map to track users and their socket IDs
  io.on('connection', (socket: Socket) => {
    console.log('A user connected!')

    // Event for user registration or identification
    socket.on('register-user', async (userId: string) => {
      userSockets.set(userId, socket.id)

      // Dynamically join user to their groups
      const groups = await getUserGroups(userId) // Implement this function based on your database logic
      groups.forEach((group: Group) => {
        socket.join(group.name)
      })
    })
    // Event for private messaging //888
    socket.on('private-message', ({ recipientId, message }) => {
      //123
      const recipientSocketId = userSockets.get(recipientId) //456
      if (recipientSocketId) {
        socket
          .to(recipientSocketId)
          .emit('private-message', { message, from: socket.id }) //888 -> 456
      }
    })

    // Event for joining a group chat
    socket.on('join-group', async (groupId) => {
      try {
        const userId = userSockets.get(socket.id)
        if (!userId) {
          console.error('User not found for socket ID:', socket.id)
          return
        }

        const user = await prisma.user.findUnique({
          where: {
            id: userId,
          },
        })
        if (!user) {
          console.error('User not found with ID:', userId)
          return
        }

        const group = await prisma.group.findUnique({
          where: {
            id: groupId,
          },
        })
        if (!group) {
          console.error('Group not found with ID:', groupId)
          return
        }

        // Check if the user is already a member of the group
        const existingMembership = await prisma.userGroup.findFirst({
          where: {
            userId: user.id,
            groupId: group.id,
          },
        })
        if (existingMembership) {
          console.log(
            `User ${user.username} is already a member of group ${group.name}.`
          )
          return
        }

        // Create a new UserGroup entry to associate the user with the group
        await prisma.userGroup.create({
          data: {
            user: {
              connect: {
                id: user.id,
              },
            },
            group: {
              connect: {
                id: group.id,
              },
            },
            role: Role.MEMBER,
          },
        })

        // Join the socket to the group room
        socket.join(group.name)
        console.log(`User ${user.username} joined group ${group.name}.`)
      } catch (error) {
        console.error('Error joining group:', error)
      }
    })

    // Event for group messaging
    socket.on('group-message', ({ groupName, message }) => {
      io.to(groupName).emit('group-message', { message, from: socket.id })
    })
    socket.on('disconnect', () => {
      console.log('A user disconnected')
    })
  })
}
