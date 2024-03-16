import { Server as SocketIOServer, Socket } from 'socket.io'

export const initializeChatSocket = (io: SocketIOServer) => {
  io.on('connection', (socket: Socket) => {
    console.log('A user connected!')

    socket.on('disconnect', () => {
      console.log('A user disconnected')
    })
  })
}
