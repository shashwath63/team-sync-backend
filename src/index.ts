import bodyParser from 'body-parser'
import cors from 'cors'
import express, { Application } from 'express'
import http from 'http'
import { Server as SocketIOServer } from 'socket.io'
import authRoutes from './routes/auth-route'
import socketRoutes from './routes/socket-route'
import { initializeChatSocket } from './socket'

const app: Application = express()
const httpServer = http.createServer(app)
export const io: SocketIOServer = new SocketIOServer(httpServer)

const PORT = 4000
app.use(cors())

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use('/api/auth', authRoutes)
app.use('/api/socket', socketRoutes)
app.get('/', (req, res) => {
  res.send('Hello world 123')
})

initializeChatSocket(io)

httpServer.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`)
})
