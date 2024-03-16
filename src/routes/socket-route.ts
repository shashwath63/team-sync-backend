import express from 'express'
import { joinGroup } from '../controllers/socket-controller/join-group'

const router = express.Router()
router.post('/join-group', joinGroup)

export default router
