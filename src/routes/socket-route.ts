import express from "express";
import { joinGroup } from "../controllers/socket-controller/join-group";
import { sendMessageToGroup } from "../controllers/socket-controller/broadcast-message";

const router = express.Router();
router.post("/join-group", joinGroup);
router.post("/broadcast-message", sendMessageToGroup);

export default router;
