import express from "express";
import cors from "cors";
const app = express();
const PORT = 3000;
app.use(cors());
app.get("/", (req, res) => {
  res.send("Hello world 123");
});
app.listen(PORT, () => {
  console.log(`App running at port ${PORT}`);
});
