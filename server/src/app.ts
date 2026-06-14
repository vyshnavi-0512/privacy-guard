import express, { type Express } from "express";
import cors from "cors";
import router from "./routes/index.js";

const app: Express = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get("/", (_req, res) => {
    res.json({
      service: "Privacy Guard API",
      status: "online",
      version: "1.0.0",
    });
  });
  app.use("/api", router);
export default app;
