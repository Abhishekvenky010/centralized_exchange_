import { Router } from "express";
import { signUp,signIn } from "../controllers/auth-controller.js";
import { asyncHandler } from "../utils/async-handler.js";

export const authRouter = Router();

authRouter.post("/signup", asyncHandler(signUp));
authRouter.post("/signin",asyncHandler(signIn)); 