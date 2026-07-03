import bcrypt from "bcryptjs";
import { response, type Request, type Response } from "express";
import { prisma } from "../db.js";
import { authSchema } from "../types/auth-schema.js";
import { createToken } from "../utils/auth.js";
import { sendValidationError } from "../utils/validation.js";

export async function signUp(
    req : Request,
    res : Response
) : Promise<void>{
   const parsedBody = authSchema.safeParse(req.body);
   if(!parsedBody){
     sendValidationError(res, parsedBody.error);
      return;
   }
   const {username,password} = parsedBody.data;
   const hashedPassword = bcrypt.hash(password,10);
   try{
    const user = await prisma.user.create({
        data:{
            username,
            password:hashedPassword,
   },
});
res.status(201).json({
      token: createToken({
        userId: user.id,
      }),
      userId: user.id,
      username: user.username,
    });
  } catch {
    res.status(409).json({
      error: "username already exists",
    });
  }
}
export async function signIn(
    req:Request,
    res: Response
): Promise<void>{
      const parsedBody = authSchema.safeParse(req.body);
      if(!parsedBody){
        sendValidationError(res, parsedBody.error);
         return;
      }
      const {username,password} = parsedBody.data;
      const userExists = await prisma.user.findFirst({
        where:{
          username,
        },
      });
      
      if (!userExists) {
    res.status(401).json({
      error: "username not exists",
    });

    return;
  }
   const correctPassword = bcrypt.compare(
    password,userExists.password,
   );
    if (!correctPassword) {
    res.status(403).json({
      error: "password is invalid",
    });

    return;
  }
  res.status(200).json({
    token: createToken({
      userId: userExists.id,
    }),
    userId: userExists.id,
    username: userExists.username,
  })
}
