import { PrismaClient, Prisma } from "@prisma/client";
import { Response, Request } from "express";
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

class UserController
{
    async create(request:Request, response:Response)
    {
        const { email, password } = request.body;

        const user = await prisma.user.findUnique({where: { email: email }})
        if(user)
            return response.status(409).json({ message: "Usuário já existe." });

        const hashedPassword = await bcrypt.hash(password, 10);
        let userInput:Prisma.UserCreateInput = {
            email:email,
            hashedPassword:hashedPassword
        }
        const newUser = await prisma.user.create({data:userInput});
        return response.status(201).json({
            message:"Usuario criado com sucesso", 
            data:{email:newUser.email}
        })
    }

    async read(request:Request, response:Response)
    {
        const id = String(request.user)
        const user = await prisma.user.findUnique({where: { id: id }})
        if(!user)
            return response.status(404).json({ message: "Usuário não encontrado." });

        return response.status(201).json({
            message:"Infomrações do usuário", 
            data:{id:user.id, email:user.email}
        })
    }

    async destroy(request:Request, response:Response)
    {
        const id = String(request.user)
        const user = await prisma.user.findUnique({where: { id: id }})
        if(!user)
            return response.status(404).json({ message: "Usuário não encontrado." });

        const deletedUser = await prisma.user.delete({where:{id:id}})

        return response.status(201).json({
            message:"Infomrações do usuário", 
            data:{id:deletedUser.id, email:deletedUser.email}
        })
    }
}