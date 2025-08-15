import { PrismaClient, Prisma } from "@prisma/client";
import { Response, Request } from "express";
import bcrypt from 'bcryptjs';
import { generateJWT } from "../services/authService";

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

    async changePassword(request:Request, response:Response)
    {
        const id = String(request.user)
        const user = await prisma.user.findUnique({where: { id: id }})
        if(!user)
            return response.status(404).json({ message: "Usuário não encontrado." });

        const { newPassword } = request.body;

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        let userInput:Prisma.UserUpdateInput = {
            hashedPassword:hashedPassword
        }
        const updatedUser = await prisma.user.update({data:userInput, where:{id:id}});

        return response.status(201).json({
            message:"Senha alterada com sucesso", 
            data:{id:updatedUser.id, email:updatedUser.email}
        })
    }

    async login(request:Request, response:Response)
    {
        const { email, password } = request.body;

        const user = await prisma.user.findUnique({where: { email: email }});
        if(!user)
            return response.status(404).json({ message: "Usuário não encontrado." });

        const isLogged = await bcrypt.compare(password, user.hashedPassword);
        if(!isLogged)
            return response.status(401).json({ message: "Login ou senha incorretos." });

        const tokenJWT = generateJWT(user);

        return response.status(201).json({
            message:"Login efetuado com sucesso", 
            data:{email:user.email, token:tokenJWT}
        })
    }
}

export default new UserController();