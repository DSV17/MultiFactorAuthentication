import { PrismaClient } from "@prisma/client";
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

export const createTempSessionAndToken = async (userId: string, expiresInMinutes: number = 5) => {
  const token = crypto.randomBytes(32).toString('hex');
  const hashedToken = await bcrypt.hash(token, 10);
  const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000);
  await prisma.tempLoginSession.create({
    data: {
      userId,
      hashedToken,
      expiresAt,
    },
  });

  return token;
};

export const validateTempSession = async (userId: string, token: string) => {
  const session = await prisma.tempLoginSession.findUnique({
    where: { userId }
  });

  if(!session) return false;
  const isSession = await bcrypt.compare(token, session.hashedToken);

  return isSession;
};