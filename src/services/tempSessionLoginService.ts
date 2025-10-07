import { PrismaClient } from "@prisma/client";
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export const createTempSessionAndToken = async (prisma: PrismaClient, userId: string, expiresInMinutes: number = 5) => {
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

export const validateTempSession = async (prisma: PrismaClient, userId: string, token: string) => {
  const session = await prisma.tempLoginSession.findUnique({
    where: { userId }
  });

  if (!session) return false;
  const isSession = (await bcrypt.compare(token, session.hashedToken)) &&
    (Date.now() < session.expiresAt.getTime())

  return isSession;
};