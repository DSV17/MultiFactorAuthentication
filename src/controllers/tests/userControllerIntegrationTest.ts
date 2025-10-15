import request from 'supertest';
import express from 'express';
import passport from 'passport';
import bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';

// Mocks
jest.mock('@prisma/client');
jest.mock('bcryptjs');
// jest.mock('passport');
// jest.mock('../../middlewares/authMiddleware');
jest.mock('passport', () => ({
  authenticate: jest.fn().mockReturnValue((req: any, res: any, next: any) => {
    req.user = 'mock-user-id';
    next();
  })
}));
jest.mock('../../middlewares/authMiddleware', () => ({
  Auth: jest.fn().mockImplementation((req: any, res: any, next: any) => {
    req.user = '550e8400-e29b-41d4-a716-446655440000';
    next();
  })
}));
jest.mock('../../validators/userValidator', () => ({
  userValidator: jest.fn().mockReturnValue([]) // Retorna array vazio para validações
}));

// Importações do app
import router from '../../routers/routes';
import { Auth } from '../../middlewares/authMiddleware';
import { userValidator } from '../../middlewares/userValidatorMiddleware';

const app = express();
app.use(express.json());
app.use(router);

const prisma = new PrismaClient();

describe('PUT /user/changePassword - Integration Test', () => {
  const mockUserId = '550e8400-e29b-41d4-a716-446655440000';
  const mockUser = {
    id: mockUserId,
    email: 'test@example.com',
    hashedPassword: 'oldHashedPassword123',
    mfaEnabled: false,
    mfaSecret: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const validNewPassword = 'newValidPassword123';
  const invalidNewPassword = 'short';

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock da autenticação bem-sucedida
    (Auth as jest.Mock).mockImplementation((req: any, res: any, next: any) => {
      req.user = mockUserId; // Simula usuário autenticado
      next();
    });

    // Mock do Passport
    (passport.authenticate as jest.Mock).mockReturnValue((req: any, res: any, next: any) => {
      req.user = mockUserId;
      next();
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Success cases', () => {
    it('should change password successfully with valid data', async () => {
      // Mock do Prisma
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        hashedPassword: 'newHashedPassword123'
      });

      // Mock do bcrypt
      (bcrypt.hash as jest.Mock).mockResolvedValue('newHashedPassword123');

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: validNewPassword
        });

      expect(response.status).toBe(201);
      expect(response.body).toEqual({
        message: "Senha alterada com sucesso",
        data: {
          id: mockUserId,
          email: mockUser.email
        }
      });

      // Verifica as chamadas do Prisma
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: mockUserId }
      });
      expect(prisma.user.update).toHaveBeenCalledWith({
        data: {
          hashedPassword: 'newHashedPassword123'
        },
        where: { id: mockUserId }
      });

      // Verifica o bcrypt
      expect(bcrypt.hash).toHaveBeenCalledWith(validNewPassword, 10);
    });
  });

  describe('Validation errors', () => {
    it('should return 400 when newPassword is missing', async () => {
      const response = await request(app)
        .put('/user/changePassword')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('errors');
      expect(response.body.errors[0].msg).toBe('Precisa ter o campo password');
    });

    it('should return 400 when newPassword is too short', async () => {
      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: invalidNewPassword
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('errors');
      expect(response.body.errors[0].msg).toBe('Precisa ter pelo menos 8 caracteres');
    });

    it('should return 400 when newPassword is not a string', async () => {
      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: 12345678
        });

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('errors');
      expect(response.body.errors[0].msg).toBe('Precisa ser um texto');
    });
  });

  describe('Authentication and authorization', () => {
    it('should return 401 when not authenticated', async () => {
      // Mock da autenticação falhando
      (Auth as jest.Mock).mockImplementation((req: any, res: any, next: any) => {
        return res.status(401).json({ message: 'Unauthorized' });
      });

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: validNewPassword
        });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe('Unauthorized');
    });
  });

  describe('User not found', () => {
    it('should return 404 when user does not exist', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: validNewPassword
        });

      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Usuário não encontrado.');
      
      expect(prisma.user.findUnique).toHaveBeenCalledWith({
        where: { id: mockUserId }
      });
      expect(prisma.user.update).not.toHaveBeenCalled();
    });
  });

  describe('Database errors', () => {
    it('should return 500 when database update fails', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.user.update as jest.Mock).mockRejectedValue(new Error('Database connection failed'));
      (bcrypt.hash as jest.Mock).mockResolvedValue('newHashedPassword123');

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: validNewPassword
        });

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('error');
    });

    it('should return 500 when bcrypt hash fails', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.hash as jest.Mock).mockRejectedValue(new Error('Bcrypt error'));

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: validNewPassword
        });

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('error');
    });
  });

  describe('Edge cases', () => {
    it('should handle very long password', async () => {
      const longPassword = 'a'.repeat(1000);
      
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.user.update as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedLongPassword');

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: longPassword
        });

      expect(response.status).toBe(201);
      expect(bcrypt.hash).toHaveBeenCalledWith(longPassword, 10);
    });

    it('should handle password with special characters', async () => {
      const specialPassword = 'P@ssw0rd!@#$%^&*()';
      
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.user.update as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedSpecialPassword');

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: specialPassword
        });

      expect(response.status).toBe(201);
      expect(bcrypt.hash).toHaveBeenCalledWith(specialPassword, 10);
    });
  });

  describe('Security aspects', () => {
    it('should not return hashed password in response', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue(mockUser);
      (prisma.user.update as jest.Mock).mockResolvedValue({
        ...mockUser,
        hashedPassword: 'newHashedPassword123'
      });
      (bcrypt.hash as jest.Mock).mockResolvedValue('newHashedPassword123');

      const response = await request(app)
        .put('/user/changePassword')
        .send({
          newPassword: validNewPassword
        });

      expect(response.status).toBe(201);
      expect(response.body.data).not.toHaveProperty('hashedPassword');
      expect(response.body.data).toEqual({
        id: mockUserId,
        email: mockUser.email
      });
    });
  });
});