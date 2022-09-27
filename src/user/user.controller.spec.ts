import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from '../common/strategies/jwt.strategy';
import { PrismaService } from '../prisma.services';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { RolesGuard } from '../common/guards/roles.guard';
import { faker } from '@faker-js/faker';
import * as request from 'supertest';
import { INestApplication, ValidationPipe } from '@nestjs/common';

import { UnencryptedPasswordValidator, UnencryptedPassword } from '../common/validators/unencrypted-password-validator';

describe('UserController', () => {
  let userController: UserController;
  let userService: UserService;
  let app: INestApplication;
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      imports: [
        PassportModule,
        JwtModule.register({
          secret: 'JWT_SECRET',
          signOptions: {
            expiresIn: '1year',
            algorithm: 'HS256',
          },
        }),
      ],
      providers: [UserService, PrismaService, JwtStrategy, ConfigService, UnencryptedPasswordValidator],
    }).compile();
    app = module.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();
    userService = module.get<UserService>(UserService);
    userController = module.get<UserController>(UserController);
  });

  it('should be defined', () => {
    expect(userController).toBeDefined();
    expect(userService).toBeDefined();
  });

  describe('when creating new user', () => {
    describe('and using valid data', () => {
      it('should respond with the data of the user without the password', () => {
        let name = faker.name.firstName('female');
        let email = `${faker.random.word()}@gmail.com`;
        const expectedData = {
          "name": name,
          "email": email,
          "email_confirmed": true,
          "is_admin": false
        }

        try {
          return request(app.getHttpServer())
            .post('/user')
            .send({
              email: email,
              email_confirmed: true,
              name: name,
              password: 'strong@Password123'
            })
            .then((result) => {
              expect(result.statusCode).toEqual(200);
              expect(JSON.parse(result.text)).toMatchObject(expectedData);
            });
        } catch (err) {
          expect(err).toBeFalsy();

        }
      })

    })
    describe('and using invalid data', () => {
      it('should throw an error', () => {
        return request(app.getHttpServer())
          .post('/user')
          .send({
            password: 'weakpassword'
          })
          .expect(400)
      })
    })
  });
});
