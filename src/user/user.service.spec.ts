import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from '../common/strategies/jwt.strategy';
import { PrismaService } from '../prisma.services';
import { UserService } from './user.service';
import * as bcrypt from 'bcrypt';
import { UnencryptedPasswordValidator, UnencryptedPassword } from '../common/validators/unencrypted-password-validator';
import exp from 'constants';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

jest.mock('bcrypt');

describe('UserService', () => {
  let userService: UserService;
  let configService: ConfigService;
  let prismaService: PrismaService;
  let bcryptCompare: jest.Mock;
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
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
    bcryptCompare = jest.fn().mockReturnValue(true);
    (bcrypt.compare as jest.Mock) = bcryptCompare;
    userService = module.get<UserService>(UserService);
    prismaService = module.get<PrismaService>(PrismaService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(userService).toBeDefined();
  });
  describe('when accessing the data of authenticating user', () => {

    it('should return false for invalid email & password', async () => {
      prismaService.user.findUnique = jest.fn().mockReturnValueOnce(
        null
      );
      let result = await userService.authenticate({ email: 'user@email.com', password: 'strongPassword' });
      expect(result).toBeFalsy();
    });

    it('should return userDetails for valid email & password', async () => {
      prismaService.user.findUnique = jest.fn().mockReturnValueOnce(
        {
          "id": 7,
          "name": "new name",
          "email": "userRegular@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-25T16:37:07.178Z",
          "updated_at": "2022-09-25T16:39:26.726Z",
          "credentials_id": 7,
          "credentials": {
            "id": 7,
            "hash": "$2b$12$HNjg7G/Xctr7UnhxyOUg5eeUKCyly1YSNfFByi1PoavzJjOmO/YqO",
            "created_at": "2022-09-25T16:37:07.178Z",
            "updated_at": "2022-09-25T16:37:07.187Z"
          }
        }
      );
      let result = await userService.authenticate({ email: 'userRegular@postgmail.com', password: 'Password@123' });
      expect(result).toBeTruthy();
      expect(result['credentials']).toBeTruthy();
    });

    it('should return JWT Token for valid User', async () => {
      let result = await userService.authenticateAndGetJwtToken({ email: 'userRegular@postgmail.com', password: 'Password@123' });

      expect(result).toBeTruthy();
      expect(result['token']).toBeTruthy();
    });

    it('should throw Access Forbidden Token for Invalid User', async () => {
      bcryptCompare = jest.fn().mockReturnValueOnce(false);
      (bcrypt.compare as jest.Mock) = bcryptCompare;
      try {
        let result = await userService.authenticateAndGetJwtToken({ email: 'Invalid@postgmail.com', password: 'Password@123' });
        expect(result).toBeFalsy();
      } catch (err) {
        expect(err.response?.message).toEqual('Access Denied');
      }
    });

    it('should return false if token is Invalid', async () => {
      try {
        let result = await userService.validateToken('Bearer eyJhbGciOInvalidiJIUzIInvalid6IkpXVCJ9.eyJpZCI6NywidXNlcm5hbWUiOiJ1c2VyUmVndWxhckBwb3N0Z21haWwuY29tIiwiaWF0IjoxNjY0MjI2NTk4LCJleHAiOjE2NjQyMjY1OTh9.ooyzkaGCBWTdQuoNA9P37YetsSqTMnktTOsw0PyDagM');

        expect(result).toBeFalsy();

      } catch (err) {
        expect(err).toBeFalsy();
      }
    });

  });

  describe('User CRUD operations', () => {

    // CREATE
    it('Create single user with valid email and password', async () => {
      prismaService.user.create = jest.fn().mockReturnValueOnce(

        {
          "id": 12,
          "name": "Mike Church",
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }

      );

      let result = await userService.create({
        name: 'Mike Church',
        email: 'mike@postgmail.com',
        password: 'Password@321',
        email_confirmed: true,
        is_admin: false
      });

      expect(result).toBeTruthy();
      expect(result).toEqual({
        "id": 12,
        "name": "Mike Church",
        "email": "mike@postgmail.com",
        "email_confirmed": true,
        "is_admin": false,
        "created_at": "2022-09-27T12:37:52.866Z",
        "updated_at": "2022-09-27T12:37:52.893Z",
        "credentials_id": 12
      });
    });

    // READ
    it('Find Users with letter ma in their names returns all users only to admin', async () => {
      prismaService.user.findMany = jest.fn().mockReturnValueOnce(
        [
          {
            "id": 10,
            "name": "NormalUser2",
            "email": "userRegular2@postgmail.com",
            "email_confirmed": true,
            "is_admin": false,
            "created_at": "2022-09-25T21:28:12.536Z",
            "updated_at": "2022-09-25T21:28:12.568Z",
            "credentials_id": 10
          },
          {
            "id": 9,
            "name": "NormalUser3",
            "email": "userRegular3@postgmail.com",
            "email_confirmed": true,
            "is_admin": false,
            "created_at": "2022-09-25T21:28:12.536Z",
            "updated_at": "2022-09-25T21:28:12.568Z",
            "credentials_id": 9
          }
        ]
      );
      let request = {
        user: {
          id: 7,
          name: 'new name',
          email: 'userRegular@postgmail.com',
          email_confirmed: true, //setting admin true here
          is_admin: true,
          created_at: '2022-09-25T16:37:07.178Z',
          updated_at: '2022-09-25T16:39:26.726Z',
          credentials_id: 7
        },
        query: { name: 'ma' }
      }

      let result = await userService.find(null, request);

      expect(result).toBeTruthy();

      expect(result[0].name.search('ma')).not.toBe(-1);
    });


    it('Find all users returns only CURRENT USER if user is not admin', async () => {
      prismaService.user.findUnique = jest.fn().mockReturnValueOnce(
        [
          {
            id: 7,
            name: 'new name',
            email: 'userRegular@postgmail.com',
            email_confirmed: true,
            is_admin: false,
            created_at: '2022-09-25T16:37:07.178Z',
            updated_at: '2022-09-25T16:39:26.726Z',
            credentials_id: 7
          }
        ]
      );
      // Mocking the passport strategy behavior of appending users details in request after validation
      let request = {
        user: {
          id: 7,
          name: 'new name',
          email: 'userRegular@postgmail.com',
          email_confirmed: true,
          is_admin: false,//non-admin user
          created_at: '2022-09-25T16:37:07.178Z',
          updated_at: '2022-09-25T16:39:26.726Z',
          credentials_id: 7
        }
      }

      let result = await userService.find(null, request);

      expect(result).toBeTruthy();
      expect(result[0].id).toEqual(request.user.id);
    });

    it('Find all users returns ALL USERS if requesting user is admin', async () => {
      prismaService.user.findMany = jest.fn().mockReturnValueOnce(
        [
          {
            "id": 10,
            "name": "NormalUser2",
            "email": "userRegular2@postgmail.com",
            "email_confirmed": true,
            "is_admin": false,
            "created_at": "2022-09-25T21:28:12.536Z",
            "updated_at": "2022-09-25T21:28:12.568Z",
            "credentials_id": 10
          },
          {
            "id": 9,
            "name": "NormalUser3",
            "email": "userRegular3@postgmail.com",
            "email_confirmed": true,
            "is_admin": false,
            "created_at": "2022-09-25T21:28:12.536Z",
            "updated_at": "2022-09-25T21:28:12.568Z",
            "credentials_id": 9
          }
        ]
      );
      // Mocking the passport strategy behavior of appending users details in request after validation
      let request = {
        user: {
          id: 7,
          name: 'new name',
          email: 'userRegular@postgmail.com',
          email_confirmed: true,
          is_admin: true,//admin user
          created_at: '2022-09-25T16:37:07.178Z',
          updated_at: '2022-09-25T16:39:26.726Z',
          credentials_id: 7
        }
      }

      let result = await userService.find(null, request);

      expect(result).toBeTruthy();
      expect(Object.keys(result).length).toBeGreaterThan(1); //as we are mocking 2 records
    });

    it('Find single user with id 9 if UserId 9 is requesting it', async () => {
      prismaService.user.findUnique = jest.fn().mockReturnValueOnce(
        [
          {
            id: 9,
            name: 'new name',
            email: 'userRegular@postgmail.com',
            email_confirmed: true,
            is_admin: false,
            created_at: '2022-09-25T16:37:07.178Z',
            updated_at: '2022-09-25T16:39:26.726Z',
            credentials_id: 7
          }
        ]
      );
      // Mocking the passport strategy behavior of appending users details in request after validation
      let request = {
        user: {
          id: 9,
          name: 'new name',
          email: 'userRegular@postgmail.com',
          email_confirmed: true,
          is_admin: false,//non-admin user
          created_at: '2022-09-25T16:37:07.178Z',
          updated_at: '2022-09-25T16:39:26.726Z',
          credentials_id: 7
        }
      }

      let result = await userService.findUnique({ id: 9 }, false);

      expect(result).toBeTruthy();
      expect(result[0].id).toEqual(request.user.id);
    });

    // UPDATE

    it('Update single user datails like name', async () => {
      prismaService.user.update = jest.fn().mockReturnValueOnce(

        {
          "id": 12,
          "name": "Updated name",
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }

      );
      // Mocking the passport strategy behavior of appending users details in request after validation
      let request = {
        user: {
          "id": 12,
          "name": "Mike Church",
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }
      }

      let result = await userService.update({ id: 12, name: 'Updated name' });

      expect(result).toBeTruthy();
      expect(result).toEqual({
        "id": 12,
        "name": "Updated name",
        "email": "mike@postgmail.com",
        "email_confirmed": true,
        "is_admin": false,
        "created_at": "2022-09-27T12:37:52.866Z",
        "updated_at": "2022-09-27T12:37:52.893Z",
        "credentials_id": 12
      });
    });

    it('Should not Update user datails if the user is deleted', async () => {
      prismaService.user.findUnique = jest.fn().mockReturnValueOnce(
        {
          "id": 12,
          "name": `(deleted)`,
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }

      );
      prismaService.user.update = jest.fn().mockReturnValueOnce(
        {
          "id": 12,
          "name": "Updated name",
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }

      );
      // Mocking the passport strategy behavior of appending users details in request after validation
      let request = {
        user: {
          "id": 12,
          "name": `(deleted)`,
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }
      }
      try {

        let result = await userService.update({ id: 12, name: 'Updated name' });

        expect('should fail').toBeFalsy();
      } catch (err) {

        expect(prismaService.user.update).not.toHaveBeenCalled();
        expect(err).toBeTruthy();
        expect(err.response).toEqual({
          statusCode: 400,
          message: 'User does not exist!',
          error: 'Bad Request'
        });
      }
    });

    // DELETE

    it('delete function should just update the record with name `(deleted)`', async () => {
      prismaService.user.update = jest.fn().mockReturnValueOnce(
        {
          "id": 12,
          "name": `(deleted)`,
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }
      );
      prismaService.user.delete = jest.fn();
      // Mocking the passport strategy behavior of appending users details in request after validation
      let request = {
        user: {
          "id": 12,
          "name": 'Normal User',
          "email": "mike@postgmail.com",
          "email_confirmed": true,
          "is_admin": false,
          "created_at": "2022-09-27T12:37:52.866Z",
          "updated_at": "2022-09-27T12:37:52.893Z",
          "credentials_id": 12
        }
      }
      try {

        let result = await userService.delete({ id: 12 });

        expect(result).toBeTruthy();
        expect(prismaService.user.update).toHaveBeenCalled();
        expect(result).toEqual({
          "users": {
            "id": 12,
            "name": `(deleted)`,
            "email": "mike@postgmail.com",
            "email_confirmed": true,
            "is_admin": false,
            "created_at": "2022-09-27T12:37:52.866Z",
            "updated_at": "2022-09-27T12:37:52.893Z",
            "credentials_id": 12
          }
        });
        expect(prismaService.user.delete).not.toHaveBeenCalled();
      } catch (err) {
        expect(err).toBeFalsy();
      }
    });

  });
});
