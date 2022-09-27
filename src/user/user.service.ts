import {
  Injectable,
  ForbiddenException,
  UnauthorizedException,
  BadRequestException,
  NotAcceptableException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Prisma, User } from '@prisma/client';
import { PrismaService } from '../prisma.services';
import { AuthenticateUserDto } from './dto/authenticate-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { hashPassword, matchHashedPassword } from '../common/utils/password';
import { JwtTokenUser } from '../common/types/jwtTokenUser';
import { ConfigService } from '@nestjs/config';
import { UnencryptedPasswordValidator, UnencryptedPassword } from '../common/validators/unencrypted-password-validator';



@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private unencryptedPasswordValidator: UnencryptedPasswordValidator,
  ) { }
  /**
   * Finds users with matching fields
   *
   * @param findUserDto
   * @returns User[]
   */
  async find(findUserDto: FindUserDto, request: any) {
    const ids = request?.query?.id
      ? request.query.id.split(',').map(function (item: any) {
        return parseInt(item, 10);
      })
      : undefined;

    let isNonAdminUser = !request?.user?.is_admin;

    if (request?.query) {
      let data = this.prisma.user.findMany({
        take: request.query.limit ? parseInt(request.query.limit) : undefined,
        skip: request.query.offset ? parseInt(request.query.offset) : undefined,
        where: {
          email: request.query.email,
          id: { in: ids },
          name: {
            contains: request.query.name,
          },
          updated_at: { gte: request.query.updatedSince ? new Date(request.query.updatedSince) : undefined },
        },
        orderBy: {
          id: 'desc',
        },
      });
      if (isNonAdminUser) {
        return (await data).filter(record => record.id == request?.user?.id);
      }
      return data;
    } else if (isNonAdminUser) {
      return this.findUnique({ id: request?.user?.id });
    }
    else {
      return this.prisma.user.findMany();
    }

  }

  /**
   * Finds single User by id, name or email
   *
   * @param whereUnique
   * @returns User
   */
  async findUnique(whereUnique: Prisma.UserWhereUniqueInput, includeCredentials = false) {

    return this.prisma.user.findUnique({
      where: whereUnique,
      include: {
        credentials: includeCredentials,
      },
    });
  }

  /**
   * Creates a new user with credentials
   *
   * @param createUserDto
   * @returns result of create
   */
  async create(createUserDto: CreateUserDto) {

    let isValidPassword = await this.unencryptedPasswordValidator.validate(createUserDto.password, {
      constraints: {
        'length': 6,
        'patternsToEscape': [],
        'caseSensitivty': true,
        'numericDigits': true,
        'specialChars': true
      }
    }
    );
    if (isValidPassword) {
      const hashedPw = await hashPassword(createUserDto.password);
      const newUser = this.prisma.user.create({
        data: {
          name: createUserDto.name,
          email: createUserDto.email,
          email_confirmed: createUserDto.email_confirmed,
          is_admin: createUserDto.is_admin,
          credentials: {
            create: {
              hash: hashedPw,
            },
          },
        },
      });

      return newUser;
    }
    else {
      throw new NotAcceptableException(`Password is not complex enough`);
    }
  }

  /**
   * Updates a user unless it does not exist or has been marked as deleted before
   *
   * @param updateUserDto
   * @returns result of update
   */

  async update(updateUserDto: UpdateUserDto) {
    const userDetails = await this.prisma.user.findUnique({
      where: { id: updateUserDto.id },
      include: { credentials: true }
    });
    const DELETED_USER_NAME = `(deleted)`;
    if (userDetails && userDetails['name'] !== DELETED_USER_NAME) {
      let data = {};
      if (updateUserDto?.newpassword) {
        data = {
          name: updateUserDto?.name,
          email: updateUserDto?.email,
          credentials: {
            update: {
              hash: await hashPassword(updateUserDto?.newpassword)
            }
          }
        }
      } else {
        data = {
          name: updateUserDto?.name,
          email: updateUserDto?.email,
        }
      }
      return await this.prisma.user.update({
        where: {
          id: Number(updateUserDto.id),
        },
        data,
      });
    }

    throw new BadRequestException(`User does not exist!`);
  }

  /**
   * Deletes a user
   * Function does not actually remove the user from database but instead marks them as deleted by:
   * - removing the corresponding `credentials` row from your db
   * - changing the name to DELETED_USER_NAME constant (default: `(deleted)`)
   * - setting email to NULL
   *
   * @param deleteUserDto
   * @returns results of users and credentials table modification
   */
  async delete(deleteUserDto: DeleteUserDto) {
    const DELETED_USER_NAME = `(deleted)`;
    const deleteOn = deleteUserDto.id ? {
      id: deleteUserDto.id
    } : { email: deleteUserDto.email };
    return {
      users: await this.prisma.user.update({
        where: deleteOn,
        data: {
          name: DELETED_USER_NAME,
          email: '',
          credentials: {
            update: { hash: '' }
          }
        }
      }),
    }
  }

  /**
   * Authenticates a user and returns a JWT token
   *
   * @param authenticateUserDto email and password for authentication
   * @returns a JWT token
   */
  async authenticateAndGetJwtToken(authenticateUserDto: AuthenticateUserDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: authenticateUserDto.email,
      },
      include: { credentials: true }
    });

    if (!user) throw new ForbiddenException('Access Denied');
    const isPasswordMatching = await matchHashedPassword(authenticateUserDto.password, user?.credentials?.hash);
    if (!isPasswordMatching) throw new ForbiddenException('Access Denied');

    const token = await this.getToken(user.id, user.email);

    return token;
  }

  async getToken(userId: number, email: string) {
    const jwtPayload: JwtTokenUser = {
      id: userId,
      username: email,
    };

    const accessToken = await this.jwtService.signAsync(jwtPayload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: this.configService.get<number>('JWT_EXPIRATION_TIME'),
    });
    return {
      token: accessToken,
    };
  }

  /**
   * Authenticates a user
   *
   * @param authenticateUserDto email and password for authentication
   * @returns true or false
   */
  async authenticate(authenticateUserDto: AuthenticateUserDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: authenticateUserDto.email,
      },
      include: {
        credentials: true,
      },
    });

    if (user && await matchHashedPassword(authenticateUserDto.password, user?.credentials?.hash)) {

      return user;
    }

    return false;
  }

  /**
   * Validates a JWT token
   *
   * @param token a JWT token
   * @returns the decoded token if valid
   */
  async validateToken(token: string) {
    const jwtToken = token.split(' ')[1];

    const decodedJwtAccessToken = await this.jwtService.decode(jwtToken);

    const currentTimestamp = new Date().getTime() / 1000;
    const tokenIsNotExpired = decodedJwtAccessToken && (decodedJwtAccessToken['exp'] > currentTimestamp);

    if (tokenIsNotExpired) {
      return decodedJwtAccessToken;
    }

    return false;

  }
}
