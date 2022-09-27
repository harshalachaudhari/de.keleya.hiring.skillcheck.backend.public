import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Patch,
  Post,
  Query,
  Req,
  HttpCode,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthenticateUserDto } from './dto/authenticate-user.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { FindUserDto } from './dto/find-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserService } from './user.service';
import { EndpointIsPublic } from '../common/decorators/publicEndpoint.decorator';
import { RolesGuard } from '../common/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { JwtAuthGuard } from '../common/guards/jwt-auth.guard';


@Controller('user')
export class UserController {
  constructor(private readonly usersService: UserService) { }

  @Get()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'user')
  async find(@Query() findUserDto: FindUserDto, @Req() req: Request) {

    return this.usersService.find(findUserDto, req);
  }

  @Get(':id')
  @Roles('admin', 'user')
  @UseGuards(JwtAuthGuard, RolesGuard)
  async findUnique(@Param('id', ParseIntPipe) id, @Req() req: Request) {

    return this.usersService.findUnique({ id: id }, false);
  }

  @EndpointIsPublic()
  @Post()
  @HttpCode(200)

  async create(@Body() createUserDto: CreateUserDto) {
    return await this.usersService.create(createUserDto);
  }

  @Patch()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'user')
  @HttpCode(200)
  async update(@Body() updateUserDto: UpdateUserDto, @Req() req: Request) {
    return await this.usersService.update(updateUserDto);
  }

  @Delete()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  async delete(@Body() deleteUserDto: DeleteUserDto, @Req() req: Request) {
    return await this.usersService.delete(deleteUserDto);
  }

  @EndpointIsPublic()
  @Post('validate')
  @HttpCode(200)
  async userValidateToken(@Req() req: Request) {
    return await this.usersService.validateToken(req?.headers?.authorization);
  }

  @EndpointIsPublic()
  @Post('authenticate')
  @HttpCode(200)
  async userAuthenticate(@Body() authenticateUserDto: AuthenticateUserDto) {
    let userValidity = await this.usersService.authenticate(authenticateUserDto)
    if (userValidity) {
      return userValidity;
    }
    throw new UnauthorizedException();
  }

  @EndpointIsPublic()
  @Post('token')
  @Roles('admin', 'user')
  @HttpCode(200)
  async userGetToken(@Body() authenticateUserDto: AuthenticateUserDto) {
    return this.usersService.authenticateAndGetJwtToken(authenticateUserDto);
  }
}
