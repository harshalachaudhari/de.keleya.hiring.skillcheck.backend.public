import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthenticateUserDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}
