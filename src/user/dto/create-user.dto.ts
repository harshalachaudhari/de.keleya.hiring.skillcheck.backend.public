import { IsEmail, IsNotEmpty, IsString, IsBoolean, MinLength, IsOptional, ValidateNested } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;

  @IsBoolean()
  email_confirmed?: boolean;

  @IsBoolean()
  @IsOptional()
  is_admin?: boolean;
}
