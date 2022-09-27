import { IsEmail, IsInt, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class DeleteUserDto {
  @IsEmail()
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  email?: string;

  @IsInt()
  @IsNotEmpty()
  @IsOptional()
  id?: number;
}
