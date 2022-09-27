import { IsEmail, IsInt, IsOptional, IsString } from 'class-validator';

export class UpdateUserDto {
  @IsInt()
  id: number;

  @IsString()
  @IsOptional()
  name: string;

  @IsString()
  @IsOptional()
  newpassword?: string;

  @IsEmail()
  @IsOptional()
  email?: string;
}
