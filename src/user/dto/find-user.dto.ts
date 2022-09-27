import { IsEmail, IsNumber, IsOptional, IsString } from 'class-validator';
export class FindUserDto {
  @IsOptional()
  @IsNumber()
  id?: number;

  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsEmail()
  email?: string;
}
