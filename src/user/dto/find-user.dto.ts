import { IsDate, IsEmail, IsNumber, IsOptional, IsString } from 'class-validator';
import { date } from 'joi';
export class FindUserDto {
  @IsOptional()
  id?: number;

  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsNumber()
  limit?: number;

  @IsOptional()
  @IsNumber()
  offset?: number;

  @IsOptional()
  @IsString()
  updatedSince?: string;

}
