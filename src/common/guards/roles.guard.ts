import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserService } from '../../user/user.service';
import { IsNotEmpty } from 'class-validator'

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector, private userService: UserService) { }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());

    const request = context.switchToHttp().getRequest();
    if (request?.user) {


      if (request?.user.is_admin) {
        return roles.includes('admin');
      }
      if (!request?.user.is_admin) {
        let isUserAccessingOwnData;
        if (request?.params?.id) {
          isUserAccessingOwnData = (request?.user?.id === Number(request.params.id))
        }
        else if (request?.body?.id) {
          isUserAccessingOwnData = (request?.user?.id === request.body.id);
        } else if (Object.keys(request?.params).length === 0 && Object.keys(request?.body).length === 0) {

          isUserAccessingOwnData = true;
        }

        return (roles.includes('user') && isUserAccessingOwnData);
      }
    }
    return false;
  }
}
