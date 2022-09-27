import { Catch, HttpStatus } from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { Request } from 'express';

@Catch(PrismaClientKnownRequestError)
export class QueryExceptionFilter {
  catch(exception: PrismaClientKnownRequestError, host) {
    const name = exception.name;
    let message = exception.message;
    const errorCode = exception.code;
    const meta = exception.meta;
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const request: Request = ctx.getRequest();

    switch (errorCode) {
      case 'P2000':
        message = 'Too Long Value Constraint Error.';
        break;
      case 'P2001':
        message = 'Record Does Not Exist.';
        break;
      case 'P2002':
        message = 'Unique Constraint Error.';
        break;
      case 'P2003':
        message = 'Foreign Key Constraint Error.';
        break;
      case 'P2004':
        message = 'Database Constraint Error.';
        break;
      case 'P2006':
        message = 'Field Value Invalid Constraint Error.';
        break;
      case 'P2007':
        message = 'Data Validation Constraint Error.';
        break;
      case 'P2011':
        message = 'NULL Constraint Violation Error.';
        break;
      case 'P2013':
        message = 'Missing Required Argument Constraint Error.';
        break;
      case 'P2020':
        message = 'Provided OutOfRange Value Constraint Error.';
        break;
      case 'P2025':
        message = 'Record not found.';
        break;
    }

    const msg = {
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message,
      errorCode,
      meta,
      name,
    };

    response.status(HttpStatus.INTERNAL_SERVER_ERROR).json(msg);
  }
}
