import { Injectable } from '@nestjs/common';
import { ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments } from 'class-validator';

export type UnencryptedPassword = string;

@ValidatorConstraint({ name: 'unencryptedPasswordValidator', async: true })
@Injectable()
export class UnencryptedPasswordValidator implements ValidatorConstraintInterface {
  async validate(val: UnencryptedPassword, args: any) {

    if (!val) return false;
    return this.isValidPassword(val, args.constraints['length'], args.constraints['patternsToEscape'], args.constraints['caseSensitivty'], args.constraints['numericDigits'], args.constraints['specialChars']);
  }

  isValidPassword(
    passwordToValidate: string,
    length: number,
    patternsToEscape: [string],
    caseSensitivty: boolean,
    numericDigits: boolean,
    specialChars: boolean
  ): boolean {

    if (!passwordToValidate) return false;
    if (passwordToValidate.length < length) {

      return false;
    }
    if (caseSensitivty) {

      const hasUpperCase = /[A-Z]/.test(passwordToValidate);
      if (!hasUpperCase) {

        return false;
      }
      const hasLowerCase = /[a-z]/.test(passwordToValidate);
      if (!hasLowerCase) {

        return false;
      }
    }
    if (numericDigits) {

      const hasNumbers = /[\d]/.test(passwordToValidate);
      if (!hasNumbers) {
        return false;
      }
    }
    if (specialChars) {

      const hasSpeacialChars = /[[@$!%*#?&\]]/.test(passwordToValidate);

      if (!hasSpeacialChars) {
        return false;
      }
    }
    if (patternsToEscape.length > 0) {

      const passwordToValidateLowerCase = passwordToValidate.toLowerCase();
      for (const pattern in patternsToEscape) {
        const hasMatchesWithPattern = passwordToValidateLowerCase.match(new RegExp(pattern)).length;

        if (hasMatchesWithPattern) {
          return false;
        }
      }
    }

    return true;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  defaultMessage(args: ValidationArguments) {
    return `Password is not complex enough`;
  }
}