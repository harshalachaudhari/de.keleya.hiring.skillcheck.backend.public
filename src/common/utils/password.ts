import * as bcrypt from 'bcrypt';

const saltOrRounds = 12;
export const hashPassword = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, saltOrRounds);
};

export const hashPasswordSync = (password: string): string => {
  return bcrypt.hashSync(password, saltOrRounds);
};

export const matchHashedPassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};
