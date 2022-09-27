import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  await prisma.user.deleteMany();
  await prisma.credentials.deleteMany();

  console.log('Seeding...');

  const user1 = await prisma.user.create({
    data: {
      name: 'Lisa',
      email: 'lisa@seed.com',
      email_confirmed: true,
      // secret42
      is_admin: true,
      credentials: {
        create: {
          hash: '$2b$12$.Az4q7.QuAHePddBBChtm.LANLIG5.mJ9t.1C7v63GtkA5XZiMpeC', //crypted PW: Password@123
        },
      },
    },
  });
  const user2 = await prisma.user.create({
    data: {
      name: 'Bart',
      email: 'bart@seed.com',
      email_confirmed: true,
      is_admin: false,
      credentials: {
        create: {
          hash: '$2b$12$kooAUtwRLUTKN2VkZfIJgexzTWkwGI.G9ophg.XdJRyJWJi2rhy/e', //crypted PW: Password@123
        },
      },
    },
  });

  console.log({ user1, user2 });
}

main()
  .catch((e) => console.error(e))
  .finally(async () => {
    await prisma.$disconnect();
  });