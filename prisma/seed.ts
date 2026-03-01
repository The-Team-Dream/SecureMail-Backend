import { PrismaClient } from '../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Role } from '../generated/prisma/enums';
import * as bcrypt from 'bcrypt';

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL!,
});
const prisma = new PrismaClient({ adapter });

async function main() {
  const adminEmail = process.env.ADMIN_EMAIL ?? 'admin@securemail.local';
  const adminPassword = process.env.ADMIN_PASSWORD ?? 'Admin123!';

  const existing = await prisma.user.findUnique({
    where: { email: adminEmail },
  });

  if (existing) {
    if (existing.role === Role.ADMIN) {
      console.log('Admin user already exists:', adminEmail);
      return;
    }
    await prisma.user.update({
      where: { email: adminEmail },
      data: { role: Role.ADMIN },
    });
    console.log('Updated user to admin:', adminEmail);
    return;
  }

  const passwordHash = await bcrypt.hash(adminPassword, 10);
  await prisma.user.create({
    data: {
      email: adminEmail,
      username: 'Admin',
      passwordHash,
      provider: 'local',
      isVerified: true,
      role: Role.ADMIN,
    },
  });
  console.log('Created admin user:', adminEmail);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
