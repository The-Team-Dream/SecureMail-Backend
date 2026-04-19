import { PrismaClient } from '../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Role } from '../generated/prisma/enums';
import * as bcrypt from 'bcrypt';

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL!,
});
const prisma = new PrismaClient({ adapter });

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function upsertUser(
  email: string,
  username: string,
  password: string,
  role: Role,
) {
  const existing = await prisma.user.findUnique({ where: { email } });

  if (existing) {
    if (existing.role === role) {
      console.log(`✔  ${role} user already exists: ${email}`);
      return;
    }
    await prisma.user.update({ where: { email }, data: { role } });
    console.log(`↑  Updated user to ${role}: ${email}`);
    return;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await prisma.user.create({
    data: {
      email,
      username,
      passwordHash,
      provider: 'local',
      isVerified: true,
      role,
    },
  });
  console.log(`✚  Created ${role} user: ${email}  (password: ${password})`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  // Admin account — can be overridden via env vars in production
  await upsertUser(
    process.env.ADMIN_EMAIL ?? 'admin@securemail.local',
    'Admin',
    process.env.ADMIN_PASSWORD ?? 'Admin123!',
    Role.ADMIN,
  );

  // Demo account — a regular user for quick manual testing
  // Credentials are intentionally public; change before going to production.
  await upsertUser(
    process.env.DEMO_EMAIL ?? 'demo@securemail.local',
    'Demo User',
    process.env.DEMO_PASSWORD ?? 'Demo123!',
    Role.USER,
  );
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
