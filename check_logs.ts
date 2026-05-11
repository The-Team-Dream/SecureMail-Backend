import { PrismaClient } from '@prisma/client';

async function main() {
  const prisma = new PrismaClient();
  const logs = await prisma.syncLog.findMany({
    orderBy: { id: 'desc' },
    take: 5
  });
  console.log(JSON.stringify(logs, null, 2));
  await prisma.$disconnect();
}

main().catch(console.error);
