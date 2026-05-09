process.env.DATABASE_URL="postgresql://postgres:0000@localhost:5432/securemail?schema=public";
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const logs = await prisma.syncLog.findMany({ orderBy: { syncedAt: 'desc' }, take: 5 });
  console.log('--- Recent SyncLogs ---');
  console.log(JSON.stringify(logs, null, 2));

  const mailboxes = await prisma.mailBox.findMany({
    select: { id: true, emailAddress: true, lastSyncedAt: true }
  });
  console.log('--- Mailboxes ---');
  console.log(JSON.stringify(mailboxes, null, 2));

  const msgCount = await prisma.mailboxMessage.count();
  console.log('Total Messages in DB:', msgCount);
}

main().catch(console.error).finally(() => prisma.$disconnect());
 