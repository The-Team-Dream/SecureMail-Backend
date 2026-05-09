const { Client } = require('pg');

async function main() {
  const client = new Client({
    connectionString: "postgresql://postgres:0000@localhost:5432/securemail?schema=public"
  });

  await client.connect();

  console.log('--- Recent SyncLogs ---');
  const logsRes = await client.query('SELECT id, "mailBoxId", status, "errorMessage", "syncedAt" FROM "SyncLog" ORDER BY "syncedAt" DESC LIMIT 5');
  console.table(logsRes.rows);

  console.log('--- Mailboxes ---');
  const mbRes = await client.query('SELECT id, "emailAddress", "lastSyncedAt" FROM "MailBox"');
  console.table(mbRes.rows);

  console.log('--- Total Messages ---');
  const msgRes = await client.query('SELECT COUNT(*) FROM "MailboxMessage"');
  console.table(msgRes.rows);

  await client.end();
}

main().catch(console.error);
