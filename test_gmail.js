
const { PrismaClient } = require('@prisma/client');
const { google } = require('googleapis');
const prisma = new PrismaClient();
const crypto = require('crypto');

// Quick decryption mock for test script
const algorithm = 'aes-256-cbc';
const secretKey = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

function decrypt(text) {
  const [ivHex, encryptedHex] = text.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

async function run() {
  const mb = await prisma.mailBox.findUnique({ where: { id: 5 }, include: { oauthToken: true } });
  if (!mb || !mb.oauthToken) return console.log('No mailbox/token');
  
  const accessToken = decrypt(mb.oauthToken.accessTokenEncrypted);
  const refreshToken = decrypt(mb.oauthToken.refreshTokenEncrypted);
  
  const oauth2Client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
  oauth2Client.setCredentials({ access_token: accessToken, refresh_token: refreshToken });
  const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
  
  try {
    const res = await gmail.users.messages.list({ userId: 'me', labelIds: ['INBOX'], maxResults: 10 });
    console.log('Messages from INBOX:', res.data.messages ? res.data.messages.length : 0);
  } catch (e) {
    console.log('Error:', e.message);
  }
}
run().finally(() => prisma.\$disconnect());

