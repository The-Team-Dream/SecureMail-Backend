const fs = require('fs');
const path = require('path');

const backendRoot = path.join(__dirname, '..');

function assertProto(name) {
  const candidates = [
    path.join(backendRoot, 'contracts', name),
    path.join(backendRoot, '..', 'contracts', name),
  ];
  const contract = candidates.find((p) => fs.existsSync(p));
  if (!contract) {
    console.error(`Missing shared proto ${name}. Tried:\n`, candidates.join('\n'));
    process.exit(1);
  }
  console.log(`contracts/${name} OK:`, contract);
}

assertProto('ai-agent.proto');
assertProto('malware.proto');
