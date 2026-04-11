const fs = require('fs');
const path = require('path');

const backendRoot = path.join(__dirname, '..');
const candidates = [
  path.join(backendRoot, 'contracts', 'ai-agent.proto'),
  path.join(backendRoot, '..', 'contracts', 'ai-agent.proto'),
];
const contract = candidates.find((p) => fs.existsSync(p));
if (!contract) {
  console.error('Missing shared proto. Tried:\n', candidates.join('\n'));
  process.exit(1);
}
console.log('contracts/ai-agent.proto OK:', contract);
