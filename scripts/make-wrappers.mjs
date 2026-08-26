import fs from 'node:fs/promises';

await fs.writeFile('dist/cli.cjs', `#!/usr/bin/env node\nimport('./cli.js').catch((err)=>{ console.error(err); process.exitCode=1; });\n`, { mode: 0o755 });
await fs.writeFile('dist/action.cjs', `import('./action.js').catch((err)=>{ console.error(err); process.exitCode=1; });\n`);
