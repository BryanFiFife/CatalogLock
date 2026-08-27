import { execFileSync } from 'node:child_process';
const out=execFileSync('npm',['pack','--dry-run','--ignore-scripts','--json'],{encoding:'utf8'});
const data=JSON.parse(out);
const files=(data[0]?.files??[]).map(x=>x.path);
const forbidden=files.filter(f=>/(^|\/)(?:node_modules|tests|src|\.test-dist|\.release|\.github|coverage|release)(?:\/|$)|(^|\/)\.env(?:\.|$)|\.log$/.test(f));
if(forbidden.length){console.error('Forbidden npm package artifacts:\n'+forbidden.join('\n'));process.exit(1);}
for(const required of ['package.json','README.md','LICENSE','action.yml','dist/index.js','dist/cli.cjs','dist/action.cjs']){
  if(!files.includes(required)){console.error(`npm package is missing ${required}`);process.exit(1);}
}
console.log(`package hygiene OK (${files.length} files)`);
