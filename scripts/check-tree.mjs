import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const forbidden = [
  /(^|\/)node_modules\//,
  /(^|\/)\.test-dist\//,
  /(^|\/)\.release\//,
  /(^|\/)\.smoke\//,
  /(^|\/)release\//,
  /(^|\/)coverage\//,
  /(^|\/)\.env(?:\.|$)/,
  /cataloglock-.*\.tgz$/,
  /(^|\/).*\.log$/
];

let files=[];
if (fs.existsSync('.git')) {
  files=execFileSync('git',['ls-files','-z'],{encoding:'utf8'}).split('\0').filter(Boolean);
} else {
  const skip=new Set(['node_modules','.test-dist','.git','coverage','release']);
  const walk=(dir='.')=>{for(const ent of fs.readdirSync(dir,{withFileTypes:true})){if(skip.has(ent.name))continue;const p=path.join(dir,ent.name).replace(/^\.\//,'');if(ent.isDirectory())walk(p);else files.push(p);}};
  walk();
}
const bad=files.filter(f=>forbidden.some(re=>re.test(f)));
if(bad.length){console.error('Forbidden release-tree artifacts:\n'+bad.join('\n'));process.exit(1);}
for(const required of ['LICENSE','.gitignore','README.md','package.json','package-lock.json','action.yml']){
  if(!files.includes(required) && !fs.existsSync(required)){console.error(`Required release file missing: ${required}`);process.exit(1);}
}
console.log(`tree hygiene OK (${files.length} source files inspected)`);
