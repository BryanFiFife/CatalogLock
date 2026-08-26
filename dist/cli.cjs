#!/usr/bin/env node
import('./cli.js').catch((err)=>{ console.error(err); process.exitCode=1; });
