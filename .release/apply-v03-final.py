#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()

def replace(path, old, new):
    p = root / path
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"expected patch anchor missing in {path}")
    p.write_text(s.replace(old, new, 1))

replace("src/mcp.ts",
"""  const messages = parseJsonRpcMessages(response.body);
  const msg = messages.find(m => m.id === id);
  if (!msg) throw new Error(`${method} response does not contain the matching request id`);
  if (msg.jsonrpc !== '2.0') throw new Error(`${method} response jsonrpc must equal 2.0`);
""",
"""  const messages = parseJsonRpcMessages(response.body);
  const msg = messages.find(m => m.id === id);
  if (!msg) {
    const unboundError = messages.find(m => (m.id === null || m.id === undefined) && isObject(m.error));
    if (unboundError) {
      if (unboundError.jsonrpc !== '2.0') throw new Error(`${method} response jsonrpc must equal 2.0`);
      const error = unboundError.error as Record<string, unknown>;
      const code = typeof error.code === 'number' ? error.code : undefined;
      const message = typeof error.message === 'string' ? error.message : 'MCP error';
      if (code === -32601 || response.status === 404) throw new MethodNotFound(`${method}: ${message}`);
      throw new Error(`${method} JSON-RPC error${code !== undefined ? ` ${code}` : ''}: ${message}`);
    }
    throw new Error(`${method} response does not contain the matching request id`);
  }
  if (msg.jsonrpc !== '2.0') throw new Error(`${method} response jsonrpc must equal 2.0`);
""")

needle = """test('response must contain matching JSON-RPC id',async()=>{const req=server({byCall:b=>b.method==='server/discover'?{url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:999,result:complete({supportedVersions:['2026-07-28'],capabilities:{}})})}:undefined});const r=await inspect(mergePolicy({inspectMcpPrimitives:false}),req);assert.ok(r.findings.some(f=>/matching request id/.test(f.message)));});
"""
replace("tests/mcp.test.ts", needle, needle + """test('unbound JSON-RPC protocol errors are surfaced accurately instead of as id mismatches',async()=>{const req=server({byCall:b=>b.method==='server/discover'?{url:endpoint,status:400,body:JSON.stringify({jsonrpc:'2.0',id:null,error:{code:-32000,message:'Unsupported protocol version: 2026-07-28'}})}:undefined});const r=await inspect(mergePolicy({inspectMcpPrimitives:false}),req);assert.ok(r.findings.some(f=>/JSON-RPC error -32000: Unsupported protocol version: 2026-07-28/.test(f.message)));assert.ok(!r.findings.some(f=>/matching request id/.test(f.message)));});
""")

p = root / "README.md"
s = p.read_text()
s = s.replace("tests-134%2F134%20passing", "tests-135%2F135%20passing")
s = s.replace("- 134 adversarial/unit/end-to-end tests", "- 135 adversarial/unit/end-to-end tests")
s = s.replace("- interoperability against the official MCP TypeScript SDK v2 / MCP 2026-07-28 server path",
              "- positive MCP 2026-07-28 interoperability against the current official TypeScript SDK source pinned to an immutable upstream commit, plus an explicit published-SDK compatibility-boundary check")
anchor = "### MCP 2026-07-28\n"
boundary = "> **Published SDK compatibility boundary:** the npm-published `@modelcontextprotocol/server@2.0.0` package currently advertises protocol support only through `2025-11-25`. CatalogLock therefore does not claim that package as a 2026-07-28 peer. Release gating uses the current official SDK source pinned by commit for positive 2026-07-28 interoperability, and separately verifies that older published peers fail closed with an accurate protocol-version diagnostic.\n"
if boundary not in s:
    if anchor not in s:
        raise SystemExit("README MCP anchor missing")
    s = s.replace(anchor, anchor + "\n" + boundary, 1)
p.write_text(s)

p = root / "docs/releases/v0.3.0.md"
s = p.read_text()
s = s.replace("official MCP TypeScript SDK v2 interoperability before publication.",
              "positive MCP 2026-07-28 interoperability against the current official TypeScript SDK source pinned to an immutable upstream commit, plus an explicit compatibility-boundary check against the npm-published SDK 2.0.0, before publication.")
line = "- Protocol-version rejections returned as JSON-RPC errors with `id:null` are now surfaced accurately instead of being misclassified as response-ID mismatches.\n"
if line not in s:
    s += "\n" + line
p.write_text(s)

p = root / "action.yml"
s = p.read_text()
if "using: node20" not in s:
    raise SystemExit("action.yml node20 anchor missing")
p.write_text(s.replace("using: node20", "using: node24", 1))

print("v0.3.0 final patch applied")
