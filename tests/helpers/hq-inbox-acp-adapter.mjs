// Protocol fixture: exercise an existing configured MCP command as a child
// inheriting the real Soul member environment. No LLM or ACP-server-slot code.
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const lines = createInterface({ input: process.stdin });
const send = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
let child;
const stop = () => { child?.stdin.end(); child?.kill(); process.exit(0); };
process.once('SIGTERM', stop); process.once('SIGINT', stop); lines.once('close', stop);
lines.on('line', (line) => {
  const request = JSON.parse(line);
  (async () => {
    if (request.method === 'initialize') return { protocolVersion: 1, agentCapabilities: {}, authMethods: [] };
    if (request.method === 'session/new') return { sessionId: 'fixture:session' };
    if (request.method === 'session/cancel') { child?.kill(); return {}; }
    if (request.method !== 'session/prompt') throw new Error('unsupported fixture method');
    const config = JSON.parse(readFileSync(process.env.TEST_HQ_MCP_CONFIG));
    child = spawn(config.command, config.args, { env: { ...process.env, ...config.env }, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stderr.on('data', (chunk) => process.stderr.write(chunk));
    const replies = createInterface({ input: child.stdout }); const pending = new Map(); let id = 0;
    child.on('error', (error) => { for (const { reject } of pending.values()) reject(error); });
    child.on('exit', () => { for (const { reject } of pending.values()) reject(new Error('MCP exited before its reply')); });
    replies.on('line', (text) => { const reply = JSON.parse(text); const waiter = pending.get(reply.id); if (waiter) { pending.delete(reply.id); waiter.resolve(reply); } });
    const ask = (method, params) => new Promise((resolve, reject) => { const next = ++id; pending.set(next, { resolve, reject }); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: next, method, params })}\n`); });
    await ask('initialize', { protocolVersion: '2025-06-18' });
    const listed = await ask('tools/list', {});
    const searched = await ask('tools/call', { name: 'search_tools', arguments: { query: 'take_inbox' } });
    const described = await ask('tools/call', { name: 'describe_tool', arguments: { name: 'take_inbox' } });
    const one = await ask('tools/call', { name: 'call_write_tool', arguments: { name: 'take_inbox', arguments: {} } });
    const empty = await ask('tools/call', { name: 'call_write_tool', arguments: { name: 'take_inbox', arguments: {} } });
    const forged = await ask('tools/call', { name: 'call_write_tool', arguments: { name: 'take_inbox', arguments: { repo: 'other/project' } } });
    child.stdin.end(); await new Promise((resolve) => child.once('exit', resolve)); child = undefined;
    send({ jsonrpc: '2.0', method: 'session/update', params: { sessionId: 'fixture:session', update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: JSON.stringify({ listed, searched, described, one, empty, forged }) } } } });
    return { stopReason: 'end_turn' };
  })().then((result) => { if (request.id !== undefined) send({ jsonrpc: '2.0', id: request.id, result }); }, (error) => { if (request.id !== undefined) send({ jsonrpc: '2.0', id: request.id, error: { code: -32603, message: error.message } }); });
});
