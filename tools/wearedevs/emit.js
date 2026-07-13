'use strict';
// Structured devirtualizer for the WeAreDevs flattened VM.
//
// Uses the fully-resolved CFG (cfg.js) + decoded constant pool (wearedevs_deobf)
// to emit, per VM function, a readable Lua reconstruction: the flattened numeric
// dispatch is rebuilt into small labelled states with real control-flow edges,
// M(k) constant fetches are inlined as their decoded string/number literals, and
// the register/global primitives are rendered in a clean, documented notation.
//
// This is a faithful *representation* of the program's logic (real constants,
// real control flow, real operations). Original local names/comments were
// discarded by the obfuscator and cannot be resurrected.

const fs = require('fs');
const cfgmod = require('./cfg.js');
const wd = require('../../wearedevs_deobf.js');
const { evalNum } = require('./analyze.js');

// ---- primitive identifier semantics (see reverse-engineering notes) ----
// a  -> register value store (R)
// A  -> refcount table (bookkeeping)          [interpreter-local A is a temp]
// N  -> alloc fresh register
// b  -> release register (refcount--)
// q  -> retain registers
// D  -> unpack
// S  -> the global environment (getfenv()/_ENV)
// M(k) -> constant pool fetch (inlined)
// s,j,y,V,H -> closure builders (arity 5/1/3/4/0)

// Original VM identifiers that get rewritten to shared prelude globals (not temps).
const idmapGlobals = new Set(['a', 'N', 'b', 'S', 'D', 'Y', 'I']);

function isConstFetch(node) {
  // M(<arith>) call
  return node && node.type === 'CallExpression' && node.base && node.base.type === 'Identifier' &&
    node.base.name === 'M' && node.arguments.length === 1;
}

function makePrinter(pool, offset, label, stateVar) {
  const builders = { s: 5, j: 1, y: 3, V: 4, H: 0 };
  function constFor(node) {
    const k = evalNum(node.arguments[0]);
    if (k == null) return null;
    const idx = k - offset; // 1-based Lua index into pool
    const v = pool[idx - 1];
    return v;
  }
  function luaStr(s) { return wd_toLua(s); }
  const idmap = { a: 'R', Y: 'arg', I: 'up', N: 'alloc', b: 'release', S: 'env', D: 'unpack' };
  function p(node) {
    if (!node) return 'nil';
    switch (node.type) {
      case 'Identifier': return node.name === stateVar ? 'state' : (idmap[node.name] || node.name);
      case 'NumericLiteral': return String(node.value);
      case 'StringLiteral': return node.raw != null ? node.raw : JSON.stringify(node.value);
      case 'BooleanLiteral': return node.value ? 'true' : 'false';
      case 'NilLiteral': return 'nil';
      case 'VarargLiteral': return '...';
      case 'UnaryExpression': return node.operator + (node.operator.match(/\w/) ? ' ' : '') + p(node.argument);
      case 'BinaryExpression': return p(node.left) + ' ' + node.operator + ' ' + p(node.right);
      case 'LogicalExpression': return p(node.left) + ' ' + node.operator + ' ' + p(node.right);
      case 'MemberExpression': return p(node.base) + node.indexer + node.identifier.name;
      case 'IndexExpression': {
        // env["name"] with a constant string key -> env.name (readable global access)
        const baseName = node.base.type === 'Identifier' ? (idmap[node.base.name] || node.base.name) : null;
        if (baseName === 'env' && isConstFetch(node.index)) {
          const v = constFor(node.index);
          if (typeof v === 'string' && /^[A-Za-z_]\w*$/.test(v)) return 'env.' + v;
          if (v != null) return 'env[' + luaStr(v) + ']';
        }
        return p(node.base) + '[' + p(node.index) + ']';
      }
      case 'CallExpression': {
        if (isConstFetch(node)) {
          const v = constFor(node);
          if (v != null) return luaStr(v);
        }
        // closure builder: s/j/y/V/H(startState, {upvalRegs}) -> makeClosure(fn_X, {..})
        if (node.base.type === 'Identifier' && builders[node.base.name] != null && node.arguments.length >= 1) {
          const st = evalNum(node.arguments[0]);
          if (st != null && label && label[st] != null) {
            const ups = node.arguments.slice(1).map(p).join(', ');
            return 'makeClosure(fn_' + label[st] + ', ' + (ups || '{}') + ')  --[[ arity ' + builders[node.base.name] + ' ]]';
          }
        }
        return p(node.base) + '(' + node.arguments.map(p).join(', ') + ')';
      }
      case 'StringCallExpression': return p(node.base) + ' ' + p(node.argument);
      case 'TableCallExpression': return p(node.base) + ' ' + p(node.arguments);
      case 'TableConstructorExpression': {
        const fields = node.fields.map((f) => {
          if (f.type === 'TableKey') return '[' + p(f.key) + '] = ' + p(f.value);
          if (f.type === 'TableKeyString') return f.key.name + ' = ' + p(f.value);
          return p(f.value);
        });
        return '{' + fields.join(', ') + '}';
      }
      case 'FunctionDeclaration': return 'function(' + node.parameters.map((x) => x.name || '...').join(', ') + ') --[[ nested ]] end';
      default: return '--[[?' + node.type + ']]';
    }
  }
  return { p, constFor };
}

function wd_toLua(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"'; else if (c === 0x5c) out += '\\\\';
    else if (c === 0x0a) out += '\\n'; else if (c === 0x0d) out += '\\r'; else if (c === 0x09) out += '\\t';
    else if (c < 0x20 || c > 0x7e) out += '\\' + c; else out += s[i];
  }
  return out + '"';
}

// Print a single statement, skipping writes to the state var (control handled by edges).
function isReleaseCall(node) {
  return node && node.type === 'CallExpression' && node.base.type === 'Identifier' && node.base.name === 'b';
}

function printStmt(st, pr, stateVar) {
  const p = pr.p;
  if (st.type === 'AssignmentStatement') {
    const vars = []; const inits = [];
    st.variables.forEach((v, i) => {
      if (v.type === 'Identifier' && v.name === stateVar) return; // drop state writes
      if (isReleaseCall(st.init[i])) return; // drop `x = release(x)` register bookkeeping
      vars.push(p(v)); inits.push(p(st.init[i]));
    });
    if (!vars.length) return null;
    return vars.join(', ') + ' = ' + inits.join(', ');
  }
  if (st.type === 'CallStatement' && isReleaseCall(st.expression)) return null;
  if (st.type === 'LocalStatement') {
    const names = st.variables.map((v) => v.name).filter((n) => n !== stateVar);
    if (!names.length) return null;
    return 'local ' + names.join(', ') + (st.init.length ? ' = ' + st.init.map(p).join(', ') : '');
  }
  if (st.type === 'CallStatement') return p(st.expression);
  if (st.type === 'ReturnStatement') return 'return ' + st.arguments.map(p).join(', ');
  return '-- [' + st.type + ']';
}

// Discover functions: entry states = main + every builder-call first arg.
function discoverEntries(cfg, mainEntry) {
  const entries = new Set([mainEntry]);
  const builders = new Set(['s', 'j', 'y', 'V', 'H']);
  function scan(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.base.type === 'Identifier' && builders.has(node.base.name) && node.arguments.length >= 1) {
      const s = evalNum(node.arguments[0]);
      if (s != null) entries.add(s);
    }
    for (const k in node) { const v = node[k]; if (Array.isArray(v)) v.forEach(scan); else if (v && v.type) scan(v); }
  }
  cfg.blocks.forEach((b) => b.stmts.forEach(scan));
  return [...entries];
}

// Reachable block set from an entry state, following jump/branch/halt edges.
function reachable(cfg, entryState) {
  const start = cfg.blockForState(entryState);
  if (!start) return [];
  const seen = new Set(); const order = []; const stack = [start.id];
  while (stack.length) {
    const id = stack.pop();
    if (seen.has(id)) continue; seen.add(id); order.push(id);
    const b = cfg.blocks[id]; const e = b.edge;
    const push = (s) => { const t = cfg.blockForState(s); if (t) stack.push(t.id); };
    if (e.kind === 'jump') push(e.to);
    else if (e.kind === 'branch') { push(e.tTo); push(e.fTo); }
  }
  return order.sort((x, y) => x - y);
}

function devirt(src) {
  const cfg = cfgmod.build(src);
  const { S: pool, offset } = wd.decodePool(src);
  // main entry state
  const m = /\bG\s*\(\s*([^,]+),\s*\{\s*\}\s*\)\s*\)\s*\(\s*D\s*\(/.exec(src) || /return\s*\(\s*[A-Za-z]\w*\s*\(\s*([-0-9+*/() ]+)\s*,\s*\{\s*\}\s*\)\s*\)/.exec(src);
  const mainEntry = m ? evalNum(cfgmod.parse('return ' + m[1]).body[0].arguments[0]) : cfg.blocks[0].lo;
  const entries = discoverEntries(cfg, mainEntry);
  const label = {}; entries.forEach((e, i) => { label[e] = i; });
  const pr = makePrinter(pool, offset, label, cfg.stateVar);

  const out = [];
  out.push('--[[ WeAreDevs devirtualization — Sudo Deobfuscator');
  out.push('     ' + wd.SUDO_INVITE);
  out.push('     Flattened VM rebuilt into ' + entries.length + ' function(s) with real control flow.');
  out.push('     Legend:  R[n]=VM register   env=global environment (getfenv)   arg=call args');
  out.push('              up=captured upvalue registers   alloc()=new register   makeN(fn,up)=closure');
  out.push('              release()/retain()/RC[]=register-lifetime bookkeeping (safe to ignore). ]]');
  out.push('');
  out.push('local env = getfenv and getfenv() or _ENV   -- global environment the VM read from');
  out.push('local R = {}                                  -- VM register file');
  out.push('local __rc = 0');
  out.push('local function alloc() __rc = __rc + 1; return __rc end');
  out.push('local function makeClosure(fn, up) return function(...) return fn({...}, up) end end');
  const fnNames = entries.map((e) => (e === mainEntry ? 'main' : 'fn_' + label[e]));
  out.push('local ' + fnNames.join(', ') + '   -- forward declarations');
  out.push('');

  entries.forEach((entryState) => {
    const blocks = reachable(cfg, entryState);
    const fname = entryState === mainEntry ? 'main' : ('fn_' + label[entryState]);
    // relabel this function's states to small ints
    const local = {}; blocks.forEach((id, i) => { local[id] = i; });
    const entryBlock = cfg.blockForState(entryState);
    // collect scratch temp names assigned in this function's blocks
    const temps = new Set();
    blocks.forEach((id) => cfg.blocks[id].stmts.forEach((st) => {
      if (st.type === 'AssignmentStatement') st.variables.forEach((v) => { if (v.type === 'Identifier' && v.name !== cfg.stateVar && !idmapGlobals.has(v.name)) temps.add(v.name); });
      if (st.type === 'LocalStatement') st.variables.forEach((v) => { if (v.name !== cfg.stateVar) temps.add(v.name); });
    }));
    out.push(fname + ' = function(arg, up)  -- entry state ' + entryState);
    if (temps.size) out.push('  local ' + [...temps].join(', '));
    out.push('  local state = ' + local[entryBlock.id]);
    out.push('  while state do');
    blocks.forEach((id, i) => {
      const b = cfg.blocks[id];
      out.push('    ' + (i === 0 ? 'if' : 'elseif') + ' state == ' + local[id] + ' then');
      b.stmts.forEach((st) => {
        const line = printStmt(st, pr, cfg.stateVar);
        if (line != null) out.push('      ' + line);
      });
      const e = b.edge;
      const lbl = (s) => { const t = cfg.blockForState(s); return t && local[t.id] != null ? local[t.id] : 'nil --[[ ' + s + ' ]]'; };
      if (e.kind === 'jump') out.push('      state = ' + lbl(e.to));
      else if (e.kind === 'branch') out.push('      state = (' + pr.p(e.cond) + ') and ' + lbl(e.tTo) + ' or ' + lbl(e.fTo));
      else out.push('      return  -- halt');
    });
    out.push('    end');
    out.push('  end');
    out.push('end');
    out.push('');
  });

  out.push('return main(...)');
  return { output: out.join('\n'), functions: entries.length, blocks: cfg.blocks.length, pool };
}

module.exports = { devirt };

if (require.main === module) {
  const src = fs.readFileSync(process.argv[2], 'utf8');
  const r = devirt(src);
  console.log(r.output);
  console.error('\n-- functions:', r.functions, 'blocks:', r.blocks);
}
