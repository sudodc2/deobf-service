'use strict';
// WeAreDevs flattened-VM CFG reconstruction.
const fs = require('fs');
const luaparse = require('luaparse');
const { findDispatcher, collectBlocks, evalNum } = require('./analyze.js');

function parse(src) {
  return luaparse.parse(src, { luaVersion: '5.1', comments: false, ranges: true, locations: false });
}

// Determine the exit edge(s) of a block from the write(s) to the state var.
function exitEdge(block, stateVar) {
  // Collect all assignments to stateVar in order (need the last, sometimes the
  // second-to-last for the `g = g or reg` idiom).
  const writes = [];
  for (const st of block.stmts) {
    if (st.type === 'AssignmentStatement') {
      st.variables.forEach((v, idx) => {
        if (v.type === 'Identifier' && v.name === stateVar) writes.push(st.init[idx]);
      });
    } else if (st.type === 'LocalStatement') {
      st.variables.forEach((v, idx) => { if (v.name === stateVar) writes.push(st.init[idx]); });
    }
  }
  const last = writes[writes.length - 1];
  if (!last) return { kind: 'fallthrough' };
  // Unconditional numeric jump
  const n = evalNum(last);
  if (n != null) return { kind: 'jump', to: n };
  // Conditional: cond and A or B
  if (last.type === 'LogicalExpression' && last.operator === 'or' &&
      last.left.type === 'LogicalExpression' && last.left.operator === 'and') {
    const cond = last.left.left;
    const a = evalNum(last.left.right);
    const b = evalNum(last.right);
    if (a != null && b != null) return { kind: 'branch', cond, tTo: a, fTo: b };
  }
  // `g = g or <X>` idioms. Build an intra-block map of temp -> last numeric value
  // so we can resolve identifiers used as jump targets / fallbacks.
  if (last.type === 'LogicalExpression' && last.operator === 'or' &&
      last.left.type === 'Identifier' && last.left.name === stateVar) {
    const tempNum = {};
    for (const st of block.stmts) {
      if (st.type === 'AssignmentStatement') {
        st.variables.forEach((v, idx) => {
          if (v.type === 'Identifier') { const n2 = evalNum(st.init[idx]); if (n2 != null) tempNum[v.name] = n2; else delete tempNum[v.name]; }
        });
      }
    }
    const resolve = (node) => {
      const nn = evalNum(node); if (nn != null) return nn;
      if (node.type === 'Identifier' && tempNum[node.name] != null) return tempNum[node.name];
      return null;
    };
    const prior = writes[writes.length - 2];
    const fb = resolve(last.right);
    // loop-condition pattern: prior g-write = `<cond> and <numA>` ; fallback = numB
    if (prior && prior.type === 'LogicalExpression' && prior.operator === 'and') {
      const a = resolve(prior.right);
      if (a != null && fb != null) return { kind: 'branch', cond: prior.left, tTo: a, fTo: fb };
    }
    // plain `g = g or reg`: g already numeric -> jump
    for (let i = writes.length - 2; i >= 0; i--) {
      const pv = resolve(writes[i]);
      if (pv != null) return { kind: 'jump', to: pv };
    }
  }
  // `g = S[M(k)]` -> S indexed by a (non-numeric) constant string = nil = halt/return.
  if (last.type === 'IndexExpression' && last.base.type === 'Identifier') {
    return { kind: 'halt', via: last };
  }
  // Boolean/nil halt (while g -> exits when falsy)
  if (last.type === 'BooleanLiteral' && last.value === false) return { kind: 'halt' };
  if (last.type === 'NilLiteral') return { kind: 'halt' };
  // Truly data-dependent next state
  return { kind: 'computed', expr: last };
}

function build(src) {
  const ast = parse(src);
  const disp = findDispatcher(ast);
  if (!disp) throw new Error('no dispatcher');
  const stateVar = disp.stateVar;
  const blocks = [];
  collectBlocks(disp.whileNode.body, stateVar, -Infinity, Infinity, blocks);
  blocks.forEach((b, i) => {
    b.id = i;
    b.edge = exitEdge(b, stateVar);
    b.hasReturn = JSON.stringify(b.stmts).includes('"ReturnStatement"');
  });
  // Map a state value -> block whose [lo,hi) contains it.
  function blockForState(s) {
    return blocks.find((b) => s >= b.lo && s < b.hi) || null;
  }
  return { stateVar, blocks, blockForState, ast, disp };
}

if (require.main === module) {
  const src = fs.readFileSync(process.argv[2], 'utf8');
  const cfg = build(src);
  const kinds = {};
  cfg.blocks.forEach((b) => { kinds[b.edge.kind] = (kinds[b.edge.kind] || 0) + 1; });
  console.log('blocks:', cfg.blocks.length, 'edge kinds:', JSON.stringify(kinds));
  console.log('blocks with ReturnStatement:', cfg.blocks.filter((b) => b.hasReturn).length);
  // Show edges + which target block each jump lands in
  cfg.blocks.forEach((b) => {
    const e = b.edge;
    let s = `#${b.id} [${b.lo},${b.hi}) ${e.kind}`;
    if (e.kind === 'jump') { const t = cfg.blockForState(e.to); s += ` -> ${e.to} (#${t ? t.id : '?'})`; }
    if (e.kind === 'branch') { const ta = cfg.blockForState(e.tTo), fb = cfg.blockForState(e.fTo); s += ` T:${e.tTo}(#${ta ? ta.id : '?'}) F:${e.fTo}(#${fb ? fb.id : '?'})`; }
    console.log(s);
  });
}

module.exports = { build, parse, exitEdge };
