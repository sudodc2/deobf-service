'use strict';
// Static structural analysis of the WeAreDevs flattened-VM interpreter.
// Parses the whole script with luaparse, locates the `while <state> do <if-tree>`
// dispatcher, and extracts every leaf basic block: the contiguous range of
// state values that route to it (from the binary-search if-tree) and its
// straight-line statement list. This is the foundation for CFG reconstruction.

const fs = require('fs');
const luaparse = require('luaparse');
const wd = require('../../wearedevs_deobf.js');

function loadDecoded(path) {
  let src = fs.readFileSync(path, 'utf8');
  // Replace the S pool with its DECODED constants so the AST carries real
  // strings, and inline M(idx) later. We keep src as-is for parsing; decoding
  // is applied when we resolve M() constant fetches.
  return src;
}

function parse(src) {
  return luaparse.parse(src, { luaVersion: '5.1', comments: false, ranges: false, locations: false });
}

// Find the interpreter: a FunctionDeclaration whose body contains a WhileStatement
// whose condition is a single Identifier (the state var `g`) and whose body is an
// IfStatement tree comparing that identifier with numeric bounds.
function findDispatcher(ast) {
  let found = null;
  function walk(node) {
    if (!node || typeof node !== 'object') return;
    if (found) return;
    if (node.type === 'WhileStatement' && node.condition && node.condition.type === 'Identifier') {
      const body = node.body || [];
      if (body.length && body[0].type === 'IfStatement') {
        found = { stateVar: node.condition.name, whileNode: node };
        return;
      }
    }
    for (const k in node) {
      const v = node[k];
      if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object' && v.type) walk(v);
    }
  }
  walk(ast);
  return found;
}

// Evaluate a numeric constant expression node (handles a+b, a-(-b), unary minus).
function evalNum(node) {
  if (!node) return null;
  if (node.type === 'NumericLiteral') return node.value;
  if (node.type === 'UnaryExpression' && node.operator === '-') {
    const v = evalNum(node.argument); return v == null ? null : -v;
  }
  if (node.type === 'BinaryExpression') {
    const a = evalNum(node.left), b = evalNum(node.right);
    if (a == null || b == null) return null;
    switch (node.operator) {
      case '+': return a + b;
      case '-': return a - b;
      case '*': return a * b;
      case '/': return a / b;
      case '%': return a % b;
      default: return null;
    }
  }
  return null;
}

// Recursively flatten the if-tree into leaf blocks with their state ranges.
// Each `if <state> < C then A else B end` splits range [lo,hi) at C.
function collectBlocks(stmts, stateVar, lo, hi, out) {
  // A "leaf" is a straight-line block (no top-level `if state < C`).
  if (stmts.length === 1 && stmts[0].type === 'IfStatement' && isStateCompare(stmts[0], stateVar)) {
    const ifn = stmts[0];
    const c = evalNum(ifn.clauses[0].condition.right);
    // then-clause: state < c  -> [lo, c)
    collectBlocks(ifn.clauses[0].body, stateVar, lo, c, out);
    // else-clause
    const elseClause = ifn.clauses.find((cl) => cl.type === 'ElseClause');
    if (elseClause) collectBlocks(elseClause.body, stateVar, c, hi, out);
    return;
  }
  out.push({ lo, hi, stmts });
}

function isStateCompare(ifn, stateVar) {
  const cl = ifn.clauses[0];
  if (!cl || cl.type !== 'IfClause') return false;
  const cond = cl.condition;
  return cond && cond.type === 'BinaryExpression' && cond.operator === '<' &&
    cond.left.type === 'Identifier' && cond.left.name === stateVar &&
    evalNum(cond.right) != null;
}

if (require.main === module) {
  const path = process.argv[2];
  const src = loadDecoded(path);
  const ast = parse(src);
  const disp = findDispatcher(ast);
  if (!disp) { console.log('no dispatcher found'); process.exit(1); }
  console.log('dispatcher state var:', disp.stateVar);
  const out = [];
  collectBlocks(disp.whileNode.body, disp.stateVar, -Infinity, Infinity, out);
  console.log('leaf blocks:', out.length);
  out.slice(0, 5).forEach((b, i) => {
    console.log(`\n#${i} range=[${b.lo}, ${b.hi}) stmts=${b.stmts.length}`);
    console.log('  types:', b.stmts.map((s) => s.type).join(','));
  });
}

module.exports = { parse, findDispatcher, collectBlocks, evalNum };
