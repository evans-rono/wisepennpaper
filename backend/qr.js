// Minimal QR encoder: byte mode, error-correction level M, versions 1-10.
//
// That is enough for the otpauth:// URI on the two-factor setup screen, and
// small enough to own outright. The alternative was a dependency tree of 29
// packages — including a command-line argument parser — to draw one square.
//
// Verified module-for-module against the `qrcode` package before that package
// was removed; see the test suite.

/* ------------------------------------------------------- GF(2^8) arithmetic */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d; // the QR field polynomial
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}
const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

// Generator polynomial for `degree` error-correction codewords: ∏ (x + α^i).
function generatorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= mul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function errorCorrection(data, count) {
  const poly = generatorPoly(count);
  const rem = new Uint8Array(data.length + count);
  rem.set(data);
  for (let i = 0; i < data.length; i++) {
    const factor = rem[i];
    if (!factor) continue;
    for (let j = 0; j < poly.length; j++) rem[i + j] ^= mul(poly[j], factor);
  }
  return Array.from(rem.subarray(data.length));
}

/* ------------------------------------------------------------ version data */

// [total codewords, EC codewords per block, [block count, data codewords]...]
// for error-correction level M.
const VERSIONS = [
  null,
  { total: 26, ecPerBlock: 10, groups: [[1, 16]] },
  { total: 44, ecPerBlock: 16, groups: [[1, 28]] },
  { total: 70, ecPerBlock: 26, groups: [[1, 44]] },
  { total: 100, ecPerBlock: 18, groups: [[2, 32]] },
  { total: 134, ecPerBlock: 24, groups: [[2, 43]] },
  { total: 172, ecPerBlock: 16, groups: [[4, 27]] },
  { total: 196, ecPerBlock: 18, groups: [[4, 31]] },
  { total: 242, ecPerBlock: 22, groups: [[2, 38], [2, 39]] },
  { total: 292, ecPerBlock: 22, groups: [[3, 36], [2, 37]] },
  { total: 346, ecPerBlock: 26, groups: [[4, 43], [1, 44]] },
];

const ALIGNMENT = [
  null, [], [6, 18], [6, 22], [6, 26], [6, 30],
  [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];

const dataCodewords = (v) =>
  VERSIONS[v].groups.reduce((n, [blocks, words]) => n + blocks * words, 0);

// The character-count indicator is 8 bits up to version 9 and 16 bits after.
const countBits = (v) => (v < 10 ? 8 : 16);

const capacity = (v) => Math.floor((dataCodewords(v) * 8 - 4 - countBits(v)) / 8);

function pickVersion(byteLength) {
  for (let v = 1; v < VERSIONS.length; v++) if (capacity(v) >= byteLength) return v;
  throw new Error(`Content is too long for this encoder (${byteLength} bytes, max ${capacity(10)}).`);
}

/* ------------------------------------------------------------- bit stream */

function buildCodewords(bytes, version) {
  const bits = [];
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >> i) & 1);
  };

  push(0b0100, 4); // byte mode
  push(bytes.length, countBits(version));
  for (const b of bytes) push(b, 8);

  const capacityBits = dataCodewords(version) * 8;
  push(0, Math.min(4, capacityBits - bits.length)); // terminator
  while (bits.length % 8) bits.push(0);

  const words = [];
  for (let i = 0; i < bits.length; i += 8) {
    words.push(bits.slice(i, i + 8).reduce((n, b) => (n << 1) | b, 0));
  }
  // Alternating pad bytes until the capacity is filled.
  for (let i = 0; words.length < dataCodewords(version); i++) words.push(i % 2 === 0 ? 0xec : 0x11);
  return words;
}

// Data and error-correction codewords are interleaved across blocks.
function interleave(words, version) {
  const { ecPerBlock, groups } = VERSIONS[version];
  const blocks = [];
  let offset = 0;
  for (const [count, size] of groups) {
    for (let i = 0; i < count; i++) {
      const data = words.slice(offset, offset + size);
      offset += size;
      blocks.push({ data, ec: errorCorrection(data, ecPerBlock) });
    }
  }

  const out = [];
  const longest = Math.max(...blocks.map((b) => b.data.length));
  for (let i = 0; i < longest; i++) {
    for (const b of blocks) if (i < b.data.length) out.push(b.data[i]);
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const b of blocks) out.push(b.ec[i]);
  }
  return out;
}

/* --------------------------------------------------------- module placement */

const bch = (value, generator, bitLength) => {
  let v = value << bitLength;
  const genBits = 32 - Math.clz32(generator);
  while (32 - Math.clz32(v) >= genBits) v ^= generator << (32 - Math.clz32(v) - genBits);
  return (value << bitLength) | v;
};

function emptyMatrix(size) {
  return {
    modules: Array.from({ length: size }, () => new Array(size).fill(0)),
    reserved: Array.from({ length: size }, () => new Array(size).fill(false)),
    size,
  };
}

function placeFunctionPatterns(m, version) {
  const { size } = m;
  const set = (r, c, dark) => {
    if (r < 0 || c < 0 || r >= size || c >= size) return;
    m.modules[r][c] = dark ? 1 : 0;
    m.reserved[r][c] = true;
  };

  // Finder patterns with their separators.
  for (const [top, left] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const inner = r >= 0 && r <= 6 && c >= 0 && c <= 6;
        const ring = r === 0 || r === 6 || c === 0 || c === 6;
        const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        set(top + r, left + c, inner && (ring || core));
      }
    }
  }

  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }

  // Alignment patterns, skipping the three finder corners.
  const centres = ALIGNMENT[version];
  for (const r of centres) {
    for (const c of centres) {
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  set(size - 8, 8, true); // the always-dark module

  // Reserve the format-information areas.
  for (let i = 0; i < 9; i++) {
    if (!m.reserved[8][i]) set(8, i, false);
    if (!m.reserved[i][8]) set(i, 8, false);
  }
  for (let i = 0; i < 8; i++) {
    if (!m.reserved[8][size - 1 - i]) set(8, size - 1 - i, false);
    if (!m.reserved[size - 1 - i][8]) set(size - 1 - i, 8, false);
  }

  // Version information for version 7 and above.
  if (version >= 7) {
    const info = bch(version, 0x1f25, 12);
    for (let i = 0; i < 18; i++) {
      const bit = (info >> i) & 1;
      set(Math.floor(i / 3), size - 11 + (i % 3), bit);
      set(size - 11 + (i % 3), Math.floor(i / 3), bit);
    }
  }
}

function placeData(m, codewords) {
  const { size } = m;
  const bits = [];
  for (const w of codewords) for (let i = 7; i >= 0; i--) bits.push((w >> i) & 1);

  let index = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // the vertical timing column is skipped
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step;
      for (const col of [right, right - 1]) {
        if (m.reserved[row][col]) continue;
        m.modules[row][col] = index < bits.length ? bits[index] : 0;
        index++;
      }
    }
    upward = !upward;
  }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function penalty(modules) {
  const size = modules.length;
  let score = 0;

  // Rule 1: runs of five or more identical modules in a row or column.
  for (const transposed of [false, true]) {
    for (let a = 0; a < size; a++) {
      let run = 1;
      for (let b = 1; b < size; b++) {
        const prev = transposed ? modules[b - 1][a] : modules[a][b - 1];
        const cur = transposed ? modules[b][a] : modules[a][b];
        if (cur === prev) {
          run++;
          if (run === 5) score += 3;
          else if (run > 5) score++;
        } else run = 1;
      }
    }
  }

  // Rule 2: 2x2 blocks of one colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = modules[r][c];
      if (v === modules[r][c + 1] && v === modules[r + 1][c] && v === modules[r + 1][c + 1]) score += 3;
    }
  }

  // Rule 3: finder-like 1:1:3:1:1 patterns.
  const A = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const B = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  const matches = (get, start) =>
    A.every((_, i) => get(start + i) === A[i]) || B.every((_, i) => get(start + i) === B[i]);
  for (let a = 0; a < size; a++) {
    for (let b = 0; b + 11 <= size; b++) {
      if (matches((i) => modules[a][i], b)) score += 40;
      if (matches((i) => modules[i][a], b)) score += 40;
    }
  }

  // Rule 4: deviation from an even balance of dark and light, in steps of 5%.
  // This is the rounding the reference implementation uses. Mask choice is a
  // readability heuristic rather than a decoding requirement -- any mask yields
  // a valid symbol -- and matching it exactly is what lets the whole encoder be
  // checked module-for-module against a known-good implementation.
  const dark = modules.flat().reduce((n, v) => n + v, 0);
  score += Math.abs(Math.ceil(((dark * 100) / (size * size)) / 5) - 10) * 10;
  return score;
}

function applyFormat(m, mask) {
  const { size } = m;
  // 00 is error-correction level M; the result is masked with 0x5412.
  const info = bch((0b00 << 3) | mask, 0x537, 10) ^ 0x5412;
  // The 15 bits are laid down most-significant first.
  const bit = (i) => (info >> (14 - i)) & 1;

  // Copy 1, wrapped around the top-left finder. Column 6 is the timing
  // pattern, which is why bit 6 skips from (8,5) to (8,7).
  for (let i = 0; i <= 5; i++) m.modules[8][i] = bit(i);
  m.modules[8][7] = bit(6);
  m.modules[8][8] = bit(7);
  m.modules[7][8] = bit(8);
  for (let i = 9; i <= 14; i++) m.modules[14 - i][8] = bit(i);

  // Copy 2: seven modules up the bottom-left column, then eight along the
  // top-right row. The always-dark module sits just above that column run and
  // is not part of the format, so the vertical loop stops at bit 6.
  for (let i = 0; i <= 6; i++) m.modules[size - 1 - i][8] = bit(i);
  for (let i = 7; i <= 14; i++) m.modules[8][size - 15 + i] = bit(i);
  m.modules[size - 8][8] = 1;
}

/**
 * Encodes `text` and returns a square matrix of 0/1 modules.
 * `forceMask` exists so the test suite can compare a single mask at a time.
 */
export function encode(text, { forceMask = null } = {}) {
  const bytes = Array.from(Buffer.from(String(text), 'utf8'));
  const version = pickVersion(bytes.length);
  const codewords = interleave(buildCodewords(bytes, version), version);

  let best = null;
  const masks = forceMask === null ? [0, 1, 2, 3, 4, 5, 6, 7] : [forceMask];
  for (const mask of masks) {
    const m = emptyMatrix(17 + 4 * version);
    placeFunctionPatterns(m, version);
    placeData(m, codewords);
    for (let r = 0; r < m.size; r++) {
      for (let c = 0; c < m.size; c++) {
        if (!m.reserved[r][c] && MASKS[mask](r, c)) m.modules[r][c] ^= 1;
      }
    }
    applyFormat(m, mask);
    const score = penalty(m.modules);
    if (!best || score < best.score) best = { score, modules: m.modules };
  }
  return best.modules;
}

/** Renders `text` as a standalone SVG string. */
export function toSvg(text, { margin = 2, scale = 1 } = {}) {
  const modules = encode(text);
  const size = modules.length + margin * 2;
  let path = '';
  for (let r = 0; r < modules.length; r++) {
    for (let c = 0; c < modules.length; c++) {
      if (modules[r][c]) path += `M${c + margin} ${r + margin}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size * scale}" height="${size * scale}" shape-rendering="crispEdges" role="img">`
    + `<rect width="${size}" height="${size}" fill="#ffffff"/>`
    + `<path d="${path}" fill="#000000"/></svg>`;
}
