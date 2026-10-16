/**
 * Minimal, self-contained LevelDB reader for Chromium IndexedDB backing files.
 *
 * Chromium's IndexedDB is backed by LevelDB but uses the custom `idb_cmp1` key
 * comparator, so standard libs (`leveldown`/`level`) refuse to open it. This
 * module reads the on-disk files directly — no DB open, no comparator — and
 * returns the CURRENT key→value map after applying delete tombstones.
 *
 * It handles:
 *   - `.log` (WAL): 32KB-block record format → WriteBatch put/delete entries.
 *   - `.ldb` (SSTable): footer → index block → Snappy-decompressed data blocks.
 *
 * No external dependencies; Snappy raw/block decode is vendored below.
 *
 * Output values are the raw IndexedDB value bytes (Blink SerializedScriptValue),
 * which embed the encrypted base64 blob as a substring — the caller extracts it.
 */

const fs = require('fs');
const path = require('path');

// ==================== Primitives ====================

// Little-endian base-128 varint (works for varint32 and varint64 up to 2^53).
// Returns { value:Number, next:offset-after }.
function readVarint(buf, off) {
  let result = 0;
  let shift = 0;
  let p = off;
  for (;;) {
    const b = buf[p++];
    result += (b & 0x7f) * Math.pow(2, shift);
    if (!(b & 0x80)) break;
    shift += 7;
    if (shift > 70) break; // safety: malformed
  }
  return { value: result, next: p };
}

// A BlockHandle is two varint64s: offset, size.
function readBlockHandle(buf, off) {
  const a = readVarint(buf, off);
  const b = readVarint(buf, a.next);
  return { offset: a.value, size: b.value, next: b.next };
}

// ==================== Snappy (raw/block format) ====================

// Copies a back-reference of `len` bytes starting `offset` bytes before `outOff`.
// May overlap, so copy byte-by-byte.
function snappyCopyBack(out, outOff, len, offset) {
  if (offset <= 0) throw new Error('snappy: invalid back-reference offset');
  const src = outOff - offset;
  if (src < 0) throw new Error('snappy: back-reference before output start');
  for (let i = 0; i < len; i++) out[outOff + i] = out[src + i];
}

// Decompress a Snappy raw/block buffer (the format LevelDB stores in compressed blocks).
function snappyDecompress(input) {
  let p = 0;
  // Leading varint = uncompressed length.
  let len = 0;
  let shift = 0;
  for (;;) {
    const b = input[p++];
    len += (b & 0x7f) * Math.pow(2, shift);
    if (!(b & 0x80)) break;
    shift += 7;
  }
  const out = Buffer.alloc(len);
  let o = 0;
  const n = input.length;
  while (p < n) {
    const tag = input[p++];
    const type = tag & 3;
    if (type === 0) {
      // Literal: 1..60 from tag, or 61..64 via 1..4 extra LE bytes.
      let litLen = (tag >> 2) + 1;
      if (litLen > 60) {
        const extra = litLen - 60; // 1..4
        let l = 0;
        for (let i = 0; i < extra; i++) l |= input[p++] << (8 * i);
        litLen = l + 1;
      }
      input.copy(out, o, p, p + litLen);
      p += litLen;
      o += litLen;
    } else if (type === 1) {
      // Copy with 1-byte offset: length 4..11, offset = top3(tag)<<8 | next.
      const cLen = 4 + ((tag >> 2) & 7);
      const offset = ((tag >> 5) << 8) | input[p++];
      snappyCopyBack(out, o, cLen, offset);
      o += cLen;
    } else if (type === 2) {
      // Copy with 2-byte offset: length = (tag>>2)+1, offset = LE2.
      const cLen = (tag >> 2) + 1;
      const offset = input[p] | (input[p + 1] << 8);
      p += 2;
      snappyCopyBack(out, o, cLen, offset);
      o += cLen;
    } else {
      // Copy with 4-byte offset: length = (tag>>2)+1, offset = LE4.
      const cLen = (tag >> 2) + 1;
      const offset =
        input[p] | (input[p + 1] << 8) | (input[p + 2] << 16) | (input[p + 3] << 24);
      p += 4;
      snappyCopyBack(out, o, cLen, offset);
      o += cLen;
    }
  }
  return out;
}

// ==================== SSTable (.ldb) ====================

// Locate the SSTable footer WITHOUT depending on the magic constant — Chromium's
// leveldb uses a different magic than upstream Google leveldb (verified on-disk:
// 57 fb 80 8b 24 75 47 db, not upstream's 21 ea 8f 92 24 7f 47 db). The footer is
// the last ~48 bytes; the index/metaindex blocks are written immediately before it,
// so one of them satisfies:  block.offset + block.size + 5(trailer) === footerStart.
// Use that invariant to validate candidate footer offsets, magic-free.
function findFooter(buf) {
  const tryAt = (fs) => {
    if (fs < 0 || fs + 20 > buf.length) return null;
    let meta, index;
    try {
      meta = readBlockHandle(buf, fs);
      index = readBlockHandle(buf, meta.next);
    } catch { return null; }
    if (!(index.size > 0 && index.offset + index.size + 5 <= buf.length)) return null;
    if (meta.offset + meta.size + 5 === fs || index.offset + index.size + 5 === fs) {
      return { footerStart: fs, index, tailMagic: buf.slice(buf.length - 8) };
    }
    return null;
  };
  for (const cand of [buf.length - 48, buf.length - 53, buf.length - 40]) {
    const r = tryAt(cand);
    if (r) return r;
  }
  for (let fs = Math.max(0, buf.length - 256); fs <= buf.length - 20; fs++) {
    const r = tryAt(fs);
    if (r) return r;
  }
  throw new Error('SSTable footer not located (no block ends at footer boundary)');
}

// Read a block pointed to by a handle: content[size] + 5-byte trailer (type[1] + crc[4]).
// type 0 = uncompressed, 1 = Snappy. size excludes the trailer.
function readBlock(buf, handle) {
  const start = handle.offset;
  const end = start + handle.size;
  if (end + 5 > buf.length) {
    // Truncated trailer — treat as uncompressed content if it at least fits.
    if (end > buf.length) return Buffer.alloc(0);
    return buf.slice(start, end);
  }
  const type = buf[end];
  let content = buf.slice(start, end);
  if (type === 1) {
    try {
      content = snappyDecompress(content);
    } catch (e) {
      // Leave compressed content; parseDataBlock will simply yield nothing.
    }
  }
  return content;
}

// Parse a (decompressed) data/index block into [ { key:Buffer, value:Buffer } ].
// Layout: entries, then restart array (numRestarts × uint32 LE), then numRestarts (uint32 LE).
function parseDataBlock(content) {
  const out = [];
  if (!content || content.length < 4) return out;
  const numRestarts = content.readUInt32LE(content.length - 4);
  const restartStart = content.length - 4 - 4 * numRestarts;
  if (restartStart < 0 || restartStart > content.length) return out;

  let off = 0;
  let prevKey = Buffer.alloc(0);
  while (off < restartStart) {
    const shared = readVarint(content, off); off = shared.next;
    const nonShared = readVarint(content, off); off = nonShared.next;
    const vlen = readVarint(content, off); off = vlen.next;
    if (off + nonShared.value + vlen.value > restartStart) break; // truncated entry
    const keyBytes = content.slice(off, off + nonShared.value); off += nonShared.value;
    const value = content.slice(off, off + vlen.value); off += vlen.value;
    const key = Buffer.concat([prevKey.slice(0, shared.value), keyBytes]);
    prevKey = key;
    out.push({ key, value });
  }
  return out;
}

// Parse an SSTable into a Map<binaryKeyString, valueBuffer>. Later entries win (L0 dedup).
function parseSst(buf) {
  const { footerStart, index, tailMagic } = findFooter(buf);
  if (index.offset + index.size + 5 > buf.length) {
    throw new Error('SSTable index handle out of range');
  }
  const indexBlock = readBlock(buf, index);
  const indexEntries = parseDataBlock(indexBlock);

  const map = new Map();
  let numDataBlocks = 0;
  let blockErrors = 0;
  for (const { value } of indexEntries) {
    const dh = readBlockHandle(value, 0);
    let dataBlock;
    try {
      dataBlock = readBlock(buf, dh);
    } catch {
      blockErrors++;
      continue;
    }
    let entries;
    try {
      entries = parseDataBlock(dataBlock);
    } catch {
      blockErrors++;
      continue;
    }
    for (const { key, value: val } of entries) map.set(key.toString('latin1'), val);
    numDataBlocks++;
  }
  return { map, numDataBlocks, blockErrors, footerStart, tailMagic };
}

// ==================== WAL (.log) ====================

const LOG_BLOCK_SIZE = 32768;
const LOG_HEADER = 7;
const REC_FULL = 1, REC_FIRST = 2, REC_MIDDLE = 3, REC_LAST = 4;

// leveldb ValueType: 1 = Value (Put), 0 = Deletion.
const TYPE_VALUE = 1, TYPE_DELETION = 0;

function parseWriteBatch(rec) {
  const out = [];
  if (rec.length < 12) return out;
  const count = rec.readUInt32LE(8); // sequence[8] + count[4]
  let off = 12;
  for (let i = 0; i < count; i++) {
    if (off >= rec.length) break;
    const t = rec[off++];
    const kv = readVarint(rec, off); off = kv.next;
    if (off + kv.value > rec.length) break;
    const key = rec.slice(off, off + kv.value); off += kv.value;
    if (t === TYPE_VALUE) {
      const vv = readVarint(rec, off); off = vv.next;
      if (off + vv.value > rec.length) break;
      const value = rec.slice(off, off + vv.value); off += vv.value;
      out.push({ type: 'put', key, value });
    } else if (t === TYPE_DELETION) {
      out.push({ type: 'del', key });
    } else {
      break; // unknown entry type — stop this batch to avoid mis-parsing
    }
  }
  return out;
}

// Parse the WAL into an ordered list of { type, key, value? } entries.
function parseLog(buf) {
  const entries = [];
  let pending = null;
  let batches = 0;
  const len = buf.length;
  let blockOff = 0;
  while (blockOff < len) {
    const blockEnd = Math.min(blockOff + LOG_BLOCK_SIZE, len);
    let off = blockOff;
    while (off + LOG_HEADER <= blockEnd) {
      const rlen = buf.readUInt16LE(off + 4);
      const rtype = buf.readUInt8(off + 6);
      if (rtype === 0) break; // kZeroType → end-of-block padding; advance to next block
      const dataStart = off + LOG_HEADER;
      if (dataStart + rlen > blockEnd) break; // truncated record at EOF
      const data = buf.slice(dataStart, dataStart + rlen);
      off = dataStart + rlen;
      if (rtype === REC_FULL) {
        entries.push(...parseWriteBatch(data)); batches++;
      } else if (rtype === REC_FIRST) {
        pending = [data];
      } else if (rtype === REC_MIDDLE) {
        if (pending) pending.push(data);
      } else if (rtype === REC_LAST) {
        if (pending) { pending.push(data); entries.push(...parseWriteBatch(Buffer.concat(pending))); batches++; pending = null; }
      }
    }
    blockOff += LOG_BLOCK_SIZE;
  }
  return { entries, batches };
}

// ==================== V8 structured-clone value ====================

// Termius stores most entities (hosts, identities, keys, configs) as Blink
// SerializedScriptValue, which wraps a V8 ValueSerializer stream behind a small
// header. v8.deserialize() reads the stream once the header is skipped. Try a few
// offsets and return the first that yields a non-empty object.
const V8_OFFSETS = [5, 4, 3, 6, 2, 7, 0, 1];
function deserializeValue(buf) {
  for (const off of V8_OFFSETS) {
    if (buf.length <= off + 4) continue;
    try {
      const o = require('v8').deserialize(buf.slice(off));
      if (o && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).length > 0) return o;
    } catch {}
  }
  return null;
}

// ==================== IndexedDB key prefix ====================

// Chromium IndexedDB object-store record keys are prefixed with:
//   [database_id varint][object_store_id varint][index_id varint][user_key...]
// index_id == 0 for the store's own data records; non-zero = a secondary-index entry.
function decodeIdbKeyPrefix(keyBuf) {
  const db = readVarint(keyBuf, 0);
  const store = readVarint(keyBuf, db.next);
  const index = readVarint(keyBuf, store.next);
  return { dbId: db.value, storeId: store.value, indexId: index.value };
}

// ==================== Compose current state ====================

function fileNumber(name) {
  const m = name.match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : 0;
}

/**
 * Read all `.ldb` + `.log` files in dbPath and return the CURRENT key→value map
 * (SSTables as the base snapshot, then the WAL applied in order, honoring deletes).
 * @returns {Map<string, Buffer>} binary-key-string → value bytes
 */
function readCurrentValues(dbPath, { debug = false } = {}) {
  const names = fs.readdirSync(dbPath);
  const logs = names.filter(f => f.endsWith('.log')).sort((a, b) => fileNumber(a) - fileNumber(b));
  const ssts = names.filter(f => f.endsWith('.ldb')).sort((a, b) => fileNumber(a) - fileNumber(b));

  if (!logs.length && !ssts.length) {
    throw new Error(`No .log/.ldb files found in ${dbPath}`);
  }

  const current = new Map(); // latin1 key string → value Buffer
  let sstKeyOps = 0, sstBlocks = 0, sstBlockErrors = 0;

  for (const f of ssts) {
    const buf = fs.readFileSync(path.join(dbPath, f));
    const { map, numDataBlocks, blockErrors, footerStart, tailMagic } = parseSst(buf);
    sstBlocks += numDataBlocks;
    sstBlockErrors += blockErrors;
    for (const [k, v] of map) { current.set(k, v); sstKeyOps++; }
    if (debug) {
      console.log(`    [sst ${f}] footer@${footerStart} dataBlocks=${numDataBlocks} (errors=${blockErrors}) keys=${map.size} magic=${tailMagic.toString('hex')}`);
    }
  }

  let puts = 0, dels = 0, logBatches = 0;
  for (const f of logs) {
    const buf = fs.readFileSync(path.join(dbPath, f));
    const { entries, batches } = parseLog(buf);
    logBatches += batches;
    for (const e of entries) {
      const k = e.key.toString('latin1');
      if (e.type === 'put') { current.set(k, e.value); puts++; }
      else if (e.type === 'del') { current.delete(k); dels++; }
    }
    if (debug) console.log(`    [log ${f}] batches=${batches} puts/dels applied in order`);
  }

  if (debug) {
    console.log(`    SST: ${ssts.length} file(s), ${sstBlocks} data blocks (${sstBlockErrors} bad), ${sstKeyOps} key-set ops`);
    console.log(`    LOG: ${logs.length} file(s), ${logBatches} batches, ${puts} puts, ${dels} deletes`);
    console.log(`    Current records: ${current.size}`);
    const dist = new Map();
    for (const k of current.keys()) {
      let p;
      try { p = decodeIdbKeyPrefix(Buffer.from(k, 'latin1')); } catch { p = null; }
      const sid = p ? `db${p.dbId}/store${p.storeId}/idx${p.indexId}` : 'unparsed';
      dist.set(sid, (dist.get(sid) || 0) + 1);
    }
    console.log('    Key-prefix distribution (top 20, counts only):');
    for (const [sid, n] of [...dist.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)) {
      console.log(`      ${sid}: ${n}`);
    }
  }
  return current;
}

module.exports = {
  readCurrentValues,
  readVarint,
  snappyDecompress,
  parseDataBlock,
  decodeIdbKeyPrefix,
  deserializeValue,
};
