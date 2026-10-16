#!/usr/bin/env node
/**
 * Termius data exporter
 *
 * Extracts and decrypts all data from the local Termius IndexedDB (LevelDB) store.
 * Output: termius_hosts.csv, ssh_keys/, snippets.csv
 *
 * Requires: npm install libsodium-wrappers keytar
 */

const sodium = require('libsodium-wrappers');
const keytar = require('keytar');
const fs = require('fs');
const path = require('path');
const os = require('os');
const leveldb = require('./leveldb-read');

const BOM = '﻿';
const OUTPUT_DIR = __dirname;

const LEVELDB_SUBPATH = ['Termius', 'IndexedDB', 'file__0.indexeddb.leveldb'];

function getDbCandidates() {
  const home = os.homedir();
  switch (process.platform) {
    case 'darwin': {
      const sandbox = path.join(home, 'Library', 'Containers', 'com.termius.mac',
        'Data', 'Library', 'Application Support');
      const standard = path.join(home, 'Library', 'Application Support');
      return [
        path.join(sandbox, ...LEVELDB_SUBPATH),
        path.join(standard, ...LEVELDB_SUBPATH),
      ];
    }
    case 'win32': {
      const base = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
      return [path.join(base, ...LEVELDB_SUBPATH)];
    }
    default: {
      const base = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
      return [path.join(base, ...LEVELDB_SUBPATH)];
    }
  }
}

function getDbPath() {
  const candidates = getDbCandidates();
  return candidates.find(p => fs.existsSync(p)) || candidates[0];
}

// ==================== Decryption ====================

const KEY_SERVICES = ['Termius', 'com.termius.mac'];
const KEY_ACCOUNTS = ['localKey', 'TermiusKey', 'key', 'masterKey'];

function parseManualKey(raw) {
  const s = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, 'hex');
  const buf = Buffer.from(s.replace(/\s+/g, ''), 'base64');
  if (buf.length === 32) return buf;
  throw new Error(
    `Provided key does not decode to 32 bytes (got ${buf.length}).` +
    ` Make sure you copied the full base64 value (~44 chars, usually ending with "=").`
  );
}

async function getEncryptionKey() {
  const argKey = process.argv.find(a => a.startsWith('--key='));
  const manual = process.env.TERMIUS_KEY || (argKey && argKey.slice('--key='.length));
  if (manual) {
    console.log('    ✓ Using manually provided key');
    return parseManualKey(manual);
  }

  for (const service of KEY_SERVICES) {
    for (const account of KEY_ACCOUNTS) {
      const v = await keytar.getPassword(service, account);
      if (v) {
        console.log(`    ✓ Found keychain entry: service="${service}" account="${account}"`);
        return Buffer.from(v, 'base64');
      }
    }
  }

  const discovered = [];
  for (const service of KEY_SERVICES) {
    try {
      for (const { account, password } of await keytar.findCredentials(service)) {
        discovered.push(`${service} / ${account}`);
        if (password && /^[A-Za-z0-9+/]{42,}={0,2}$/.test(password)) {
          console.log(`    ✓ Auto-discovered key: service="${service}" account="${account}"`);
          return Buffer.from(password, 'base64');
        }
      }
    } catch {}
  }

  const found = discovered.length
    ? `\nKeychain entries found:\n  - ${discovered.join('\n  - ')}`
    : '\nCould not read keychain (sandboxed Termius keys are ACL-protected).';

  throw new Error(
    'Termius encryption key not found.' + found +
    '\n\nManual key fallback:' +
    '\n  1) Open Keychain Access / Credential Manager, search "Termius"' +
    '\n  2) Copy the password value (~44 char base64)' +
    '\n  3) Re-run:  TERMIUS_KEY=\'<value>\' node termius-exporter.js' +
    '\n     or:     node termius-exporter.js --key=\'<value>\''
  );
}

// Decrypt a single encrypted field value. Termius stores most entities as plaintext
// V8 structured-clone objects, with only the credential fields (password, private_key,
// passphrase, sometimes username) encrypted as base64 `version+options+nonce+ciphertext`
// strings. Returns the cleartext, or the original value if it isn't an encrypted blob.
function decryptField(v, key) {
  if (typeof v !== 'string' || !v) return v == null ? '' : v;
  const d = Buffer.from(v, 'base64');
  if (d.length < 28 || d[0] !== 4) return v;
  try {
    const pt = sodium.crypto_secretbox_open_easy(
      new Uint8Array(d.slice(26)), new Uint8Array(d.slice(2, 26)), new Uint8Array(key));
    return Buffer.from(pt).toString('utf8');
  } catch { return v; }
}

// ==================== Model ====================

// Object-store ids in this Termius IndexedDB:
//   4/9  ssh connection configs (port, identity ref)
//   11   SSH keys (label, private_key, passphrase)
//   12   identities (username, password, ssh_key ref)
//   13   snippets (label, script)
//   16   hosts (address, label, ssh_config ref, group ref, os_name)
//   15   groups (label, parent_group)
const STORE = { SSH_CONFIG: 4, SSH_CONFIG2: 9, KEY: 11, IDENTITY: 12, SNIPPET: 13, HOST: 16, GROUP: 15 };

// Read every current object-store DATA record (index_id == 0), deserialize it (V8
// structured-clone, falling back to whole-record encrypted JSON for the few stores that
// use it), and index by store + local_id + id for relational joins.
async function buildModel(key, debug) {
  const dbPath = getDbPath();
  if (!fs.existsSync(dbPath)) {
    throw new Error(`Termius database not found at: ${dbPath}`);
  }

  const current = leveldb.readCurrentValues(dbPath, { debug });
  console.log(`Found ${current.size} current records (post-tombstone)`);

  const byStore = new Map(); // storeId -> { byLocal, byId, list }
  let objects = 0;
  const completeness = (o) => { let n = 0; for (const v of Object.values(o)) if (v != null && v !== '') n++; return n; };

  // Decrypt an encrypted value blob (raw 0x04-prefixed, or a base64 run inside the
  // value) to its cleartext bytes, or null.
  const openBlob = (val) => {
    let d = null;
    if (val[0] === 4) {
      try { d = Buffer.from(sodium.crypto_secretbox_open_easy(new Uint8Array(val.slice(26)), new Uint8Array(val.slice(2, 26)), new Uint8Array(key))); } catch {}
    }
    if (!d) {
      const runs = val.toString('latin1').match(/[A-Za-z0-9+/]{44,}={0,2}/g) || [];
      for (const r of runs) {
        const b = Buffer.from(r, 'base64');
        if (b[0] !== 4) continue;
        try { d = Buffer.from(sodium.crypto_secretbox_open_easy(new Uint8Array(b.slice(26)), new Uint8Array(b.slice(2, 26)), new Uint8Array(key))); } catch {}
        if (d) break;
      }
    }
    return d;
  };
  // Some entities are stored only as an encrypted sync-blob (no V8 object), with their
  // local_id encoded in the LevelDB key as a number: after the [db][store][index]
  // varints, the user key is `[arrayLen?][0x03][8-byte double LE]`. Probe offsets.
  const localIdFromKey = (kStr) => {
    const kb = Buffer.from(kStr, 'latin1');
    let off = 0;
    for (let i = 0; i < 3; i++) { const v = leveldb.readVarint(kb, off); off = v.next; }
    // IDB number key: a 0x03 tag immediately precedes the 8-byte double LE; a 1-byte
    // array marker may sit before that. Require the tag to avoid garbage matches.
    for (const skip of [2, 1, 3]) {
      if (off + skip + 8 > kb.length) continue;
      if (kb[off + skip - 1] !== 0x03) continue;
      const dv = kb.readDoubleLE(off + skip);
      if (Number.isInteger(dv) && dv > 0 && dv < 1e9) return dv;
    }
    return null;
  };
  const looksEntity = (o) => o && (o.username !== undefined || o.password !== undefined
    || o.private_key !== undefined || o.script !== undefined || o.address !== undefined
    || o.host !== undefined);

  for (const [kStr, val] of current) {
    let p;
    try { p = leveldb.decodeIdbKeyPrefix(Buffer.from(kStr, 'latin1')); }
    catch { continue; }
    // Entities (hosts, identities, keys, snippets, configs) are stored as plaintext
    // V8 structured-clone; a few are stored only as encrypted sync-blobs. Index/string
    // refs don't deserialize to objects and are skipped naturally.
    let o = leveldb.deserializeValue(val);

    if (!o) { // encrypted-blob entity: decrypt value
      const d = openBlob(val);
      if (d) {
        try { o = JSON.parse(d.toString('utf8')); } catch {}
        if (!o) o = leveldb.deserializeValue(d);
        if (!looksEntity(o)) o = null;
      }
    }
    if (!o || typeof o !== 'object' || Array.isArray(o)) continue;

    // The `content` field is an encrypted sync payload. It can carry current values
    // for non-sensitive fields (port, address, label), but for failed-sync entities
    // (status CREATE_FAILED etc.) it reflects a STALE sync and must NOT overwrite the
    // current local credentials/refs — otherwise usernames/passwords end up swapped
    // onto the wrong host. Merge only non-credential, non-ref fields.
    if (typeof o.content === 'string' && o.content) {
      const cd = Buffer.from(o.content, 'base64');
      if (cd.length >= 28 && cd[0] === 4) {
        try {
          const pt = Buffer.from(sodium.crypto_secretbox_open_easy(
            new Uint8Array(cd.slice(26)), new Uint8Array(cd.slice(2, 26)), new Uint8Array(key)));
          let c = null;
          try { c = JSON.parse(pt.toString('utf8')); } catch {}
          if (!c) c = leveldb.deserializeValue(pt);
          if (c && typeof c === 'object' && !Array.isArray(c)) {
            const skip = new Set(['content', 'username', 'password', 'private_key',
              'passphrase', 'public_key', 'ssh_key', 'identity', 'ssh_config',
              'local_id', 'id', 'status']);
            for (const f of Object.keys(c)) if (!skip.has(f)) o[f] = c[f];
          }
        } catch {}
      }
    }

    objects++;
    let idx = byStore.get(p.storeId);
    if (!idx) { idx = { byLocal: new Map(), byKeyLocal: new Map(), byId: new Map(), noLocal: [] }; byStore.set(p.storeId, idx); }
    if (o.local_id != null) {
      // Dedup duplicate records (same local_id — e.g. a data record plus a stale index
      // copy): keep the most complete one so a half-empty copy can't shadow the real
      // host and drop its ssh_config/credentials.
      const prev = idx.byLocal.get(o.local_id);
      if (!prev || completeness(o) > completeness(prev)) idx.byLocal.set(o.local_id, o);
    } else {
      // local_id may be encoded only in the LevelDB key (`.. 0x03 <8-byte double LE>`).
      // Stash these separately so they only FILL gaps — never overwrite a canonical
      // value-local_id record that happens to share the id.
      const kId = localIdFromKey(kStr);
      if (kId != null) {
        const prev = idx.byKeyLocal.get(kId);
        if (!prev || completeness(o) > completeness(prev)) idx.byKeyLocal.set(kId, o);
      } else {
        idx.noLocal.push(o);
      }
    }
    if (o.id != null && !idx.byId.has(o.id)) idx.byId.set(o.id, o);
  }
  for (const idx of byStore.values()) {
    // Some records carry local_id only in the LevelDB key (value.local_id is empty).
    // Fill those into byLocal so refs resolve. Config records (store4) are often in
    // this form and ARE the authoritative ssh_config (store9 is a stale wrapper), so
    // they must be filled — lookup checks store4 before store9.
    for (const [lid, obj] of idx.byKeyLocal) if (!idx.byLocal.has(lid)) idx.byLocal.set(lid, obj);
    idx.list = [...idx.byLocal.values(), ...idx.noLocal];
  }

  if (debug) {
    console.log(`    Deserialized ${objects} entity objects across ${byStore.size} stores:`);
    for (const [sid, idx] of [...byStore.entries()].sort((a, b) => a[0] - b[0])) {
      console.log(`      store${sid}: ${idx.list.length}`);
    }
  }
  return { byStore };
}

// Resolve a {local_id, id} reference to a record in the given store.
function lookup(model, storeId, refObj) {
  if (!refObj || typeof refObj !== 'object') return null;
  const idx = model.byStore.get(storeId);
  if (!idx) return null;
  if (refObj.local_id != null && idx.byLocal.has(refObj.local_id)) return idx.byLocal.get(refObj.local_id);
  if (refObj.id != null && idx.byId.has(refObj.id)) return idx.byId.get(refObj.id);
  return null;
}

// ==================== Export ====================

function escapeCsv(v) {
  v = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
  return `"${v.replace(/"/g, '""')}"`;
}

// host (store16) -> ssh_config (store4/9, port + identity ref) -> identity (store12,
// username + password) and ssh_key (store11, label). Credentials are encrypted sub-fields.
function buildHostRows(model, key) {
  const hosts = (model.byStore.get(STORE.HOST) || { list: [] }).list;
  const rows = [];
  const seen = new Set();
  for (const h of hosts) {
    if (h.address === undefined) continue; // only host records (store16) carry address
    // Termius soft-deletes hosts by marking status "DELETE_FAILED" (cloud delete didn't
    // sync). The record lingers locally and the UI hides it — exclude it so deleted
    // hosts (e.g. stale "v10") don't reappear in the export.
    if (typeof h.status === 'string' && /delete/i.test(h.status)) continue;
    const id = h.local_id != null ? `lid:${h.local_id}`
      : (h.id != null ? `id:${h.id}` : `${h.label}|${h.address}`);
    if (seen.has(id)) continue;
    seen.add(id);

    // ssh_config may resolve to a store4 record (port + identity directly) OR a store9
    // wrapper whose `ssh_config` ref points to the real store4 config. store9.identity
    // is a denormalized copy that can be stale / cross-referenced; the inner store4
    // identity is self-consistent, so prefer it for both port and identity.
    const cfg = lookup(model, STORE.SSH_CONFIG, h.ssh_config)
      || lookup(model, STORE.SSH_CONFIG2, h.ssh_config);
    let inner = null;
    if (cfg && cfg.ssh_config && typeof cfg.ssh_config === 'object') {
      inner = lookup(model, STORE.SSH_CONFIG, cfg.ssh_config);
    }
    const portCfg = inner || cfg;
    let port = portCfg && portCfg.port;
    if (port && typeof port === 'object') port = port.value ?? port.number ?? null;
    if (typeof port !== 'number' || !port) port = 22;

    const identRef = (inner && inner.identity) || (cfg && cfg.identity);
    const ident = lookup(model, STORE.IDENTITY, identRef);
    const username = ident ? decryptField(ident.username, key) : '';
    const password = ident ? decryptField(ident.password, key) : '';

    let keyName = '';
    const keyObj = lookup(model, STORE.KEY, ident && ident.ssh_key);
    if (keyObj) keyName = decryptField(keyObj.label, key) || keyObj.label || '';

    // Resolve the host's group chain: host.group -> store15 group -> parent_group -> ...
    // Build a "parent/child" path so nested groups survive import.
    let groupPath = '';
    if (h.group && typeof h.group === 'object') {
      const parts = [];
      let ref = h.group;
      const visited = new Set();
      while (ref && typeof ref === 'object') {
        const refKey = ref.local_id != null ? ref.local_id : ref.id;
        if (refKey == null || visited.has(refKey)) break;
        visited.add(refKey);
        const g = lookup(model, STORE.GROUP, ref);
        if (!g) break;
        const lbl = decryptField(g.label, key) || g.label || '';
        if (lbl) parts.unshift(lbl);
        ref = (g.parent_group && typeof g.parent_group === 'object') ? g.parent_group : null;
      }
      groupPath = parts.join('/');
    }

    rows.push({
      label: decryptField(h.label, key) || h.label || '',
      host: decryptField(h.address, key) || h.address || '',
      port,
      username,
      password,
      keyName,
      os: decryptField(h.os_name, key) || h.os_name || '',
      group: groupPath,
    });
  }
  return rows;
}

function exportHostsCsv(rows) {
  let csv = 'Label,Host,Port,Username,Password,SSH_Key,OS,Group\n';
  rows.forEach(h => {
    csv += [h.label, h.host, h.port, h.username, h.password, h.keyName, h.os, h.group].map(escapeCsv).join(',') + '\n';
  });
  fs.writeFileSync(path.join(OUTPUT_DIR, 'termius_hosts.csv'), BOM + csv);
  return rows.length;
}

function exportSshKeys(model, key) {
  const keys = (model.byStore.get(STORE.KEY) || { list: [] }).list;
  const keysDir = path.join(OUTPUT_DIR, 'ssh_keys');
  if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { mode: 0o700 });

  let count = 0;
  keys.forEach((k, i) => {
    if (typeof k.status === 'string' && /delete/i.test(k.status)) return;
    const pk = decryptField(k.private_key, key);
    if (!pk) return;
    const label = decryptField(k.label, key) || k.label || `key_${i}`;
    const safeName = String(label).replace(/[<>:"/\\|?*]/g, '_');

    let content = pk;
    if (!content.endsWith('\n')) content += '\n';
    fs.writeFileSync(path.join(keysDir, `${safeName}.pem`), content, { mode: 0o600 });

    const pp = decryptField(k.passphrase, key);
    if (pp) fs.writeFileSync(path.join(keysDir, `${safeName}.passphrase`), pp, { mode: 0o600 });
    count++;
  });
  return count;
}

function exportSnippets(model, key) {
  const snippets = (model.byStore.get(STORE.SNIPPET) || { list: [] }).list;
  let csv = 'Label,Script\n';
  snippets.forEach(s => {
    if (s.script === undefined) return; // only snippet records carry a script
    if (typeof s.status === 'string' && /delete/i.test(s.status)) return;
    const label = decryptField(s.label, key) || s.label || '';
    const script = decryptField(s.script, key) || '';
    csv += [label, script].map(escapeCsv).join(',') + '\n';
  });
  fs.writeFileSync(path.join(OUTPUT_DIR, 'snippets.csv'), BOM + csv);
  return snippets.length;
}

// ==================== Main ====================

async function main() {
  console.log('=== Termius Data Exporter ===\n');

  await sodium.ready;

  console.log('[1/4] Retrieving encryption key...');
  const key = await getEncryptionKey();
  console.log('    ✓ Key retrieved\n');

  const debug = process.argv.includes('--debug');

  console.log('[2/4] Decrypting database...');
  const model = await buildModel(key, debug);
  console.log('');

  console.log('[3/4] Building host list...');
  const rows = buildHostRows(model, key);
  const keysCount = (model.byStore.get(STORE.KEY) || { list: [] }).list.length;
  const snippetsCount = (model.byStore.get(STORE.SNIPPET) || { list: [] }).list.length;
  console.log(`    ✓ Hosts:     ${rows.length}`);
  console.log(`    ✓ SSH keys:  ${keysCount}`);
  console.log(`    ✓ Snippets:  ${snippetsCount}\n`);
  if (debug) {
    const w = (f) => rows.filter(r => r[f]).length;
    console.log(`    join coverage: ${w('username')}/${rows.length} username, ${w('password')}/${rows.length} password, ${w('keyName')}/${rows.length} key, ${rows.filter(r => r.port !== 22).length} non-22 port\n`);
  }

  console.log('[4/4] Exporting...');
  const hostsCount = exportHostsCsv(rows);
  const exportedKeys = exportSshKeys(model, key);
  const exportedSnippets = exportSnippets(model, key);

  console.log(`    ✓ termius_hosts.csv (${hostsCount} hosts)`);
  console.log(`    ✓ ssh_keys/ (${exportedKeys} keys)`);
  console.log(`    ✓ snippets.csv (${exportedSnippets} snippets)\n`);

  console.log('=== Export complete ===');
  console.log(`Output: ${OUTPUT_DIR}`);
}

if (require.main === module) {
  main().catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
  });
}

module.exports = { buildModel, lookup, decryptField, buildHostRows, exportHostsCsv, exportSshKeys, exportSnippets, STORE };
