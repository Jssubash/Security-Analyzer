/**
 * `docs/security.md` §8 test 1 — the BSON reader.
 *
 * Every element tag is round-tripped, and every way a document can be malformed must produce a
 * `BsonParseError` rather than a partial tree. That distinction is the whole point: a reader that
 * returns what it managed to read before the corruption hands the extractors a model that is
 * missing access rules, and a missing access rule is indistinguishable downstream from an entity
 * that has none. The tree is also cross-validated against `./mxcli bson dump`, which is used here
 * purely as an oracle — nothing at runtime depends on it.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { BsonParseError, parseBsonDocument, parseBsonHeader } from '@mendix-analyzer/mendix-parser';

import { FIXTURE_MPR, REPO_ROOT, describeFixture } from './helpers/fixture.mjs';

// --- a minimal independent encoder, so the tests do not verify the reader against itself ----

function cstring(s) {
  return Buffer.concat([Buffer.from(s, 'utf8'), Buffer.from([0])]);
}

function element(tag, key, body) {
  return Buffer.concat([Buffer.from([tag]), cstring(key), body]);
}

function document(elements) {
  const body = Buffer.concat(elements);
  const length = Buffer.alloc(4);
  length.writeInt32LE(body.length + 5, 0);
  return Buffer.concat([length, body, Buffer.from([0])]);
}

function int32(n) {
  const b = Buffer.alloc(4);
  b.writeInt32LE(n, 0);
  return b;
}

function int64(n) {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt(n), 0);
  return b;
}

function double(n) {
  const b = Buffer.alloc(8);
  b.writeDoubleLE(n, 0);
  return b;
}

function bsonString(s) {
  const bytes = Buffer.from(s, 'utf8');
  return Buffer.concat([int32(bytes.length + 1), bytes, Buffer.from([0])]);
}

function binary(bytes, subtype = 0) {
  return Buffer.concat([int32(bytes.length), Buffer.from([subtype]), Buffer.from(bytes)]);
}

describe('BSON reader: element tags', () => {
  it('round-trips every tag the Mendix units use', () => {
    const guid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const buf = document([
      element(0x01, 'aDouble', double(1.5)),
      element(0x02, 'aString', bsonString('hello')),
      element(0x03, 'aDocument', document([element(0x10, 'inner', int32(7))])),
      element(0x05, 'aBinary', binary(guid)),
      element(0x06, 'anUndefined', Buffer.alloc(0)),
      element(0x07, 'anObjectId', Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])),
      element(0x08, 'aTrue', Buffer.from([1])),
      element(0x08, 'aFalse', Buffer.from([0])),
      element(0x09, 'aDateTime', int64(1_700_000_000_000)),
      element(0x0a, 'aNull', Buffer.alloc(0)),
      element(0x0b, 'aRegex', Buffer.concat([cstring('ab+c'), cstring('i')])),
      element(0x10, 'anInt32', int32(-42)),
      element(0x11, 'aTimestamp', int64(99)),
      element(0x12, 'anInt64', int64(123)),
    ]);

    const doc = parseBsonDocument(buf);

    assert.equal(doc.aDouble, 1.5);
    assert.equal(doc.aString, 'hello');
    assert.deepEqual(doc.aDocument, { inner: 7 });
    assert.ok(doc.aBinary instanceof Uint8Array);
    assert.deepEqual([...doc.aBinary], guid);
    assert.equal(doc.anUndefined, null);
    assert.equal(doc.anObjectId.length, 12);
    assert.equal(doc.aTrue, true);
    assert.equal(doc.aFalse, false);
    assert.equal(doc.aDateTime, 1_700_000_000_000n);
    assert.equal(doc.aNull, null);
    assert.equal(doc.aRegex, '/ab+c/i');
    assert.equal(doc.anInt32, -42);
    assert.equal(doc.aTimestamp, 99n);
    // int64 narrows to number when it is lossless, so a TabIndex reads as 123, not 123n.
    assert.equal(doc.anInt64, 123);
  });

  it('drops the int32 version marker at key "0" and keeps items from "1"', () => {
    const buf = document([
      element(
        0x04,
        'Items',
        document([
          element(0x10, '0', int32(3)), // version marker, not an item
          element(0x02, '1', bsonString('first')),
          element(0x02, '2', bsonString('second')),
        ])
      ),
    ]);

    assert.deepEqual(parseBsonDocument(buf).Items, ['first', 'second']);
  });

  it('keeps index 0 when it is a real item rather than a marker', () => {
    const buf = document([
      element(
        0x04,
        'Plain',
        document([
          element(0x02, '0', bsonString('zero')),
          element(0x02, '1', bsonString('one')),
        ])
      ),
    ]);

    assert.deepEqual(parseBsonDocument(buf).Plain, ['zero', 'one']);
  });

  it('reads an empty array as an empty list', () => {
    const buf = document([element(0x04, 'Empty', document([]))]);
    assert.deepEqual(parseBsonDocument(buf).Empty, []);
  });
});

describe('BSON reader: malformed input throws rather than returning partial garbage', () => {
  /** Assert the call throws a BsonParseError whose message mentions `expected`. */
  function assertBsonError(fn, expected) {
    assert.throws(fn, (err) => {
      assert.ok(err instanceof BsonParseError, `expected BsonParseError, got ${err?.name}`);
      assert.equal(err.name, 'BsonParseError');
      assert.equal(typeof err.offset, 'number');
      assert.match(err.message, expected);
      return true;
    });
  }

  it('rejects a document truncated mid-body', () => {
    const full = document([element(0x02, 'Name', bsonString('MyFirstModule'))]);
    assertBsonError(() => parseBsonDocument(full.subarray(0, full.length - 6)), /truncated/);
  });

  it('rejects a document truncated inside its length prefix', () => {
    assertBsonError(() => parseBsonDocument(Buffer.from([0x20, 0x00])), /truncated|int32/);
  });

  it('rejects a length prefix below the 5-byte minimum', () => {
    const buf = Buffer.concat([int32(3), Buffer.from([0])]);
    assertBsonError(() => parseBsonDocument(buf), /invalid document length 3/);
  });

  it('rejects a length prefix larger than the 64 MB cap', () => {
    const buf = Buffer.concat([int32(0x7fff_ffff), Buffer.alloc(8)]);
    assertBsonError(() => parseBsonDocument(buf), /exceeds the .* byte cap|truncated/);
  });

  it('rejects an unknown element tag', () => {
    const buf = document([element(0x7e, 'Weird', int32(1))]);
    assertBsonError(() => parseBsonDocument(buf), /unknown BSON element tag 0x7e/);
  });

  it('rejects an unterminated element key', () => {
    const body = Buffer.concat([Buffer.from([0x02]), Buffer.from('NoNulHere', 'utf8')]);
    const buf = Buffer.concat([int32(body.length + 5), body, Buffer.from([0])]);
    assertBsonError(() => parseBsonDocument(buf), /unterminated element key|truncated/);
  });

  it('rejects a negative string length', () => {
    const buf = document([element(0x02, 'Name', Buffer.concat([int32(-1), Buffer.from([0])]))]);
    assertBsonError(() => parseBsonDocument(buf), /invalid string length -1/);
  });

  it('rejects a nested document that overruns its parent', () => {
    // A nested document claiming more bytes than the parent's body holds.
    const inner = Buffer.concat([int32(64), Buffer.from([0])]);
    const buf = document([element(0x03, 'Child', inner)]);
    assertBsonError(() => parseBsonDocument(buf), /truncated|overran/);
  });

  it('does not silently return the elements it read before the corruption', () => {
    const good = element(0x02, 'Name', bsonString('Readable'));
    const bad = element(0x7e, 'Broken', int32(1));
    const buf = document([good, bad]);
    let result;
    try {
      result = parseBsonDocument(buf);
    } catch {
      result = 'threw';
    }
    assert.equal(result, 'threw', 'a partial tree containing only Name would be worse than an error');
  });
});

describe('BSON header reader', () => {
  it('reads top-level scalars and skips nested documents', () => {
    const buf = document([
      element(0x02, '$Type', bsonString('Forms$Page')),
      element(0x03, 'Huge', document([element(0x02, 'Deep', bsonString('ignored'))])),
      element(0x02, 'Name', bsonString('Home_Web')),
    ]);

    const header = parseBsonHeader(buf);
    assert.equal(header.$Type, 'Forms$Page');
    assert.equal(header.Name, 'Home_Web');
    assert.equal(header.Huge, undefined, 'nested documents must not be materialised');
  });

  it('stops cleanly when a nested value is longer than the buffer', () => {
    // The realistic overrun: a page unit whose widget tree declares more bytes than are
    // present. The discriminator already read is still trustworthy, so it is returned.
    const buf = Buffer.concat([
      document([
        element(0x02, '$Type', bsonString('Forms$Page')),
        element(0x02, 'Name', bsonString('Home_Web')),
        element(0x03, 'Widgets', Buffer.concat([int32(4096), Buffer.alloc(8)])),
      ]),
    ]);

    const header = parseBsonHeader(buf);
    assert.equal(header.$Type, 'Forms$Page');
    assert.equal(header.Name, 'Home_Web');
    assert.equal(header.Widgets, undefined);
  });

  it('throws when a top-level scalar is cut short, rather than classifying a corrupt unit', () => {
    // The caller hands in whole files, so a cut scalar means the file is damaged. Returning
    // the `$Type` anyway would index the unit and let every extractor read it as intact.
    const buf = document([
      element(0x02, '$Type', bsonString('Forms$Page')),
      element(0x02, 'Name', bsonString('Home_Web')),
    ]);
    assert.throws(() => parseBsonHeader(buf.subarray(0, 30)), BsonParseError);
  });
});

// --- the oracle cross-check -----------------------------------------------------------------

/** `./mxcli bson dump` output uses [{Key, Value}] pairs; flatten to the reader's shape. */
function normaliseOracle(value) {
  if (Array.isArray(value)) {
    const isKvList =
      value.length > 0 &&
      value.every((e) => e && typeof e === 'object' && !Array.isArray(e) && 'Key' in e);
    if (isKvList) {
      const out = {};
      for (const { Key, Value } of value) out[Key] = normaliseOracle(Value);
      return out;
    }
    const items = typeof value[0] === 'number' ? value.slice(1) : value;
    return items.map(normaliseOracle);
  }
  if (value && typeof value === 'object') {
    if ('Subtype' in value && 'Data' in value) return '<binary>';
    return value;
  }
  return value;
}

/** The reader's tree in the same shape, so the two are comparable. */
function normaliseTree(value) {
  if (value instanceof Uint8Array) return '<binary>';
  if (Array.isArray(value)) return value.map(normaliseTree);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).map((k) => [k, normaliseTree(value[k])]));
  }
  if (typeof value === 'bigint') return Number(value);
  return value;
}

const MXCLI = join(REPO_ROOT, process.platform === 'win32' ? 'mxcli.exe' : 'mxcli');

describeFixture('BSON reader cross-validated against ./mxcli bson dump', () => {
  const oracleAvailable = existsSync(MXCLI);

  it(
    'agrees with the oracle on a sample of page units',
    { skip: oracleAvailable ? false : `${MXCLI} not present; the oracle is optional` },
    async () => {
      const listed = execFileSync(
        MXCLI,
        ['bson', 'dump', '-p', FIXTURE_MPR, '--type', 'page', '--list'],
        { encoding: 'utf8', cwd: REPO_ROOT }
      );
      const names = [...listed.matchAll(/([A-Za-z_][\w]*\.[A-Za-z_][\w]*)/g)]
        .map((m) => m[1])
        .filter((n) => !n.endsWith('.mpr'));
      assert.ok(names.length > 0, 'the oracle listed no pages');

      const { ModelGraph } = await import('@mendix-analyzer/mendix-parser');
      const graph = ModelGraph.build(
        join(REPO_ROOT, 'scratch', 'testapp_unpacked', 'TestApp-main'),
        FIXTURE_MPR
      );

      // Three pages is a sample, not a sweep: each dump is a separate process launch, and the
      // property the test establishes — that the tree shape matches — does not get truer on the
      // sixteenth page.
      let compared = 0;
      for (const qualified of [...new Set(names)].slice(0, 3)) {
        const raw = execFileSync(
          MXCLI,
          ['bson', 'dump', '-p', FIXTURE_MPR, '--type', 'page', '--object', qualified],
          { encoding: 'utf8', cwd: REPO_ROOT, maxBuffer: 64 * 1024 * 1024 }
        );
        const jsonStart = raw.indexOf('[') >= 0 ? raw.indexOf('[') : raw.indexOf('{');
        if (jsonStart < 0) continue;
        const oracle = normaliseOracle(JSON.parse(raw.slice(jsonStart)));

        const name = qualified.slice(qualified.indexOf('.') + 1);
        const match = graph.units
          .unitsOfType('Forms$Page')
          .find(({ tree }) => tree.Name === name);
        assert.ok(match, `the reader found no Forms$Page named ${name}`);

        const mine = normaliseTree(match.tree);
        // Compare the structural spine rather than every leaf: the oracle renders some scalars
        // differently (dates, enum casing), and a key-set mismatch is what would actually mean
        // the reader had lost part of the model.
        assert.deepEqual(
          Object.keys(mine).sort(),
          Object.keys(oracle).sort(),
          `top-level keys differ for ${qualified}`
        );
        assert.equal(mine.Name, oracle.Name);
        assert.equal(mine.$Type, oracle.$Type);
        compared++;
      }

      assert.ok(compared > 0, 'no page could be compared against the oracle');
    }
  );
});

describeFixture('BSON reader against the real units', () => {
  it('parses every unit in the reference project without throwing', async () => {
    const { ModelGraph } = await import('@mendix-analyzer/mendix-parser');
    const graph = ModelGraph.build(
      join(REPO_ROOT, 'scratch', 'testapp_unpacked', 'TestApp-main'),
      FIXTURE_MPR
    );
    assert.deepEqual(
      graph.diagnosticsReport.unitParseFailures,
      [],
      'a unit that fails to parse is a fact the analyzer silently loses'
    );
  });

  it('reads a real unit file the same way twice', async () => {
    const { ModelGraph } = await import('@mendix-analyzer/mendix-parser');
    const root = join(REPO_ROOT, 'scratch', 'testapp_unpacked', 'TestApp-main');
    const graph = ModelGraph.build(root, FIXTURE_MPR);
    const [first] = graph.units.refsOfType('Security$ProjectSecurity');
    assert.ok(first, 'the reference project has a Security$ProjectSecurity unit');

    const bytes = readFileSync(join(root, first.unitPath));
    assert.deepEqual(parseBsonDocument(bytes), parseBsonDocument(bytes));
  });
});
