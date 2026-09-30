/**
 * Minimal BSON reader for Mendix `.mxunit` documents.
 *
 * Mendix stores every model unit under `mprcontents/**` as a standard BSON document.
 * Reading it as a nested tree (rather than a flat scan for tag bytes) is what makes
 * containment-dependent facts — access rules, member access, role mappings, page
 * allowed-roles — recoverable at all.
 *
 * Deliberately dependency-free: parsing untrusted uploaded archives is the analyzer's
 * core threat surface, so this reads bytes and nothing else. Every length is validated
 * against the remaining buffer before use, and a malformed document throws
 * `BsonParseError` rather than returning a partial tree.
 *
 * See docs/security.md, Appendix B for the observed encoding.
 */

export class BsonParseError extends Error {
  constructor(message: string, public readonly offset: number) {
    super(`${message} (at byte ${offset})`);
    this.name = 'BsonParseError';
  }
}

/** A parsed unit: a plain object tree. `$Type` and `$ID` are present on model elements. */
export type BsonValue =
  | string
  | number
  | bigint
  | boolean
  | null
  | Uint8Array
  | BsonDocument
  | BsonValue[];

export interface BsonDocument {
  [key: string]: BsonValue | undefined;
}

// BSON element type tags observed in Mendix units.
const TAG_DOUBLE = 0x01;
const TAG_STRING = 0x02;
const TAG_DOCUMENT = 0x03;
const TAG_ARRAY = 0x04;
const TAG_BINARY = 0x05;
const TAG_UNDEFINED = 0x06; // deprecated in BSON, treated as null
const TAG_OBJECTID = 0x07;
const TAG_BOOLEAN = 0x08;
const TAG_UTC_DATETIME = 0x09;
const TAG_NULL = 0x0a;
const TAG_REGEX = 0x0b;
const TAG_INT32 = 0x10;
const TAG_TIMESTAMP = 0x11;
const TAG_INT64 = 0x12;

/**
 * Guards against a corrupt or hostile length prefix claiming more than the file holds.
 * 64 MB is well above the largest unit observed (the biggest page document in the
 * reference fixture is ~500 KB).
 */
const MAX_DOCUMENT_BYTES = 64 * 1024 * 1024;

class Cursor {
  public offset = 0;

  constructor(public readonly buf: Uint8Array, private readonly view: DataView) {}

  public get remaining(): number {
    return this.buf.length - this.offset;
  }

  public need(bytes: number, what: string): void {
    if (bytes < 0 || bytes > this.remaining) {
      throw new BsonParseError(
        `truncated document: needed ${bytes} byte(s) for ${what}, ${this.remaining} remaining`,
        this.offset
      );
    }
  }

  public readUint8(): number {
    this.need(1, 'tag');
    return this.buf[this.offset++];
  }

  public readInt32(): number {
    this.need(4, 'int32');
    const v = this.view.getInt32(this.offset, true);
    this.offset += 4;
    return v;
  }

  public readInt64(): bigint {
    this.need(8, 'int64');
    const v = this.view.getBigInt64(this.offset, true);
    this.offset += 8;
    return v;
  }

  public readDouble(): number {
    this.need(8, 'double');
    const v = this.view.getFloat64(this.offset, true);
    this.offset += 8;
    return v;
  }

  /** NUL-terminated key. */
  public readCString(): string {
    const start = this.offset;
    while (this.offset < this.buf.length && this.buf[this.offset] !== 0x00) {
      this.offset++;
    }
    if (this.offset >= this.buf.length) {
      throw new BsonParseError('unterminated element key', start);
    }
    const s = decodeUtf8(this.buf.subarray(start, this.offset));
    this.offset++; // consume NUL
    return s;
  }

  /** int32 length-prefixed string; the declared length includes the trailing NUL. */
  public readString(): string {
    const declared = this.readInt32();
    if (declared < 1) {
      throw new BsonParseError(`invalid string length ${declared}`, this.offset - 4);
    }
    this.need(declared, 'string body');
    const s = decodeUtf8(this.buf.subarray(this.offset, this.offset + declared - 1));
    this.offset += declared;
    return s;
  }

  public readBytes(n: number): Uint8Array {
    this.need(n, 'binary body');
    const out = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }
}

const utf8Decoder = new TextDecoder('utf-8', { fatal: false });
function decodeUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

/**
 * Parse a complete BSON document from `buffer`.
 *
 * @throws {BsonParseError} on truncation, a bad length prefix, or an unknown element tag.
 */
export function parseBsonDocument(buffer: Uint8Array): BsonDocument {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const cur = new Cursor(buffer, view);
  const doc = readDocument(cur, 0);
  return doc;
}

/**
 * Read only the top-level scalar properties, skipping nested documents and arrays.
 *
 * Used to classify a unit by `$Type` without materialising its tree. A page unit can be
 * 3 MB of nested widgets; the unit index needs four bytes of discriminator to decide
 * whether any extractor will ever ask for it. Nested values are skipped by their own
 * length prefix, so this shares the reader's validation and cannot desynchronise.
 *
 * A nested value whose length runs past the end of the buffer stops the scan and the scalars
 * read so far are returned; a scalar element that is itself cut short throws. The asymmetry is
 * deliberate. The caller hands in whole files, so a cut scalar means the file is corrupt, and
 * returning a `$Type` read out of a damaged unit would let the unit be classified, indexed and
 * then silently misread. A nested value only overruns when the declared length is longer than
 * the file, which is the one case where the header we already have is still trustworthy.
 *
 * @throws {BsonParseError} on a bad length prefix, an unknown tag, or a truncated scalar.
 */
export function parseBsonHeader(buffer: Uint8Array): BsonDocument {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const cur = new Cursor(buffer, view);

  const start = cur.offset;
  const declaredLength = cur.readInt32();
  if (declaredLength < 5) {
    throw new BsonParseError(`invalid document length ${declaredLength}`, start);
  }
  // Bound the scan by whatever is actually present, so a declared length longer than the
  // file scans the bytes we have rather than reading past the end of the buffer.
  const end = Math.min(start + declaredLength, buffer.length);

  const doc: BsonDocument = {};
  while (cur.offset < end - 1) {
    const tag = cur.readUint8();
    if (tag === 0x00) break;
    const key = cur.readCString();
    if (tag === TAG_DOCUMENT || tag === TAG_ARRAY) {
      const nestedStart = cur.offset;
      const nestedLength = cur.readInt32();
      if (nestedLength < 5) {
        throw new BsonParseError(`invalid nested document length ${nestedLength}`, nestedStart);
      }
      cur.offset = nestedStart + nestedLength;
      if (cur.offset > buffer.length) break; // ran off the end of a prefix; stop cleanly
    } else {
      doc[key] = readElement(cur, tag, MAX_DEPTH);
    }
  }
  return doc;
}

/** Nesting cap: unit documents in the reference fixture reach ~20 levels. */
const MAX_DEPTH = 200;

function readDocument(cur: Cursor, depth: number): BsonDocument {
  if (depth > MAX_DEPTH) {
    throw new BsonParseError(`document nesting exceeded ${MAX_DEPTH} levels`, cur.offset);
  }

  const start = cur.offset;
  const declaredLength = cur.readInt32();

  if (declaredLength < 5) {
    throw new BsonParseError(`invalid document length ${declaredLength}`, start);
  }
  if (declaredLength > MAX_DOCUMENT_BYTES) {
    throw new BsonParseError(
      `document length ${declaredLength} exceeds the ${MAX_DOCUMENT_BYTES} byte cap`,
      start
    );
  }
  // The length prefix counts itself, so the body plus terminator is length - 4.
  cur.need(declaredLength - 4, 'document body');

  const end = start + declaredLength;
  const doc: BsonDocument = {};

  while (cur.offset < end - 1) {
    const tag = cur.readUint8();
    if (tag === 0x00) {
      // Early terminator. Tolerate it: the declared length is authoritative.
      cur.offset = end;
      return doc;
    }
    const key = cur.readCString();
    doc[key] = readElement(cur, tag, depth);
  }

  // Consume the document terminator.
  if (cur.offset < end) {
    const terminator = cur.readUint8();
    if (terminator !== 0x00) {
      throw new BsonParseError(
        `expected document terminator, found 0x${terminator.toString(16)}`,
        cur.offset - 1
      );
    }
  }

  if (cur.offset !== end) {
    throw new BsonParseError(
      `document overran its declared length by ${cur.offset - end} byte(s)`,
      cur.offset
    );
  }

  return doc;
}

function readElement(cur: Cursor, tag: number, depth: number): BsonValue {
  switch (tag) {
    case TAG_DOUBLE:
      return cur.readDouble();

    case TAG_STRING:
      return cur.readString();

    case TAG_DOCUMENT:
      return readDocument(cur, depth + 1);

    case TAG_ARRAY:
      return documentToArray(readDocument(cur, depth + 1));

    case TAG_BINARY: {
      const len = cur.readInt32();
      if (len < 0) {
        throw new BsonParseError(`invalid binary length ${len}`, cur.offset - 4);
      }
      cur.readUint8(); // binary subtype; Mendix uses 0x00 (generic) for $ID GUIDs
      return cur.readBytes(len);
    }

    case TAG_OBJECTID:
      return cur.readBytes(12);

    case TAG_BOOLEAN:
      return cur.readUint8() !== 0x00;

    case TAG_UTC_DATETIME:
      return cur.readInt64();

    case TAG_UNDEFINED:
    case TAG_NULL:
      return null;

    case TAG_REGEX:
      // pattern + flags, both NUL-terminated
      return `/${cur.readCString()}/${cur.readCString()}`;

    case TAG_INT32:
      return cur.readInt32();

    case TAG_TIMESTAMP:
      return cur.readInt64();

    case TAG_INT64: {
      const v = cur.readInt64();
      // Mendix uses int64 for small layout/config values (TabIndex, MinimumLength).
      // Narrow to number when lossless so consumers don't juggle bigint.
      return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(v)
        : v;
    }

    default:
      throw new BsonParseError(`unknown BSON element tag 0x${tag.toString(16)}`, cur.offset - 1);
  }
}

/**
 * BSON arrays are documents keyed "0", "1", "2", ….
 *
 * Mendix puts an int32 *version marker* at key "0" and the real items from "1" onward.
 * The marker is metadata about the serialisation format, not a model element, so it is
 * dropped — but only when it is genuinely a bare number at index 0. An array whose "0"
 * is a document or string is a plain BSON array and is returned whole.
 */
function documentToArray(doc: BsonDocument): BsonValue[] {
  const keys = Object.keys(doc);
  if (keys.length === 0) return [];

  const first = doc['0'];
  const hasVersionMarker = typeof first === 'number' || typeof first === 'bigint';

  const items: BsonValue[] = [];
  let index = hasVersionMarker ? 1 : 0;
  for (;;) {
    const v = doc[String(index)];
    if (v === undefined) break;
    items.push(v);
    index++;
  }
  return items;
}
