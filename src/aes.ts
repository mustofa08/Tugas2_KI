import { randomBytes } from "crypto";

const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
const MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
const INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]];

function xtime(a: number): number {
  a <<= 1;
  return a & 0x100 ? a ^ 0x11b : a;
}

function gmul(a: number, b: number): number {
  let p = 0;
  while (b) {
    if (b & 1) p ^= a;
    a = xtime(a);
    b >>= 1;
  }
  return p;
}

function gfInverse(a: number): number {
  if (a === 0) return 0;
  let r = 1;
  for (let i = 0; i < 254; i++) r = gmul(r, a);
  return r;
}

function buildSbox(): void {
  for (let i = 0; i < 256; i++) {
    const b = gfInverse(i);
    let s = b;
    for (let k = 1; k < 5; k++) s ^= ((b << k) | (b >> (8 - k))) & 0xff;
    s ^= 0x63;
    SBOX[i] = s;
    INV_SBOX[s] = i;
  }
}

buildSbox();

export function keyExpansion(key: Uint8Array): number[][] {
  const nk = key.length / 4;
  const nr = nk + 6;
  const w: number[][] = [];
  for (let i = 0; i < nk; i++) w.push(Array.from(key.slice(4 * i, 4 * i + 4)));
  for (let i = nk; i < 4 * (nr + 1); i++) {
    let temp = w[i - 1].slice();
    if (i % nk === 0) {
      temp = [...temp.slice(1), temp[0]].map((b) => SBOX[b]);
      temp[0] ^= RCON[i / nk - 1];
    } else if (nk > 6 && i % nk === 4) {
      temp = temp.map((b) => SBOX[b]);
    }
    w.push(w[i - nk].map((b, j) => b ^ temp[j]));
  }
  const roundKeys: number[][] = [];
  for (let r = 0; r <= nr; r++) roundKeys.push(w.slice(4 * r, 4 * r + 4).flat());
  return roundKeys;
}

function addRoundKey(state: number[], rk: number[]): number[] {
  return state.map((s, i) => s ^ rk[i]);
}

function subBytes(state: number[], box: Uint8Array): number[] {
  return state.map((b) => box[b]);
}

function shiftRows(state: number[]): number[] {
  return state.map((_, i) => state[(i + 4 * (i % 4)) % 16]);
}

function invShiftRows(state: number[]): number[] {
  return state.map((_, i) => state[(i - 4 * (i % 4) + 16) % 16]);
}

function mixColumns(state: number[], m: number[][]): number[] {
  const out: number[] = [];
  for (let c = 0; c < 4; c++) {
    const col = state.slice(4 * c, 4 * c + 4);
    for (let r = 0; r < 4; r++) {
      let v = 0;
      for (let k = 0; k < 4; k++) v ^= gmul(m[r][k], col[k]);
      out.push(v);
    }
  }
  return out;
}

export function encryptBlock(block: Uint8Array, roundKeys: number[][]): Uint8Array {
  const nr = roundKeys.length - 1;
  let state = addRoundKey(Array.from(block), roundKeys[0]);
  for (let r = 1; r < nr; r++) {
    state = subBytes(state, SBOX);
    state = shiftRows(state);
    state = mixColumns(state, MIX);
    state = addRoundKey(state, roundKeys[r]);
  }
  state = subBytes(state, SBOX);
  state = shiftRows(state);
  state = addRoundKey(state, roundKeys[nr]);
  return Uint8Array.from(state);
}

export function decryptBlock(block: Uint8Array, roundKeys: number[][]): Uint8Array {
  const nr = roundKeys.length - 1;
  let state = addRoundKey(Array.from(block), roundKeys[nr]);
  for (let r = nr - 1; r > 0; r--) {
    state = invShiftRows(state);
    state = subBytes(state, INV_SBOX);
    state = addRoundKey(state, roundKeys[r]);
    state = mixColumns(state, INV_MIX);
  }
  state = invShiftRows(state);
  state = subBytes(state, INV_SBOX);
  state = addRoundKey(state, roundKeys[0]);
  return Uint8Array.from(state);
}

function pad(data: Uint8Array): Uint8Array {
  const n = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + n).fill(n);
  out.set(data);
  return out;
}

function unpad(data: Uint8Array): Uint8Array {
  const n = data.length ? data[data.length - 1] : 0;
  if (n < 1 || n > 16 || data.slice(data.length - n).some((b) => b !== n)) {
    throw new Error("padding tidak valid (key salah?)");
  }
  return data.slice(0, data.length - n);
}

export function checkKey(key: string): Uint8Array {
  if (!/^[\x00-\x7f]*$/.test(key)) throw new Error("key harus ASCII");
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("panjang key harus 16, 24, atau 32 karakter (AES-128/192/256)");
  }
  return Uint8Array.from(Buffer.from(key, "ascii"));
}

function xorBlock(a: Uint8Array, b: Uint8Array): Uint8Array {
  return a.map((x, i) => x ^ b[i]);
}

export function encrypt(plaintext: string, key: string): string {
  const roundKeys = keyExpansion(checkKey(key));
  const iv = Uint8Array.from(randomBytes(16));
  const data = pad(Buffer.from(plaintext, "utf8"));
  const out = new Uint8Array(16 + data.length);
  out.set(iv);
  let prev: Uint8Array = iv;
  for (let i = 0; i < data.length; i += 16) {
    prev = encryptBlock(xorBlock(data.slice(i, i + 16), prev), roundKeys);
    out.set(prev, 16 + i);
  }
  return Buffer.from(out).toString("hex");
}

export function decrypt(cipherHex: string, key: string): string {
  const roundKeys = keyExpansion(checkKey(key));
  if (!/^([0-9a-fA-F]{2})+$/.test(cipherHex)) throw new Error("ciphertext bukan hex");
  const raw = Uint8Array.from(Buffer.from(cipherHex, "hex"));
  if (raw.length < 32 || raw.length % 16) throw new Error("panjang ciphertext tidak valid");
  const out = new Uint8Array(raw.length - 16);
  let prev: Uint8Array = raw.slice(0, 16);
  for (let i = 16; i < raw.length; i += 16) {
    const block = raw.slice(i, i + 16);
    out.set(xorBlock(decryptBlock(block, roundKeys), prev), i - 16);
    prev = block;
  }
  return Buffer.from(unpad(out)).toString("utf8");
}
