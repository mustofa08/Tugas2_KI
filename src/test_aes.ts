import { decrypt, decryptBlock, encrypt, encryptBlock, keyExpansion } from "./aes";

const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");
const fromHex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));

const vectors: [string, string][] = [
  ["000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"],
  ["000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"],
  ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"],
];
const pt = fromHex("00112233445566778899aabbccddeeff");

for (const [key, expected] of vectors) {
  const rk = keyExpansion(fromHex(key));
  const ct = encryptBlock(pt, rk);
  if (hex(ct) !== expected) throw new Error(`AES-${key.length * 4} gagal: ${hex(ct)}`);
  if (hex(decryptBlock(ct, rk)) !== hex(pt)) throw new Error("dekripsi blok gagal");
  console.log(`AES-${key.length * 4} OK  ${hex(ct)}`);
}

const msg = "Halo Bob, ini pesan rahasia!";
const c = encrypt(msg, "kuncirahasia1234");
if (decrypt(c, "kuncirahasia1234") !== msg) throw new Error("CBC gagal");
console.log("CBC OK", c);
