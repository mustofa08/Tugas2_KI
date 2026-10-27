# Tugas 2 Keamanan Informasi: Key Distribution Scenario + AES

Implementasi manual (tanpa library kriptografi) dengan TypeScript (Node.js):

- **AES** 128/192/256 bit, mode CBC dengan padding PKCS#7 (`src/aes.ts`)
- **KDC** sesuai Key Distribution Scenario (Stallings), 5 langkah:
  1. A → KDC: `IDA || IDB || N1`
  2. KDC → A: `E(Ka, [Ks || IDA || IDB || N1]) || E(Kb, [Ks || IDA])`
  3. A → B: `E(Kb, [Ks || IDA])`
  4. B → A: `E(Ks, N2)`
  5. A → B: `E(Ks, f(N2))`, dengan `f(N2) = N2 + 1`
- Setelah langkah 5, Alice dan Bob chat dua arah terenkripsi AES memakai `Ks`.

Key dan plaintext dalam ASCII, ciphertext ditampilkan dalam hex. Modul `crypto` Node hanya dipakai untuk membangkitkan bilangan acak (IV, nonce, Ks); seluruh algoritma AES ditulis sendiri.

## Struktur

| File | Isi |
|---|---|
| `src/aes.ts` | AES manual: S-box, key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, CBC |
| `src/common.ts` | Framing pesan TCP (JSON per baris), input interaktif, nonce, session key, perintah chat |
| `src/kdc.ts` | Server KDC, menyimpan master key tiap user |
| `src/alice.ts` | Initiator: minta Ks ke KDC lalu autentikasi ke Bob |
| `src/bob.ts` | Responder: menerima tiket, challenge N2, verifikasi f(N2) |
| `src/test_aes.ts` | Uji AES dengan test vector FIPS-197 |

## Persiapan

Butuh Node.js 18+.

```bash
npm install
npm run build
npm test        # uji AES (FIPS-197)
```

Setelah `npm run build`, program dijalankan dengan `node dist/<nama>.js`.

## Cara menjalankan

### Di 3 perangkat berbeda (demo)

Misal KDC = `192.168.1.10`, Alice = `192.168.1.11`, Bob = `192.168.1.12` (satu jaringan, firewall mengizinkan port 5000 dan 6000).

```bash
# Perangkat KDC
node dist/kdc.js --port 5000
add Alice kunciAlice123456
add Bob kunciBob12345678

# Perangkat Bob
node dist/bob.js --port 6000

# Perangkat Alice
node dist/alice.js --kdc 192.168.1.10:5000 --bob 192.168.1.12:6000
```

Master key bisa juga diberikan saat start: `node dist/kdc.js --user Alice:kunciAlice123456 --user Bob:kunciBob12345678`.

### Di 1 laptop dengan 3 IP loopback

```bash
node dist/kdc.js --host 127.0.0.1 --user Alice:kunciAlice123456 --user Bob:kunciBob12345678
node dist/bob.js --host 127.0.0.3
node dist/alice.js --bind 127.0.0.2 --kdc 127.0.0.1:5000 --bob 127.0.0.3:6000
```

(Di Windows, seluruh 127.x.x.x biasanya bisa dipakai tanpa konfigurasi tambahan.)

## Perintah interaktif

KDC: `add <ID> <key>`, `del <ID>`, `list`, `quit`.

Alice/Bob saat chat:

| Perintah | Fungsi |
|---|---|
| `<teks>` | kirim pesan terenkripsi |
| `/key <key>` | ganti session key lokal (uji key berbeda: pesan gagal didekripsi) |
| `/master <key>` | ganti master key sendiri |
| `/rekey` | minta Ks baru dari KDC, ulang langkah 1–5 tanpa restart |
| `/enc <teks>`, `/dec <hex>` | enkripsi/dekripsi lokal untuk test case |
| `/info` | tampilkan ID dan key aktif |
| `/quit` | keluar |

Panjang key harus 16, 24, atau 32 karakter ASCII (AES-128/192/256).

## Wireshark

- Interface: Wi-Fi/Ethernet yang dipakai bersama. Untuk uji di 1 laptop Windows pakai **Adapter for loopback traffic capture** (Npcap), di Linux pakai `lo`.
- Filter tampilan:
  - Semua: `tcp.port == 5000 || tcp.port == 6000`
  - Hanya yang berisi data: `(tcp.port == 5000 || tcp.port == 6000) && tcp.len > 0`
  - Langkah 1–2 (Alice ↔ KDC): `tcp.port == 5000`
  - Langkah 3–5 dan chat (Alice ↔ Bob): `tcp.port == 6000`
- Klik kanan paket → **Follow → TCP Stream** untuk melihat JSON: `step1` terlihat plaintext (sesuai skenario), sedangkan `step2` sampai `chat` hanya berisi hex ciphertext.
