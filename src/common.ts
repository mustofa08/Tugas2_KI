import { randomBytes, randomInt } from "crypto";
import * as net from "net";
import * as readline from "readline";
import { checkKey, decrypt, encrypt } from "./aes";

export const SEP = "||";
export type Msg = { type: string; [field: string]: string };

export const rl = readline.createInterface({ input: process.stdin });
const lineQueue: string[] = [];
const waiters: ((line: string | null) => void)[] = [];
let inputClosed = false;
let chatHandler: ((line: string) => void) | null = null;

rl.on("line", (line) => {
  const waiter = waiters.shift();
  if (waiter) waiter(line);
  else if (chatHandler) chatHandler(line);
  else lineQueue.push(line);
});
rl.on("close", () => {
  inputClosed = true;
  waiters.splice(0).forEach((w) => w(null));
  if (chatHandler) chatHandler("/quit");
});

export function log(...args: unknown[]): void {
  console.log(...args);
}

function nextLine(): Promise<string | null> {
  const queued = lineQueue.shift();
  if (queued !== undefined) return Promise.resolve(queued);
  if (inputClosed) return Promise.resolve(null);
  return new Promise((resolve) => waiters.push(resolve));
}

export async function ask(prompt: string, def?: string): Promise<string> {
  process.stdout.write(`${prompt}${def ? ` [${def}]` : ""}: `);
  const line = await nextLine();
  if (line === null) process.exit(0);
  return line.trim() || def || "";
}

export async function askKey(prompt: string): Promise<string> {
  for (;;) {
    process.stdout.write(`${prompt}: `);
    const key = await nextLine();
    if (key === null) process.exit(0);
    try {
      checkKey(key);
      return key;
    } catch (e) {
      log("  ", (e as Error).message);
    }
  }
}

export function onLines(handler: ((line: string) => void) | null): void {
  chatHandler = handler;
}

export function send(sock: net.Socket, msg: Msg): void {
  sock.write(JSON.stringify(msg) + "\n");
}

export function readMessages(sock: net.Socket, onMsg: (m: Msg) => void, onEnd: () => void): void {
  let buf = "";
  sock.setEncoding("utf8");
  sock.on("data", (chunk: string) => {
    buf += chunk;
    let idx: number;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      if (!line.trim()) continue;
      try {
        onMsg(JSON.parse(line));
      } catch (e) {
        log(`[!] pesan tidak valid: ${(e as Error).message}`);
      }
    }
  });
  sock.on("error", (e) => log(`[!] koneksi error: ${e.message}`));
  sock.on("close", onEnd);
}

export function connect(host: string, port: number, localAddress?: string): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port, localAddress });
    sock.setTimeout(10000, () => sock.destroy(new Error("timeout")));
    sock.once("connect", () => {
      sock.setTimeout(0);
      resolve(sock);
    });
    sock.once("error", reject);
  });
}

export function requestOnce(sock: net.Socket, msg: Msg): Promise<Msg> {
  return new Promise((resolve, reject) => {
    readMessages(sock, resolve, () => reject(new Error("koneksi terputus")));
    send(sock, msg);
  });
}

export function parseAddr(addr: string): [string, number] {
  const i = addr.lastIndexOf(":");
  return [addr.slice(0, i), Number(addr.slice(i + 1))];
}

export function makeNonce(): string {
  return String(randomBytes(4).readUInt32BE());
}

export function makeSessionKey(length = 16): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length }, () => chars[randomInt(chars.length)]).join("");
}

export function f(n: string): string {
  return String(BigInt(n) + 1n);
}

export const HELP = `Perintah:
  <teks>          kirim pesan terenkripsi AES
  /key <key>      ganti session key lokal (16/24/32 karakter ASCII)
  /master <key>   ganti master key sendiri (harus sama dengan di KDC)
  /rekey          minta session key baru dari KDC (ulang langkah 1-5)
  /enc <teks>     enkripsi lokal saja, tampilkan hex
  /dec <hex>      dekripsi lokal saja
  /info           tampilkan ID dan key saat ini
  /quit           keluar`;

export abstract class Peer {
  sessionKey = "";
  peerId = "";
  sock: net.Socket | null = null;

  constructor(public myId: string, public masterKey: string) {}

  abstract rekey(): void;

  handle(msg: Msg): void {
    if (msg.type === "chat") this.onChat(msg.data);
    else if (msg.type === "error") log(`[ERROR dari ${this.peerId || "peer"}] ${msg.reason}`);
    else log(`[?] pesan tidak dikenal: ${JSON.stringify(msg)}`);
  }

  onChat(cipherHex: string): void {
    log(`\n[RECV cipher] ${cipherHex}`);
    try {
      log(`[RECV plain ] ${this.peerId}: ${decrypt(cipherHex, this.sessionKey)}`);
    } catch (e) {
      log(`[RECV plain ] gagal dekripsi: ${(e as Error).message}`);
    }
  }

  setKey(arg: string, apply: (key: string) => void, message: string): void {
    try {
      checkKey(arg);
      apply(arg);
      log(message);
    } catch (e) {
      log(`[!] ${(e as Error).message}`);
    }
  }

  command(line: string): void {
    const space = line.indexOf(" ");
    const cmd = space < 0 ? line : line.slice(0, space);
    const arg = space < 0 ? "" : line.slice(space + 1);
    switch (cmd) {
      case "/help":
        log(HELP);
        break;
      case "/key":
        this.setKey(arg, (k) => (this.sessionKey = k), `[*] session key lokal diganti -> ${arg}`);
        break;
      case "/master":
        this.setKey(arg, (k) => (this.masterKey = k), `[*] master key ${this.myId} diganti (samakan juga di KDC)`);
        break;
      case "/info":
        log(`[*] saya=${this.myId} peer=${this.peerId} master_key=${this.masterKey} session_key=${this.sessionKey}`);
        break;
      case "/enc":
        try {
          log(`[*] ${encrypt(arg, this.sessionKey)}`);
        } catch (e) {
          log(`[!] ${(e as Error).message}`);
        }
        break;
      case "/dec":
        try {
          log(`[*] ${decrypt(arg, this.sessionKey)}`);
        } catch (e) {
          log(`[!] ${(e as Error).message}`);
        }
        break;
      case "/rekey":
        this.rekey();
        break;
      default:
        log("[!] perintah tidak dikenal, ketik /help");
    }
  }

  onLine(line: string): void {
    if (!this.sock || !line) return;
    if (line === "/quit") {
      this.sock.end();
      return;
    }
    if (line.startsWith("/")) return this.command(line);
    if (!this.sessionKey) return log("[!] session key belum ada, tunggu key distribution selesai");
    const cipherHex = encrypt(line, this.sessionKey);
    log(`[SEND cipher] ${cipherHex}`);
    send(this.sock, { type: "chat", data: cipherHex });
  }

  startChat(): void {
    log(HELP);
    onLines((line) => this.onLine(line));
  }
}
