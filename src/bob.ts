import * as net from "net";
import { decrypt, encrypt } from "./aes";
import { Msg, Peer, SEP, ask, askKey, f, log, makeNonce, readMessages, send } from "./common";

class Bob extends Peer {
  pending: { ks: string; ida: string; n2: string } | null = null;

  handle(msg: Msg): void {
    if (msg.type === "step3") this.onStep3(msg.ticket);
    else if (msg.type === "step5") this.onStep5(msg.data);
    else super.handle(msg);
  }

  onStep3(ticket: string): void {
    log(`\n[STEP 3] terima E(Kb,[Ks||IDA]) = ${ticket}`);
    let ks: string, ida: string;
    try {
      [ks, ida] = decrypt(ticket, this.masterKey).split(SEP);
      if (!ks || !ida) throw new Error("format tiket salah");
    } catch (e) {
      log(`[!] ticket gagal didekripsi dengan Kb: ${(e as Error).message}`);
      return send(this.sock!, { type: "error", reason: "ticket tidak valid untuk Bob" });
    }
    const n2 = makeNonce();
    this.pending = { ks, ida, n2 };
    const data = encrypt(n2, ks);
    send(this.sock!, { type: "step4", data });
    log(`         Ks=${ks} IDA=${ida}`);
    log(`[STEP 4] kirim N2=${n2} -> E(Ks,N2) = ${data}`);
  }

  onStep5(data: string): void {
    log(`\n[STEP 5] terima E(Ks,f(N2)) = ${data}`);
    if (!this.pending) return;
    const { ks, ida, n2 } = this.pending;
    let ok = false;
    try {
      ok = decrypt(data, ks) === f(n2);
    } catch {}
    if (!ok) {
      log("[!] f(N2) tidak cocok, autentikasi gagal");
      return send(this.sock!, { type: "error", reason: "f(N2) tidak cocok" });
    }
    this.sessionKey = ks;
    this.peerId = ida;
    this.pending = null;
    send(this.sock!, { type: "auth_ok" });
    log(`         f(N2)=${f(n2)} cocok, ${ida} terautentikasi. Session key = ${ks}`);
    log("[*] chat aktif");
  }

  rekey(): void {
    if (this.sock) send(this.sock, { type: "rekey_request" });
    log("[*] minta Alice melakukan rekey");
  }
}

function parseArgs(): { host: string; port: number; id?: string } {
  const args = process.argv.slice(2);
  const out: { host: string; port: number; id?: string } = { host: "0.0.0.0", port: 6000 };
  for (let i = 0; i < args.length; i += 2) {
    if (args[i] === "--host") out.host = args[i + 1];
    else if (args[i] === "--port") out.port = Number(args[i + 1]);
    else if (args[i] === "--id") out.id = args[i + 1];
    else throw new Error(`argumen tidak dikenal: ${args[i]}`);
  }
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs();
  const myId = args.id || (await ask("ID Bob", "Bob"));
  const bob = new Bob(myId, await askKey("Master key Kb (16/24/32 char, sama dengan di KDC)"));

  net
    .createServer((conn) => {
      if (bob.sock) {
        conn.destroy();
        return;
      }
      log(`[*] koneksi dari ${conn.remoteAddress}:${conn.remotePort}`);
      bob.sock = conn;
      bob.sessionKey = "";
      bob.pending = null;
      bob.startChat();
      readMessages(conn, (m) => bob.handle(m), () => {
        log("[!] koneksi ditutup oleh peer");
        bob.sock = null;
        log(`[*] ${myId} menunggu koneksi di ${args.host}:${args.port}`);
      });
    })
    .listen(args.port, args.host, () => log(`[*] ${myId} menunggu koneksi di ${args.host}:${args.port}`));
}

main();
