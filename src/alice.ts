import { decrypt, encrypt } from "./aes";
import {
  Msg, Peer, SEP, ask, askKey, connect, f, log, makeNonce, parseAddr, readMessages, requestOnce, send,
} from "./common";

class Alice extends Peer {
  pendingKs = "";
  onAuth: (() => void) | null = null;

  constructor(myId: string, masterKey: string, public bobId: string, public kdcAddr: [string, number], public bind?: string) {
    super(myId, masterKey);
  }

  async requestKdc(): Promise<{ ks: string; ticket: string }> {
    const n1 = makeNonce();
    const kdc = await connect(this.kdcAddr[0], this.kdcAddr[1], this.bind);
    log(`\n[STEP 1] ke KDC: IDA=${this.myId} IDB=${this.bobId} N1=${n1}`);
    const reply = await requestOnce(kdc, { type: "step1", ida: this.myId, idb: this.bobId, n1 });
    kdc.end();
    if (reply.type !== "step2") throw new Error(reply.reason);
    log(`[STEP 2] terima E(Ka,[Ks||IDA||IDB||N1]) = ${reply.for_a}`);
    log(`         dan E(Kb,[Ks||IDA]) = ${reply.ticket}`);
    let ks: string, ida: string, idb: string, n1Back: string;
    try {
      [ks, ida, idb, n1Back] = decrypt(reply.for_a, this.masterKey).split(SEP);
    } catch (e) {
      throw new Error(`gagal dekripsi dengan Ka: ${(e as Error).message}`);
    }
    if (n1Back !== n1 || idb !== this.bobId || ida !== this.myId) {
      throw new Error("N1/ID tidak cocok, kemungkinan replay");
    }
    log(`         Ks=${ks}, N1 cocok`);
    return { ks, ticket: reply.ticket };
  }

  async handshake(): Promise<void> {
    const { ks, ticket } = await this.requestKdc();
    this.pendingKs = ks;
    const authenticated = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Bob tidak mengonfirmasi autentikasi")), 10000);
      this.onAuth = () => {
        clearTimeout(timer);
        resolve();
      };
    });
    send(this.sock!, { type: "step3", ticket });
    log("[STEP 3] teruskan E(Kb,[Ks||IDA]) ke Bob");
    await authenticated;
  }

  handle(msg: Msg): void {
    if (msg.type === "step4") {
      log(`\n[STEP 4] terima E(Ks,N2) = ${msg.data}`);
      let n2: string;
      try {
        n2 = decrypt(msg.data, this.pendingKs);
        BigInt(n2);
      } catch (e) {
        return log(`[!] gagal dekripsi N2: ${(e as Error).message}`);
      }
      const data = encrypt(f(n2), this.pendingKs);
      send(this.sock!, { type: "step5", data });
      log(`         N2=${n2}`);
      log(`[STEP 5] kirim f(N2)=${f(n2)} -> E(Ks,f(N2)) = ${data}`);
    } else if (msg.type === "auth_ok") {
      this.sessionKey = this.pendingKs;
      this.peerId = this.bobId;
      log(`[*] Bob mengonfirmasi. Session key = ${this.sessionKey}, chat aktif`);
      this.onAuth?.();
    } else if (msg.type === "rekey_request") {
      log("\n[*] Bob meminta rekey");
      this.rekey();
    } else {
      super.handle(msg);
    }
  }

  rekey(): void {
    this.handshake().catch((e) => log(`[!] rekey gagal: ${e.message}`));
  }
}

function parseArgs(): Record<string, string> {
  const args = process.argv.slice(2);
  const out: Record<string, string> = {};
  for (let i = 0; i < args.length; i += 2) {
    if (!args[i].startsWith("--")) throw new Error(`argumen tidak dikenal: ${args[i]}`);
    out[args[i].slice(2)] = args[i + 1];
  }
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs();
  const myId = args.id || (await ask("ID Alice", "Alice"));
  const masterKey = await askKey("Master key Ka (16/24/32 char, sama dengan di KDC)");
  const bobId = args["bob-id"] || (await ask("ID Bob", "Bob"));
  const kdcAddr = parseAddr(args.kdc || (await ask("Alamat KDC", "127.0.0.1:5000")));
  const bobAddr = parseAddr(args.bob || (await ask("Alamat Bob", "127.0.0.1:6000")));

  const alice = new Alice(myId, masterKey, bobId, kdcAddr, args.bind);
  try {
    alice.sock = await connect(bobAddr[0], bobAddr[1], args.bind);
  } catch (e) {
    log(`[!] gagal terhubung ke Bob: ${(e as Error).message}`);
    process.exit(1);
  }
  log(`[*] terhubung ke Bob ${bobAddr[0]}:${bobAddr[1]}`);
  readMessages(alice.sock, (m) => alice.handle(m), () => {
    log("[!] koneksi ditutup oleh peer");
    process.exit(0);
  });
  try {
    await alice.handshake();
  } catch (e) {
    log(`[!] key distribution gagal: ${(e as Error).message}`);
    alice.sock.destroy();
    process.exit(1);
  }
  alice.startChat();
}

main();
