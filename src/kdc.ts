import * as net from "net";
import { checkKey, encrypt } from "./aes";
import { SEP, log, makeSessionKey, onLines, readMessages, send, Msg } from "./common";

const users = new Map<string, string>();

function setUser(id: string, key: string): void {
  if (id.includes(SEP)) throw new Error(`ID tidak boleh mengandung '${SEP}'`);
  checkKey(key);
  users.set(id, key);
}

function handleStep1(conn: net.Socket, msg: Msg): void {
  if (msg.type !== "step1") return send(conn, { type: "error", reason: "KDC hanya menerima step1" });
  const { ida, idb, n1 } = msg;
  log(`\n[STEP 1] dari ${conn.remoteAddress}: IDA=${ida} IDB=${idb} N1=${n1}`);
  const ka = users.get(ida);
  const kb = users.get(idb);
  if (!ka || !kb) {
    log("[!] ID tidak terdaftar");
    return send(conn, { type: "error", reason: `ID tidak terdaftar di KDC: ${ida}/${idb}` });
  }
  const ks = makeSessionKey();
  const forA = encrypt([ks, ida, idb, n1].join(SEP), ka);
  const ticket = encrypt([ks, ida].join(SEP), kb);
  send(conn, { type: "step2", for_a: forA, ticket });
  log(`[STEP 2] Ks=${ks}`);
  log(`         E(Ka,[Ks||IDA||IDB||N1]) = ${forA}`);
  log(`         E(Kb,[Ks||IDA])          = ${ticket}`);
}

function parseArgs(): { host: string; port: number; users: string[] } {
  const args = process.argv.slice(2);
  const out = { host: "0.0.0.0", port: 5000, users: [] as string[] };
  for (let i = 0; i < args.length; i += 2) {
    if (args[i] === "--host") out.host = args[i + 1];
    else if (args[i] === "--port") out.port = Number(args[i + 1]);
    else if (args[i] === "--user") out.users.push(args[i + 1]);
    else throw new Error(`argumen tidak dikenal: ${args[i]}`);
  }
  return out;
}

function main(): void {
  const args = parseArgs();
  for (const item of args.users) {
    const i = item.indexOf(":");
    try {
      setUser(item.slice(0, i), item.slice(i + 1));
    } catch (e) {
      console.error(`--user ${item}: ${(e as Error).message}`);
      process.exit(2);
    }
  }

  net
    .createServer((conn) => {
      readMessages(conn, (m) => handleStep1(conn, m), () => {});
    })
    .listen(args.port, args.host, () => log(`[*] KDC listening di ${args.host}:${args.port}`));

  log("Perintah KDC: add <ID> <key> | del <ID> | list | quit");
  onLines((line) => {
    const [cmd, id, key] = line.split(" ");
    if (cmd === "add" && id && key) {
      try {
        setUser(id, key);
        log(`[*] ${id} terdaftar`);
      } catch (e) {
        log(`[!] ${(e as Error).message}`);
      }
    } else if (cmd === "del" && id) {
      users.delete(id);
      log(`[*] ${id} dihapus`);
    } else if (cmd === "list") {
      users.forEach((k, u) => log(`  ${u}: ${k}`));
    } else if (cmd === "quit") {
      process.exit(0);
    } else if (cmd) {
      log("[!] perintah: add <ID> <key> | del <ID> | list | quit");
    }
  });
}

main();
