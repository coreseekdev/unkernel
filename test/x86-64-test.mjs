// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Pooya Parsa <pooya@pi0.io>
// Run the static x86-64 guests through the x86-64 kwemu harness and compare
// their output and exit status with qemu-x86_64 (when it is on PATH) and with
// the expected output recorded here.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const prefix = process.argv[2] ?? "zig-out";
const harness = join(prefix, "bin", "kwemu-harness-x86");
const guestDir = join(prefix, "guest", "x86_64");

const guests = [
  { name: "hello", expected: "hello x86_64\nargc=1\nHOME=/\n" },
  { name: "inttest", expected: "hash=e49dd49b310c518\nint ok\n" },
  { name: "fptest", expected: "fp ok\n" },
  { name: "sse2test", expected: "sse2 ok\n" },
  { name: "strtest", expected: "str ok\n" },
];

function hasQemu() {
  const r = spawnSync("sh", ["-c", "command -v qemu-x86_64"], { encoding: "utf8" });
  return r.status === 0 && r.stdout.trim() !== "";
}

function run(cmd, args, env = process.env) {
  const r = spawnSync(cmd, args, { encoding: "utf8", timeout: 120000, env });
  return { out: r.stdout ?? "", err: r.stderr ?? "", status: r.status, signal: r.signal };
}

// What the harness puts in the guest's environment; qemu-x86_64 inherits
// its own environment otherwise, and guests that read HOME differ.
const guestEnv = { HOME: "/", PATH: "/bin", TERM: "dumb" };

const qemu = hasQemu();
let failed = 0;

// The wasm64 interpreter (the browser backend's CPU object) runs the same
// guests through the harness's kwh_run entry.
const wasmPath = join(prefix, "x86_64", "kwemu-harness.wasm");
let wasmModule = null;
if (existsSync(wasmPath)) {
  wasmModule = await WebAssembly.compile(await readFile(wasmPath));
  const bad = WebAssembly.Module.imports(wasmModule).filter((i) => i.kind === "function" && i.module !== "env");
  if (bad.length) {
    console.error(`x86_64 wasm harness imports functions: ${bad.map((i) => i.name).join(", ")}`);
    failed++;
  }
} else console.log(`x86_64: ${wasmPath} not built; wasm64 runs skipped`);

async function runWasm(elf) {
  let out = "";
  let err = "";
  let mem;
  const dec = new TextDecoder();
  const imports = {
    env: {
      host_write: (fd, ptr, len) => {
        const s = dec.decode(new Uint8Array(mem.buffer, Number(ptr), Number(len)));
        if (fd === 2) err += s;
        else out += s;
      },
      host_now_ns: () => Number(process.hrtime.bigint()),
    },
  };
  const instance = await WebAssembly.instantiate(wasmModule, imports);
  const ex = instance.exports;
  mem = ex.memory;
  const image = await readFile(elf);
  const argBytes = new TextEncoder().encode(elf + "\0");
  const total = image.length + argBytes.length;
  const ptr = Number(ex.kwh_buf(BigInt(total)));
  if (!ptr) return { status: -1, out: "", err: "kwh_buf failed" };
  const view = new Uint8Array(mem.buffer, ptr, total);
  view.set(image, 0);
  view.set(argBytes, image.length);
  const status = ex.kwh_run(BigInt(image.length), BigInt(argBytes.length), 0);
  return { status, out, err };
}
for (const g of guests) {
  const elf = join(guestDir, `${g.name}.elf`);
  if (!existsSync(elf)) {
    console.error(`missing guest ${elf}; run zig build first`);
    failed++;
    continue;
  }
  const got = run(harness, [elf]);
  let ok = got.status === 0 && got.out === g.expected;
  let why = "";
  if (!ok) {
    why = `harness status=${got.status}${got.signal ? ` signal=${got.signal}` : ""}\n--- output ---\n${got.out}--- stderr ---\n${got.err}`;
  }
  if (ok && wasmModule) {
    const w = await runWasm(elf);
    if (w.status !== got.status || w.out !== got.out) {
      ok = false;
      why += `\n--- wasm64 differs (status ${w.status}) ---\n${w.out}${w.err}`;
    }
  }
  if (qemu) {
    const ref = run("qemu-x86_64", [elf], guestEnv);
    if (ref.status !== got.status || ref.out !== got.out) {
      ok = false;
      why += `\n--- qemu-x86_64 differs (status ${ref.status}) ---\n${ref.out}${ref.err}`;
    }
  }
  if (ok) console.log(`x86_64 guest ${g.name}: ok${wasmModule ? " (native and wasm64)" : ""}${qemu ? ", matches qemu-x86_64" : ""}`);
  else {
    console.error(`x86_64 guest ${g.name}: FAILED\n${why}`);
    failed++;
  }
}
if (!qemu) console.log("x86_64: qemu-x86_64 not on PATH; compared with the expected outputs only");
process.exit(failed === 0 ? 0 : 1);
