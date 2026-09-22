import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

/** Paseo compiles the plugin checkout without node_modules and only maps
 *  @getpaseo/plugin* + zod (+ the react stack on client). Any other bare
 *  import fails install-time `checkSourceImports`
 *  ("Could not resolve type dependency …"). This test locks that invariant
 *  so a regression can never reach GitHub again. */
const ROOTS = ["server", "shared", "client", "index.server.ts", "index.client.tsx"];
const ALLOWED = new Set([
  "@getpaseo/plugin",
  "@getpaseo/plugin/server",
  "@getpaseo/plugin/client",
  "zod",
  "react",
  "react-native",
  "@tanstack/react-query",
]);

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (/\.tsx?$/.test(e)) out.push(p);
  }
  return out;
}

const FROM_RE = /from\s+["']([^"']+)["']/g;
const SIDE_RE = /^\s*import\s+["']([^"']+)["']/gm;

describe("install-time import boundary", () => {
  it("no bare imports outside the daemon-mapped set", () => {
    const files = ROOTS.flatMap((r) =>
      statSync(r).isDirectory() ? sources(r) : [r],
    );
    expect(files.length).toBeGreaterThan(10);
    const violations: string[] = [];
    for (const f of files) {
      const src = readFileSync(f, "utf8");
      const specs = new Set<string>();
      for (const m of src.matchAll(FROM_RE)) specs.add(m[1]!);
      for (const m of src.matchAll(SIDE_RE)) specs.add(m[1]!);
      for (const s of specs) {
        if (s.startsWith(".") || s.startsWith("/")) continue;
        if (s.startsWith("node:")) continue; // platform builtins, externalized
        if (!ALLOWED.has(s)) violations.push(`${f} -> ${s}`);
      }
    }
    expect(violations).toEqual([]);
  });
  it("no protocol/client package references in shipped sources", () => {
    const files = ROOTS.flatMap((r) =>
      statSync(r).isDirectory() ? sources(r) : [r],
    );
    const hits = files.filter((f) =>
      /@getpaseo\/(protocol|client)/.test(readFileSync(f, "utf8")),
    );
    expect(hits).toEqual([]);
  });
  it("package.json dependencies stay install-safe (no unmappable packages)", () => {
    const pkg = JSON.parse(readFileSync("package.json", "utf8"));
    const bad = Object.keys(pkg.dependencies ?? {}).filter((k) =>
      k.startsWith("@getpaseo/"),
    );
    expect(bad).toEqual([]);
  });
});
