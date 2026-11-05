#!/usr/bin/env python3
"""8BP 56.34.0 helper. Modes: gate | recon | patch"""
import argparse, json, re, struct, sys
from pathlib import Path

RET = 0xD65F03C0
FLT = ("float", "single", "system.single")

def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def float_word(v):
    bits = struct.unpack("<I", struct.pack("<f", v))[0]
    if bits & 0xFFFF: raise ValueError(f"{v} fit nahi")
    return 0x52C00000 | (((bits >> 16) & 0xFFFF) << 5)

def dec(w):
    if (w & 0xFFE0001F) == 0x52C00000:
        i = (w >> 5) & 0xFFFF
        return f"{struct.unpack('<f', struct.pack('<I', i << 16))[0]:.4f}"
    if (w & 0x7F800000) == 0x1E200000: return "FMOV"
    if (w & 0xFF00001F) == 0x1C000000: return "LDR"
    return "?"

def cands(dump, kws, excl=()):
    out, cls, pend = [], "", None
    kwl = [k.lower() for k in kws]; exl = [e.lower() for e in excl]
    with dump.open(encoding="utf-8", errors="ignore") as f:
        for raw in f:
            s = raw.strip()
            if not s: continue
            m = re.search(r"\b(?:class|struct)\s+([A-Za-z_][\w`<>]*)", s)
            if m: cls = m.group(1)
            r = re.match(r"//\s*RVA:\s*0x[0-9A-Fa-f]+\s+Offset:\s*0x([0-9A-Fa-f]+)", s)
            if r: pend = int(r.group(1), 16); continue
            if pend is not None and not s.startswith("//"):
                off, pend = pend, None
                hay = (cls + " " + s).lower()
                if not any(k in hay for k in kwl): continue
                nm = s.split("(")[0].split()[-1]
                if any(e in (nm.lower() + s.lower()) for e in exl): continue
                if not any(t in s.lower() for t in FLT): continue
                tail = s[s.index("("):] if "(" in s else "()"
                if tail.strip("() ").replace(" ", "") not in ("", ")"): continue
                out.append({"class": cls, "sig": s, "off": off})
    return out

def sections(b):
    e = struct.unpack_from("<Q", b, 0x28)[0]; n = struct.unpack_from("<H", b, 0x3C)[0]
    sz = struct.unpack_from("<H", b, 0x3A)[0]
    t = r = (0, 0)
    for i in range(n):
        p = e + i * sz
        if u32(b, p + 4) != 1: continue
        fl = struct.unpack_from("<Q", b, p + 8)[0]
        o = struct.unpack_from("<Q", b, p + 0x18)[0]
        s = struct.unpack_from("<Q", b, p + 0x20)[0]
        if fl & 4: t = (o, o + s)
        elif fl & 2: r = (o, o + s)
    return t[0], t[1], r[0], r[1]

def xrefs(b, ts, te):
    out = {}
    for off in range(ts, max(ts, te - 20), 4):
        w = u32(b, off)
        if (w & 0x9F000000) != 0x90000000: continue
        rd = w & 0x1F
        imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
        if imm & 0x100000: imm -= 0x200000
        page = (off & ~0xFFF) + (imm << 12)
        for k in range(1, 5):
            p = off + 4 * k
            if p + 4 > te: break
            w2 = u32(b, p)
            if (w2 & 0xFF800000) != 0x91000000 or (w2 & 0x1F) != rd: continue
            out.setdefault(page + ((w2 >> 10) & 0xFFF), []).append(off)
    return out

def fstart(b, o, ts):
    for p in range(o, ts, -4):
        if u32(b, p) == RET: return p + 4
    return o

def m_gate(a):
    want = json.loads(Path(a.config).read_text()).get("version", "")
    m = re.search(r"versionName:\s*'?([0-9][\w.\-]*)'?", Path(a.yml).read_text(errors="ignore"))
    have = m.group(1) if m else "unknown"
    print(f"chahiye={want} mila={have}")
    if want and have != want and not a.allow: sys.exit("[!] version mismatch")
    print("[+] ok")

def m_recon(a):
    cfg = json.loads(Path(a.config).read_text())
    out = ["# RECON REPORT", ""]
    if a.dump.exists() and a.dump.stat().st_size > 1024:
        h = cands(a.dump, cfg["keywords"])
        out += ["## Asli candidates", "", "| class | method | offset |", "|---|---|---|"]
        for c in h: out.append(f"| {c['class']} | {c['sig'][:60]} | 0x{c['off']:x} |")
        out.append(f"\n**{len(h)} mile**\n")
        if h:
            out.append("### config.json me ye daalo:\n```json\n\"targets\": [")
            for c in h[:4]: out.append(f'  {{ "class": "{c["class"]}", "method": "{c["sig"].split("(")[0].split()[-1]}", "offset": "0x{c["off"]:x}" }},')
            out.append("]\n```")
    else:
        out.append("## dump.cs nahi mila (metadata protected)")
    b = (a.app / "lib/arm64-v8a/libil2cpp.so").read_bytes()
    ts, te, rs, re_ = sections(b)
    xr = xrefs(b, ts, te); n = 0
    out += ["", "## String xref (dump fail hua to ye use karo)"]
    for kw in cfg["keywords"]:
        i = rs
        while True:
            i = b.find(kw.encode(), i, re_ or len(b))
            if i < 0: break
            for c in xr.get(i, [])[:2]:
                out.append(f"- `{kw}` -> offset `0x{fstart(b, c, ts):x}`"); n += 1
            i += 1
    out.append(f"\n**{n} xref**")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    txt = "\n".join(out); a.out.write_text(txt); print(txt)
    Path("dist/summary.md").write_text(txt)

def m_patch(a):
    cfg = json.loads(Path(a.config).read_text())
    so = a.app / "lib/arm64-v8a/libil2cpp.so"
    if not so.exists(): sys.exit("[!] libil2cpp.so nahi mila")
    blob = bytearray(so.read_bytes()); log = ["# PATCH REPORT", ""]; done = 0
    for t in cfg.get("targets", []):
        off = t.get("offset")
        if not off:
            hit = [c for c in cands(a.dump, [t["method"]]) if c["class"].lower() == t["class"].lower()]
            if not hit: log.append(f"- MISS {t['class']}.{t['method']}"); continue
            off = hit[0]["off"]
        o = int(off, 16)
        if o + 8 > len(blob): log.append(f"- OOB 0x{o:x}"); continue
        old = dec(u32(blob, o))
        struct.pack_into("<II", blob, o, float_word(float(a.scale)), RET)
        log.append(f"- PATCH 0x{o:x} ({t.get('class')}.{t.get('method')}) orig={old}"); done += 1
    if not cfg.get("targets"):
        log.append("targets khaali -> keyword fallback")
        for c in cands(a.dump, cfg["keywords"], cfg.get("exclude", []))[:10]:
            o = c["off"]
            if o + 8 > len(blob) or u32(blob, o + 4) != RET: continue
            struct.pack_into("<II", blob, o, float_word(float(a.scale)), RET)
            log.append(f"- PATCH 0x{o:x} ({c['sig'][:50]})"); done += 1
    log.append(f"\n**Total {done}**")
    a.report.parent.mkdir(parents=True, exist_ok=True)
    txt = "\n".join(log); a.report.write_text(txt); print(txt)
    Path("dist/summary.md").write_text(txt)
    if done: so.write_bytes(blob)
    else: sys.exit("[!] 0 patch")

p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="m", required=True)
g = sub.add_parser("gate"); g.add_argument("--yml", required=True); g.add_argument("--config", default="patcher/config.json"); g.add_argument("--allow", action="store_true"); g.set_defaults(f=m_gate)
r = sub.add_parser("recon"); r.add_argument("--app", type=Path, required=True); r.add_argument("--dump", type=Path, default=Path("work/dump/dump.cs")); r.add_argument("--config", default="patcher/config.json"); r.add_argument("--out", type=Path, default=Path("dist/recon.md")); r.set_defaults(f=m_recon)
x = sub.add_parser("patch"); x.add_argument("--app", type=Path, required=True); x.add_argument("--dump", type=Path, default=Path("work/dump/dump.cs")); x.add_argument("--config", default="patcher/config.json"); x.add_argument("--scale", default="1.0"); x.add_argument("--report", type=Path, default=Path("dist/patch-report.md")); x.set_defaults(f=m_patch)
a = p.parse_args(); a.f(a)
