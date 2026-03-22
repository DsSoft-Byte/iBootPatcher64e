#!/usr/bin/env python3
"""
iBoot arm64e patcher - dynamic version
Confirmed working on: 9275 (10151.2.12), d38, iOS 17.0 (21A350), CPFM 0x00

Dynamically searches for patch sites rather than using hardcoded offsets.
Will prompt user for confirmation on any patch site it is unsure about.

Usage:
    python3 iboot_patcher_dynamic.py <input.raw> <output.raw> [-b "boot-args"] [-y]

    -y / --yes   auto-confirm all prompts (non-interactive mode)

Decrypt first with img4tool:
    img4tool -e --iv <iv> --key <key> -o iBSS.raw iBSS.d38.RELEASE.im4p
"""

import sys
import struct
import argparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PACIBSP   = 0xd503237f
RETAB     = 0xd65f0fff
RET       = 0xd65f03c0
NOP       = 0xd503201f
MAX_BOOTARGS = 270

# Known image type strings across iBoot versions.
# Key = substring used to find it, value = human description.
# Add new entries here as new versions are discovered.
IMAGE_TYPE_STRINGS = [
    # 9275 / iOS 17 (mpla insertion)
    b'cebilefciladmplarmmhtreptlhptmbr',
    # iOS 14-16
    b'cebilefciladrmmhtreptlhptmbr',
    # iOS 10-13
    b'cebilefctmbrtlhptreprmmh',
]

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def r32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]

def w32(buf, off, val):
    struct.pack_into('<I', buf, off, val)

def is_pacibsp(op):  return op == PACIBSP
def is_bl(op):       return (op & 0xfc000000) == 0x94000000
def is_blr(op):      return (op & 0xfe1f0000) == 0xd61f0000
def is_adrp(op):     return (op & 0x9f000000) == 0x90000000
def is_adr(op):      return (op & 0x9f000000) == 0x10000000
def is_add_imm(op):  return (op & 0xff000000) == 0x91000000
def is_cbz(op):      return (op & 0x7e000000) == 0x34000000
def is_ret_like(op): return op in (RET, RETAB, 0xd65f0bff, 0xd65f0fff)

def decode_adrp(pc, op):
    immlo = (op >> 29) & 0x3
    immhi = (op >>  5) & 0x7ffff
    imm   = ((immhi << 2) | immlo) << 12
    if imm & (1 << 32): imm -= (1 << 33)
    return (pc & ~0xfff) + imm

def decode_add_imm(op):
    shift = (op >> 22) & 0x3
    imm   = (op >> 10) & 0xfff
    if shift == 1: imm <<= 12
    return imm

def decode_adr(pc, op):
    immlo = (op >> 29) & 0x3
    immhi = (op >>  5) & 0x7ffff
    imm   = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= (1 << 21)
    return pc + imm

def build_adr(pc, target, rd):
    diff  = target - pc
    if abs(diff) >= (1 << 20):
        raise ValueError(f"ADR out of range: diff={diff:#x}")
    immlo = diff & 0x3
    immhi = (diff >> 2) & 0x7ffff
    op    = (immlo << 29) | (0x10 << 24) | (immhi << 5) | rd
    assert decode_adr(pc, op) == target
    return op

def find_cbz_before(buf, start, window=80):
    for i in range(1, window):
        off = start - i * 4
        if off < 0: break
        op = r32(buf, off)
        if is_cbz(op):
            return off
    return None

def cbz_branch_target(buf, off):
    op     = r32(buf, off)
    offset = (op >> 5) & 0x7ffff
    if offset & 0x40000: offset |= ~0x7ffff
    return off + offset * 4

def find_zero_region(buf, size=270):
    idx = bytes(buf).find(b'\x00' * (size + 0x10))
    if idx == -1:
        raise RuntimeError("no zero region found for boot-args")
    return idx + 0x10

def count_bl_forward(buf, start, n):
    pos, found = start, 0
    while found < n:
        pos += 4
        if pos + 4 > len(buf):
            raise RuntimeError(f"ran off buffer looking for BL #{n}")
        if is_bl(r32(buf, pos)):
            found += 1
    return pos

def bof64(buf, start, where):
    pos = where
    while pos >= start:
        op = r32(buf, pos)
        if (op & 0xffc003ff) == 0x910003fd:
            delta = (op >> 10) & 0xfff
            if (delta & 0xf) == 0:
                prev = pos - ((delta >> 4) + 1) * 4
                if prev >= 0 and (r32(buf, prev) & 0xffc003e0) == 0xa98003e0:
                    return prev
                p2 = pos
                while p2 > start:
                    p2 -= 4
                    au = r32(buf, p2)
                    if ((au & 0xffc003ff) == 0xd10003ff and
                            ((au >> 10) & 0xfff) == delta + 0x10):
                        return p2
                    if (au & 0xffc003e0) != 0xa90003e0:
                        break
        pos -= 4
    return 0

# ---------------------------------------------------------------------------
# ADRP+ADD xref scanner
# ---------------------------------------------------------------------------

def find_adrp_add_xrefs(buf, target_off):
    page   = target_off & ~0xfff
    pg_off = target_off &  0xfff
    hits   = []
    for i in range(0, len(buf) - 8, 4):
        op = r32(buf, i)
        if is_adrp(op):
            if decode_adrp(i, op) == page:
                op2 = r32(buf, i + 4)
                if is_add_imm(op2) and decode_add_imm(op2) == pg_off:
                    hits.append(i)
    return hits

# ---------------------------------------------------------------------------
# Interactive confirm
# ---------------------------------------------------------------------------

def confirm(prompt, auto_yes):
    if auto_yes:
        print(f"  [AUTO-YES] {prompt}")
        return True
    while True:
        ans = input(f"  {prompt} [y/n]: ").strip().lower()
        if ans in ('y', 'yes'): return True
        if ans in ('n', 'no'):  return False

# ---------------------------------------------------------------------------
# Dynamic finders
# ---------------------------------------------------------------------------

def detect_pac(buf):
    return bytes(buf).find(struct.pack('<I', PACIBSP)) != -1

def detect_version(buf):
    idx = bytes(buf).find(b'iBoot-')
    if idx == -1:
        return None, None
    raw = bytes(buf[idx:idx+30]).split(b'\x00')[0].decode(errors='replace')
    # raw like 'iBoot-10151.2.12' -> version int from first number component
    try:
        ver_int = int(raw.split('-')[1].split('.')[0])
    except Exception:
        ver_int = 0
    return raw, ver_int

def detect_base(buf):
    # Try 0x318 first (newer), fall back to 0x300
    for off in (0x318, 0x300):
        val = struct.unpack_from('<Q', buf, off)[0]
        if 0x100000000 < val < 0x300000000:
            return val, off
    return 0, 0

def find_sig_check_fn(buf, paced):
    """
    Locate _image4_validate_property_cb_interposer dynamically.

    Strategy:
      1. Find 'movk w0, #0x4353, lsl #16' (0x72a86a60) which is a stable
         instruction inside the function body across versions.
      2. Walk forward to the first BR/BLR (indirect call/jump) -- that's
         the end of the dispatch block.
      3. bof64 backwards from there to get the function start.
      4. Confirm PACIBSP (arm64e) or plain prologue precedes it.
    """
    NEEDLE = struct.pack('<I', 0x72a86a60)   # movk w0, #0x4353, lsl #16
    idx = bytes(buf).find(NEEDLE)
    if idx == -1:
        return None, "movk needle not found"

    # Walk forward to BR/BLR
    pos = idx
    for _ in range(200):
        pos += 4
        op = r32(buf, pos)
        if is_blr(op) or is_ret_like(op):
            break
    else:
        return None, "BR/BLR not found after needle"

    fn = bof64(buf, 0, pos)
    if fn == 0:
        return None, "bof64 failed"

    return fn, None

def find_kernel_debug_bl(buf, paced, ver_int):
    """
    Find the BL to _security_allow_modes by walking forward from the
    xref to the 'debug-enabled' string.

    pac_set(6723, 5, 2): if version==6723 AND paced -> 5 BLs, else 2 BLs.
    """
    debug_off = bytes(buf).find(b'debug-enabled')
    if debug_off == -1:
        return None, None, "debug-enabled string not found"

    xrefs = find_adrp_add_xrefs(buf, debug_off)
    if not xrefs:
        return None, None, "no xref to debug-enabled"

    bl_count = 5 if (ver_int == 6723 and paced) else 2
    try:
        bl_off = count_bl_forward(buf, xrefs[0], bl_count)
    except RuntimeError as e:
        return None, None, str(e)

    return bl_off, xrefs[0], None

def find_bootargs_sites(buf, ver_int):
    """
    Find boot-args ADRP xref and the CBZ fallback path.
    Tries 'rd=md0' (>= 6723), then older strings.
    """
    candidates = [b'rd=md0\x00', b'rd=md0 nand-enable-reformat=1 -progress', b'is-tethered']
    ba_off = None
    for c in candidates:
        idx = bytes(buf).find(c)
        if idx != -1:
            ba_off = idx
            break
    if ba_off is None:
        return None, None, None, "boot-args string not found"

    xrefs = find_adrp_add_xrefs(buf, ba_off)
    if not xrefs:
        return None, None, None, "no xref to boot-args string"

    xref = xrefs[0]
    cbz_off = find_cbz_before(buf, xref) if ver_int >= 3406 else None
    cbz_tgt = cbz_branch_target(buf, cbz_off) if cbz_off else None

    return xref, cbz_off, cbz_tgt, None

def find_image_type_sites(buf):
    """
    Dynamically find the image type string (handles version differences)
    and return the xref sites and count variable location.
    """
    str_off  = None
    str_used = None
    for s in IMAGE_TYPE_STRINGS:
        idx = bytes(buf).find(s)
        if idx != -1:
            str_off  = idx
            str_used = s
            break

    if str_off is None:
        return None, None, None, \
            "image type string not found (unknown iBoot version?)"

    xrefs = find_adrp_add_xrefs(buf, str_off)
    if not xrefs:
        return None, None, str_used, "no xref to image type string"

    # Count variable: MOVZ Wrd, #nonzero near a known pattern
    # Search for any MOVZ W*, #N (N > 0) within 0x100 bytes of the last xref
    # More robust: scan entire binary for MOVZ W6/W5/W4, #small_nonzero
    COUNT_NEEDLES = [
        struct.pack('<I', 0x528000e6),  # MOVZ W6, #7  (9275)
        struct.pack('<I', 0xe5071f32),  # ORR W5, WZR, #7 (older)
        struct.pack('<I', 0xe60b0032),  # ORR W6, WZR, ...
    ]
    cnt_off = None
    for needle in COUNT_NEEDLES:
        idx = bytes(buf).find(needle)
        if idx != -1:
            cnt_off = idx
            break

    return xrefs, cnt_off, str_used, None

# ---------------------------------------------------------------------------
# Patch applicators
# ---------------------------------------------------------------------------

def apply_sig_check(buf, fn, paced, base, auto_yes):
    retx = RETAB if paced else RET
    ret_name = "RETAB" if paced else "RET"

    print(f"\n[Patch 1] Signature check bypass")
    print(f"  Function start : {base+fn:#x}")
    print(f"  Current insns  : {r32(buf,fn):#010x}  {r32(buf,fn+4):#010x}")
    print(f"  Will write     : MOVZ X0,#0 ({MOVZ_X0_0:#010x})  {ret_name} ({retx:#010x})")

    # Check PACIBSP consistency
    if paced and r32(buf, fn - 4) != PACIBSP:
        print(f"  [WARN] expected PACIBSP at {base+fn-4:#x}, got {r32(buf,fn-4):#010x}")

    if not confirm("Apply signature check patch?", auto_yes):
        print("  Skipped.")
        return False

    w32(buf, fn,     MOVZ_X0_0)
    w32(buf, fn + 4, retx)
    print(f"  Applied.")
    return True

MOVZ_X0_0 = 0xd2800000
MOVZ_X0_1 = 0xd2800020

def apply_kernel_debug(buf, bl_off, base, auto_yes):
    print(f"\n[Patch 2] Kernel debug enable (_security_allow_modes)")
    print(f"  BL location    : {base+bl_off:#x}")
    print(f"  Current insn   : {r32(buf,bl_off):#010x}")
    print(f"  Will write     : MOVZ X0,#1 ({MOVZ_X0_1:#010x})")

    if not confirm("Apply kernel debug patch?", auto_yes):
        print("  Skipped.")
        return False

    w32(buf, bl_off, MOVZ_X0_1)
    print(f"  Applied.")
    return True

def apply_bootargs(buf, xref, cbz_off, cbz_tgt, bootargs_str, base, auto_yes):
    ba_bytes = bootargs_str.encode() + b'\x00'
    if len(ba_bytes) > MAX_BOOTARGS:
        raise ValueError(f"boot-args too long ({len(ba_bytes)} > {MAX_BOOTARGS})")

    new_off = find_zero_region(buf)
    rd      = r32(buf, xref) & 0x1f

    print(f"\n[Patch 3] Boot-args redirect")
    print(f"  Main ADRP      : {base+xref:#x}  (X{rd})")
    if cbz_tgt:
        print(f"  CBZ fallback   : {base+cbz_tgt:#x}")
    print(f"  New ba region  : {base+new_off:#x}")
    print(f"  Boot-args      : \"{bootargs_str}\"")
    print(f"  Current insns  : {r32(buf,xref):#010x}  {r32(buf,xref+4):#010x}")
    print(f"  Will write     : ADR X{rd} + NOP")

    if not confirm("Apply boot-args patch?", auto_yes):
        print("  Skipped.")
        return False

    w32(buf, xref,     build_adr(xref, new_off, rd))
    w32(buf, xref + 4, NOP)

    if cbz_tgt:
        cbz_rd = r32(buf, cbz_tgt) & 0x1f
        w32(buf, cbz_tgt, build_adr(cbz_tgt, new_off, cbz_rd))
        print(f"  CBZ path patched: ADR X{cbz_rd} @ {base+cbz_tgt:#x}")

    buf[new_off:new_off + len(ba_bytes)] = ba_bytes
    print(f"  Applied.")
    return True

def apply_image_type(buf, xrefs, cnt_off, str_used, base, auto_yes):
    print(f"\n[Patch 4] Allow any image type")
    print(f"  String found   : {str_used}")
    print(f"  Xref count     : {len(xrefs)}")
    for i, h in enumerate(xrefs):
        rd = r32(buf, h) & 0x1f
        print(f"  Xref {i+1}         : {base+h:#x}  ADRP X{rd}  -> will MOVZ X{rd},#0 + NOP + NOP")
    if cnt_off:
        cnt_rd = r32(buf, cnt_off) & 0x1f
        print(f"  Count var      : {base+cnt_off:#x}  -> MOVZ W{cnt_rd},#0")
    else:
        print(f"  Count var      : not found (will skip)")

    if not confirm("Apply image type patch?", auto_yes):
        print("  Skipped.")
        return False

    for i, h in enumerate(xrefs):
        rd = r32(buf, h) & 0x1f
        w32(buf, h,     0xd2800000 | rd)
        w32(buf, h + 4, NOP)
        w32(buf, h + 8, NOP)
        print(f"  Xref {i+1} patched: MOVZ X{rd},#0 @ {base+h:#x}")

    if cnt_off:
        cnt_rd = r32(buf, cnt_off) & 0x1f
        w32(buf, cnt_off, 0x52800000 | cnt_rd)
        print(f"  Count patched : MOVZ W{cnt_rd},#0 @ {base+cnt_off:#x}")

    print(f"  Applied.")
    return True

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="iBoot arm64e dynamic patcher")
    ap.add_argument("input",  help="decrypted raw iBoot binary")
    ap.add_argument("output", help="output patched binary")
    ap.add_argument("-b", "--boot-args", default=None,
                    help="custom boot-args string")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="auto-confirm all patches (non-interactive)")
    args = ap.parse_args()

    with open(args.input, 'rb') as f:
        buf = bytearray(f.read())

    print("=" * 60)
    print("iBoot arm64e dynamic patcher")
    print("=" * 60)
    print(f"Input : {args.input} ({len(buf):#x} bytes)")

    # Detect metadata
    ver_str, ver_int = detect_version(buf)
    base, base_off   = detect_base(buf)
    paced            = detect_pac(buf)

    print(f"Version : {ver_str or 'unknown'}  (int={ver_int})")
    print(f"Base    : {base:#x}  (from offset {base_off:#x})")
    print(f"arm64e  : {'YES (PACIBSP found)' if paced else 'NO (no PACIBSP)'}")
    print()

    # --- Find all patch sites ---
    errors = []

    fn, err = find_sig_check_fn(buf, paced)
    if err: errors.append(f"Sig check: {err}")

    bl_off, _, err = find_kernel_debug_bl(buf, paced, ver_int)
    if err: errors.append(f"Kernel debug: {err}")

    xref_ba, cbz_off, cbz_tgt, err = find_bootargs_sites(buf, ver_int)
    if err: errors.append(f"Boot-args: {err}")

    xrefs_it, cnt_off, str_used, err = find_image_type_sites(buf)
    if err: errors.append(f"Image type: {err}")

    if errors:
        print("[WARNINGS] Some patch sites could not be found:")
        for e in errors: print(f"  - {e}")
        print()

    if not any([fn, bl_off, xref_ba, xrefs_it]):
        print("No patch sites found at all -- wrong binary?")
        sys.exit(1)

    # --- Apply patches interactively ---
    applied = []

    if fn is not None:
        if apply_sig_check(buf, fn, paced, base, args.yes):
            applied.append("sig_check")

    if bl_off is not None:
        if apply_kernel_debug(buf, bl_off, base, args.yes):
            applied.append("kernel_debug")

    if xref_ba is not None and args.boot_args:
        if apply_bootargs(buf, xref_ba, cbz_off, cbz_tgt,
                          args.boot_args, base, args.yes):
            applied.append("boot_args")
    elif args.boot_args is None:
        print("\n[Patch 3] Boot-args: skipped (no -b provided)")

    if xrefs_it is not None:
        if apply_image_type(buf, xrefs_it, cnt_off, str_used, base, args.yes):
            applied.append("image_type")

    # --- Write output ---
    print(f"\n{'='*60}")
    print(f"Patches applied : {', '.join(applied) if applied else 'none'}")

    if not applied:
        print("Nothing to write.")
        sys.exit(0)

    with open(args.output, 'wb') as f:
        f.write(buf)
    print(f"Output written  : {args.output}")
    print("Done.")

if __name__ == "__main__":
    main()
