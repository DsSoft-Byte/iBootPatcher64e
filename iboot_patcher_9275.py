#!/usr/bin/env python3
"""
iBoot 9275 (10151.2.12) arm64e patcher
Targets: iPhone 15 Plus (d38) iOS 17.0 (21A350)
Patches: sig check, kernel debug, boot-args, allow any image type

Confirmed working on dev-fused (CPFM 0x00) units.
Input must be decrypted raw iBoot binary (use img4tool -e first).
Output is a raw binary ready to be repackaged with img4tool -c.

Usage:
    python3 iboot_patcher_9275.py <input.raw> <output.raw> -b "your boot-args"

    # Decrypt first:
    img4tool -e --iv <iv> --key <key> -o iBSS.raw iBSS.d38.RELEASE.im4p
    img4tool -e --iv <iv> --key <key> -o iBEC.raw iBEC.d38.RELEASE.im4p

    # Patch:
    python3 iboot_patcher_9275.py iBSS.raw iBSS_patched.raw -b "wdt=-1 serial=3 cs_enforcement_disable=1 amfi_get_out_of_my_way=1 amfi=-1 -v rd=md0 debug=0x2014e"
    python3 iboot_patcher_9275.py iBEC.raw iBEC_patched.raw -b "wdt=-1 serial=3 cs_enforcement_disable=1 amfi_get_out_of_my_way=1 amfi=-1 -v rd=md0 debug=0x2014e"

    # Repackage:
    img4tool -c iBSS_patched.im4p -t ibss iBSS_patched.raw
    img4tool -c iBEC_patched.im4p -t ibec iBEC_patched.raw
"""

import sys
import struct
import shutil
import argparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IBOOT_VERSION   = "10151.2.12"
IBOOT_BASE      = 0x1fc28c000
EXPECTED_SIZE   = 0x26ea68
MAX_BOOTARGS    = 270

PACIBSP         = 0xd503237f
RETAB           = 0xd65f0fff
NOP             = 0xd503201f
MOVZ_X0_0       = 0xd2800000
MOVZ_X0_1       = 0xd2800020

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def r32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]

def w32(buf, off, val):
    struct.pack_into('<I', buf, off, val)

def find_adrp_add_xref(buf, target_off):
    """Scan for ADRP+ADD pair that resolves to target_off."""
    page    = target_off & ~0xfff
    pg_off  = target_off &  0xfff
    hits    = []
    for i in range(0, len(buf) - 8, 4):
        op = r32(buf, i)
        if (op & 0x9f000000) == 0x90000000:
            immlo = (op >> 29) & 0x3
            immhi = (op >>  5) & 0x7ffff
            imm   = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm -= (1 << 33)
            if (i & ~0xfff) + imm == page:
                op2 = r32(buf, i + 4)
                if (op2 & 0xffc00000) == 0x91000000:
                    if (op2 >> 10) & 0xfff == pg_off:
                        hits.append(i)
    return hits

def count_bl_forward(buf, start, n):
    """Return offset of the nth BL instruction after start."""
    pos   = start
    found = 0
    while found < n:
        pos += 4
        if pos + 4 > len(buf):
            raise ValueError(f"ran off end of buffer looking for BL #{n}")
        if (r32(buf, pos) & 0xfc000000) == 0x94000000:
            found += 1
    return pos

def bof64(buf, start, where):
    """Walk backwards to find the beginning of a function."""
    pos = where
    while pos >= start:
        op = r32(buf, pos)
        if (op & 0xffc003ff) == 0x910003fd:
            delta = (op >> 10) & 0xfff
            if (delta & 0xf) == 0:
                prev = pos - ((delta >> 4) + 1) * 4
                if prev >= 0:
                    au = r32(buf, prev)
                    if (au & 0xffc003e0) == 0xa98003e0:
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

def find_cbz_before(buf, start, window=80):
    """Find the nearest CBZ/CBNZ before start within window instructions."""
    for i in range(1, window):
        off = start - i * 4
        if off < 0:
            break
        op = r32(buf, off)
        if (op & 0x7e000000) == 0x34000000:
            return off
    return None

def cbz_target(buf, off):
    op     = r32(buf, off)
    offset = (op >> 5) & 0x7ffff
    if offset & 0x40000:
        offset |= ~0x7ffff
    return off + offset * 4

def build_adr(pc_off, target_off, rd):
    diff  = target_off - pc_off
    immlo = diff & 0x3
    immhi = (diff >> 2) & 0x7ffff
    op    = (immlo << 29) | (0x10 << 24) | (immhi << 5) | rd
    # Verify decode
    dl = (op >> 29) & 0x3
    dh = (op >>  5) & 0x7ffff
    d  = (dh << 2) | dl
    if d & (1 << 20):
        d -= (1 << 21)
    assert pc_off + d == target_off, \
        f"ADR encode mismatch: {pc_off+d:#x} != {target_off:#x}"
    return op

def find_zero_region(buf, size=270):
    """Find a run of at least size+0x10 zero bytes."""
    needle = b'\x00' * size
    idx    = bytes(buf).find(needle)
    if idx == -1:
        raise RuntimeError("no suitable zero region found for boot-args")
    return idx + 0x10

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

EXPECTED_MAGIC = {
    0x2e6b8: 0xd103c3ff,   # sig check fn start
    0x2e6bc: 0xa9096ffc,   # sig check fn+4
    0x306d8: 0x9400093a,   # BL _security_allow_modes
    0x36fd0: 0xb0000a02,   # ADRP boot-args main
    0x36fd4: 0x9108ec42,   # ADD  boot-args main
    0x3703c: 0xf00009f9,   # ADRP boot-args cbz path
    0x25d0:  0xd0000bc8,   # ADRP image type
    0x25d4:  0x9114a108,   # ADD  image type 1
    0x25d8:  0x91008109,   # ADD  image type 2
    0x277c:  0xd0000bc9,   # ADRP image type alt path
    0x40b68: 0x528000e6,   # count var
}

def verify_pre(buf):
    ok = True
    for off, expected in EXPECTED_MAGIC.items():
        got = r32(buf, off)
        if got != expected:
            print(f"  [MISMATCH] @ {off:#x}: got {got:#010x}, expected {expected:#010x}")
            ok = False
    return ok

# ---------------------------------------------------------------------------
# Patches
# ---------------------------------------------------------------------------

def patch_sig_check(buf):
    """
    Patch _image4_validate_property_cb_interposer to return 0 immediately.
    Function is arm64e (PACIBSP at fn-4), so we use RETAB not RET.
    """
    # Confirmed: PACIBSP at 0x2e6b4, function body at 0x2e6b8
    fn = 0x2e6b8
    assert r32(buf, fn - 4) == PACIBSP, "PACIBSP not found before sig check fn"
    w32(buf, fn,     MOVZ_X0_0)
    w32(buf, fn + 4, RETAB)
    print(f"  [P1] sig check: MOVZ X0,#0 + RETAB @ {IBOOT_BASE+fn:#x}")

def patch_kernel_debug(buf):
    """
    Patch BL to _security_allow_modes to always return 1 (debug enabled).
    Walk 2 BLs forward from debug-enabled string xref.
    (pac_set(6723, 5, 2) -> version != 6723 -> 2 BLs)
    """
    debug_off = bytes(buf).find(b'debug-enabled')
    if debug_off == -1:
        raise RuntimeError("debug-enabled string not found")

    xrefs = find_adrp_add_xref(buf, debug_off)
    if not xrefs:
        raise RuntimeError("no xref to debug-enabled string")

    bl_off = count_bl_forward(buf, xrefs[0], 2)
    w32(buf, bl_off, MOVZ_X0_1)
    print(f"  [P2] kernel debug: MOVZ X0,#1 @ {IBOOT_BASE+bl_off:#x}")

def patch_bootargs(buf, bootargs_str):
    """
    Redirect boot-args ADRP to a zero region and write custom string.
    Handles both the main path and the CBZ fallback path (>= iOS 10 behaviour).
    """
    ba_bytes = bootargs_str.encode() + b'\x00'
    if len(ba_bytes) > MAX_BOOTARGS:
        raise ValueError(f"boot-args too long ({len(ba_bytes)} > {MAX_BOOTARGS})")

    # Find rd=md0 string (version >= 6723 path)
    rd_off = bytes(buf).find(b'rd=md0\x00')
    if rd_off == -1:
        raise RuntimeError("rd=md0 string not found")

    xrefs = find_adrp_add_xref(buf, rd_off)
    if not xrefs:
        raise RuntimeError("no xref to rd=md0")

    xref    = xrefs[0]
    rd_reg  = r32(buf, xref) & 0x1f
    new_off = find_zero_region(buf)

    # Main path: replace ADRP+ADD with ADR+NOP
    adr_op = build_adr(xref, new_off, rd_reg)
    w32(buf, xref,     adr_op)
    w32(buf, xref + 4, NOP)
    print(f"  [P3a] boot-args ADR @ {IBOOT_BASE+xref:#x} -> {IBOOT_BASE+new_off:#x}")

    # CBZ fallback path (>= 3406)
    cbz_off = find_cbz_before(buf, xref)
    if cbz_off is not None:
        tgt     = cbz_target(buf, cbz_off)
        tgt_reg = r32(buf, tgt) & 0x1f
        adr_op2 = build_adr(tgt, new_off, tgt_reg)
        w32(buf, tgt, adr_op2)
        print(f"  [P3b] boot-args CBZ path ADR @ {IBOOT_BASE+tgt:#x} -> {IBOOT_BASE+new_off:#x}")

    # Write the string
    buf[new_off:new_off + len(ba_bytes)] = ba_bytes
    print(f"  [P3c] boot-args written @ {IBOOT_BASE+new_off:#x}: \"{bootargs_str}\"")

def patch_image_type(buf):
    """
    Allow loading any image type by zeroing the type and count variables
    passed into the image type validation routine.

    In 9275 the lookup string is 'cebilefciladmplarmmhtreptlhptmbr'
    (note 'mpla' insertion vs older 'cebilefciladrmmhtreptlhptmbr').

    Patch sites:
      - ADRP X8 + two ADDs (type var, main path)   -> MOVZ X8,#0 + NOP + NOP
      - ADRP X9 (type var, alt path)                -> MOVZ X9,#0
      - MOVZ W6, #7 (count var)                     -> MOVZ W6,#0
    """
    TYPE_STR = b'cebilefciladmplarmmhtreptlhptmbr'
    str_off  = bytes(buf).find(TYPE_STR)
    if str_off == -1:
        raise RuntimeError(
            "image type string not found -- "
            "older iBoots use 'cebilefciladrmmhtreptlhptmbr' (no 'mpla')")

    xrefs = find_adrp_add_xref(buf, str_off)
    if len(xrefs) < 1:
        raise RuntimeError("no xref to image type string")

    # Main path xref (X8)
    h = xrefs[0]
    rd = r32(buf, h) & 0x1f
    w32(buf, h,     0xd2800000 | rd)   # MOVZ Xrd, #0
    w32(buf, h + 4, NOP)
    w32(buf, h + 8, NOP)
    print(f"  [P4a] image type main: MOVZ X{rd},#0 + 2xNOP @ {IBOOT_BASE+h:#x}")

    # Alt path xref (X9) if present
    if len(xrefs) >= 2:
        h2  = xrefs[1]
        rd2 = r32(buf, h2) & 0x1f
        w32(buf, h2, 0xd2800000 | rd2)
        print(f"  [P4b] image type alt:  MOVZ X{rd2},#0 @ {IBOOT_BASE+h2:#x}")

    # Count variable: search for MOVZ W6, #7 (0x528000e6)
    COUNT_NEEDLE = struct.pack('<I', 0x528000e6)
    cnt_off = bytes(buf).find(COUNT_NEEDLE)
    if cnt_off == -1:
        raise RuntimeError("count variable needle not found")
    cnt_rd = r32(buf, cnt_off) & 0x1f
    w32(buf, cnt_off, 0x52800000 | cnt_rd)   # MOVZ Wrd, #0
    print(f"  [P4c] image type count: MOVZ W{cnt_rd},#0 @ {IBOOT_BASE+cnt_off:#x}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="iBoot 9275 (10151.2.12) arm64e patcher for d38 iOS 17.0")
    ap.add_argument("input",  help="decrypted raw iBoot binary")
    ap.add_argument("output", help="output patched binary")
    ap.add_argument("-b", "--boot-args", default=None,
                    help="custom boot-args string (optional)")
    ap.add_argument("--skip-verify", action="store_true",
                    help="skip pre-patch byte verification")
    args = ap.parse_args()

    with open(args.input, 'rb') as f:
        buf = bytearray(f.read())

    print(f"Input:  {args.input} ({len(buf):#x} bytes)")

    if len(buf) != EXPECTED_SIZE:
        print(f"  [WARN] unexpected size {len(buf):#x}, expected {EXPECTED_SIZE:#x}")

    # Check version string
    ver_idx = bytes(buf).find(b'iBoot-')
    if ver_idx != -1:
        ver = bytes(buf[ver_idx:ver_idx+20]).split(b'\x00')[0].decode(errors='replace')
        print(f"Version: {ver}")
        if IBOOT_VERSION not in ver:
            print(f"  [WARN] expected iBoot-{IBOOT_VERSION}, got {ver}")
            print(f"  [WARN] patches are hardcoded for 9275 -- proceed at your own risk")

    # Confirm arm64e
    pac_idx = bytes(buf).find(struct.pack('<I', PACIBSP))
    if pac_idx == -1:
        print("  [WARN] PACIBSP not found -- may not be arm64e")
    else:
        print(f"arm64e: confirmed (PACIBSP @ {IBOOT_BASE+pac_idx:#x})")

    print()

    if not args.skip_verify:
        print("Pre-patch verification...")
        if not verify_pre(buf):
            print("Verification FAILED -- wrong binary or already patched?")
            print("Use --skip-verify to override.")
            sys.exit(1)
        print("  All checks passed.\n")

    print("Applying patches...")
    patch_sig_check(buf)
    patch_kernel_debug(buf)

    if args.boot_args:
        patch_bootargs(buf, args.boot_args)
    else:
        print("  [P3] boot-args: skipped (no -b provided)")

    patch_image_type(buf)

    print()
    with open(args.output, 'wb') as f:
        f.write(buf)
    print(f"Output: {args.output}")
    print("Done.")

if __name__ == "__main__":
    main()
