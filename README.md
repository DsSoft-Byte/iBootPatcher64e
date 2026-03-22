# iBootPatcher64e
iBootPatcher for arm64e devices

A dynamic iBoot patcher for arm64e devices. Searches for patch sites at runtime rather than relying on hardcoded offsets, making it more portable across iBoot versions.

Confirmed working on:
- iBoot 9275 / 10151.2.12, iPhone 15 Plus (d38), iOS 17.0 (21A350), CPFM 0x00

## Requirements

- Python 3.6+
- Decrypted raw iBoot binary (use [img4tool](https://github.com/tihmstar/img4tool) to decrypt first)
- Dev-fused device (CPFM 0x00, 0x01)

## Usage

```bash
# 1. Decrypt iBSS and iBEC
img4tool -e --iv <iv> --key <key> -o iBSS.raw iBSS.d38.RELEASE.im4p
img4tool -e --iv <iv> --key <key> -o iBEC.raw iBEC.d38.RELEASE.im4p

# 2. Patch (interactive — confirms each patch before applying)
python3 iboot_patcher_dynamic.py iBSS.raw iBSS_patched.raw -b "your boot-args"
python3 iboot_patcher_dynamic.py iBEC.raw iBEC_patched.raw -b "your boot-args"

# 3. Repackage
img4tool -c iBSS_patched.im4p -t ibss iBSS_patched.raw
img4tool -c iBEC_patched.im4p -t ibec iBEC_patched.raw
```

Use `-y` to skip confirmation prompts (non-interactive/scripted use).

## Patches applied

| # | Name | Description |
|---|------|-------------|
| 1 | Signature check | Patches `_image4_validate_property_cb_interposer` to return 0 immediately. Uses `RETAB` on arm64e, `RET` on arm64. |
| 2 | Kernel debug | Patches the BL to `_security_allow_modes` to always return 1. |
| 3 | Boot-args | Redirects the boot-args ADRP to a zero region and writes a custom string. Handles both the main path and the CBZ fallback path. |
| 4 | Image type | Zeroes the type and count variables in the image type validator, allowing any image type to be loaded. |

## Notes on arm64e

- The tool auto-detects arm64e via PACIBSP scanning and adjusts accordingly
- Patch 1 uses `RETAB` instead of `RET` on arm64e — patching a PAC-authenticated function with a plain `RET` will cause a PAC fault and hang the device
- Do not patch or remove the `PACIBSP` instruction at the start of authenticated functions

## Adding support for new iBoot versions

If the image type string has changed in a newer iBoot, add it to `IMAGE_TYPE_STRINGS` at the top of the script. The known variants so far:

```python
IMAGE_TYPE_STRINGS = [
    b'cebilefciladmplarmmhtreptlhptmbr',  # 9275+ (iOS 17, mpla insertion)
    b'cebilefciladrmmhtreptlhptmbr',       # iOS 14-16
    b'cebilefctmbrtlhptreprmmh',           # iOS 10-13
]
```

All other patch sites are found dynamically and should work across versions without modification, though testing on each new version is recommended before use.

## Credits

Patchfinder logic based on [iBoot64Finder](https://github.com/Siguza/iBoot64Finder) and [kairos](https://github.com/dayt0n/kairos).
