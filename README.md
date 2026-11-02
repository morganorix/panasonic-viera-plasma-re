# Reverse-engineering the Panasonic VIERA plasma firmware (PEAKS / UniPhier platform, 2010)

> Technical study carried out **on my own television set**, for **educational and defensive security research** purposes.
> **No Panasonic firmware, binary, key or proprietary file is redistributed here** — this repository contains only my analysis and my scripts.
> The official firmware is available from Panasonic support; the third-party tools used are linked to their original repositories.

---

## 1. Context

- **Device**: Panasonic VIERA **G20** plasma TV (2010), from the `TX-P42G20` / `GT20` / `VT20` family.
- **Platform**: Panasonic **PEAKS / UniPhier**, internal build name **PAL10LDA2 / EU10LDA2**.
- **Firmware studied**: official update **v2.612** (`P102_2612.zip`, ~24.9 MB), distributed by Panasonic.
- **Initial goal**: understand why the "smart" part (VieraCast) is dead (servers shut down), then — out of curiosity — fully audit the firmware: technologies, how it works, and how locked down it is.

The "smart" network subsystems of this generation are **outbound** (the TV reaches out to Panasonic servers that are now offline); there is **no inbound network control** (the "network remote control" protocol only appears on 2011+ models).

---

## 2. The `SDDL.SEC` container

The official `.zip` decompresses into a single file, **`SDDL.SEC`** ("Secured"), with entropy ≈ 7.95/8 → **encrypted end to end**.

Structure analysis (see `scripts/analyze.py`):

- Header + descriptor table at the start of the file.
- Payload split into **512 KB blocks**, each preceded by an ASCII descriptor (size prefixes like `0021XXXXXX PEAKS.T00/...`).
- Download magic `11 22 33 44`.

### Package protection layers

1. **`decipher()`** — an in-house obfuscation (stateful XOR, seed `904`, period of 128 bytes). Not cryptography, just scrambling; trivially reversible.
2. **Block cipher** — **3DES** (2010 models) or **AES-128-CBC** (2009 / some 2010), with **symmetric keys**.
3. **zlib** on some modules.

The symmetric keys were reverse-engineered by the community and are **public** (see `sddl_dec` below). Because this is **symmetric** encryption, "being able to decrypt" implies "being able to re-encrypt". Decrypting the package is therefore **not** the obstacle (see §6).

---

## 3. Decryption and unpacking

Done with the community tool **[`theubusu/sddl_dec`](https://github.com/theubusu/sddl_dec)** (Rust, GPL-3) — obtain it from its own repository, not re-hosted here.

```
sddl_dec -v -s SDDL.SEC out/
```

Output:

- `SDIT.FDI` — module description table ("Software Download Information Table").
- **PEAKS** modules (main firmware, ~115 segments) and **PEAKSBT** (bootloader).
- `*.TXT` files listing the target models: `TXPGT20E/L/R`, `TXPVTS20E`, `TXPVD20EA` → confirms the **P102** platform shared across the series.

---

## 4. Partitions and filesystem

The `PEAKS.bin` module is a FreeBSD flash image. After trimming the padding (magic `D50 ` at offset `0x200000`, boot args `root=/dev/fma4`), it is split into partitions with `sddl_dec -p`, then the **big-endian UFS2** filesystems are extracted with **[`theubusu/ufs-dump`](https://github.com/theubusu/ufs-dump)** (Rust, `-p` option for a superblock at `0x2000`, the "Old Panasonic PEAKS" case).

Reconstructed mount table (`/etc/fstab`):

| Device | Mount | FS |
|--------|-------|-----|
| `/dev/fma4` | `/` | UFS2 (ro) |
| `/dev/fma5` | `/usr` | UFS2 (ro) |
| `/dev/fma6` | `/lsidata` | UFS2 (ro) |
| `/dev/fma7` | `/ajax_misc` | JFFS2 (rw) |
| `/dev/fma9` | `/si` | JFFS2 (rw) |
| `/dev/fma10` | `/nv` | JFFS2 (rw, noauto) |
| `/dev/fma11` | `/gemstar` | JFFS2 (rw) |
| `/dev/fma12` | `/work` | JFFS2 (rw) |
| `/dev/fma13` | `/edata` | UFS2 (ro, noauto) |

---

## 5. Architecture and technology stack

| Layer | Technology |
|-------|------------|
| **SoC** | Panasonic **UniPhier** |
| **Application CPU** | **Proprietary Panasonic** core (most likely the **IPP**, *Instruction Parallel Processor*) — ELF32 **big-endian**, `e_machine = 0x1040`, `e_flags = 0x00034000`, built with a **private fork of GCC 4.2.1** |
| **Plasma image engine** | **PEAKS** ("Picture Enhancement Accelerator with Kinetic System") + `uniphier.rom` microcode, driven by the `pied` daemon |
| **OS** | Embedded **FreeBSD** (full userland: `init`, `geom`, `newfs`, `fsck_ffs`, `ifconfig`, `bsdtar`…) |
| **Shell** | `sash` |
| **Application / UI layer** | **GLISP** — an in-house Panasonic **Lisp** dialect (608 `.lsp` files defining menus, EPG, teletext, timer, etc.) |
| **Browser (VieraCast)** | **AjaxCE** engine + a dedicated JavaScript interpreter |

### Boot chain

```
PEAKSBT bootloader → FreeBSD kernel → /sbin/init → /etc/initrc (DTV config)
    → /usr/target/startrc:
        /usr/local/bin/initcfg
        /usr/pie/bin/pied &
        exec /usr/local/bin/tvsh     (main TV application)
```

### Features (daemons in `/usr/local/bin` + GLISP modules)

- **TV / tuner**: satellite/terrestrial/analog scanning, EPG, teletext, subtitles, **MHEG-5** (interactive TV).
- **Network / smart**: `ajaxce` (VieraCast), `dlnad` (DLNA server), DHCP, Wi-Fi (`wpa_supplicant`), software update (`ssu`).
- **Recording**: timer, USB recording, cron.
- **Third-party services**: Skype, Sky, Gemstar/Guide Plus EPG.
- **DRM / pay-TV**: **CI+** (Common Interface Plus, CAM certificates), **PlayReady/Janus**, smartcard reader.

Various internal Panasonic build-chain artifacts remain in the firmware: hostname `target-takehara` (Takehara plasma plant, Japan), lab addresses `10.73.x` on the `tvrl.mei.co.jp` domain, commented-out `gdbserver` lines.

---

## 6. Protection analysis (the real lock)

Decrypting ≠ being able to modify and reinstall. The update firmware is **signed**:

- Key **`/usr/ssl/ssu/public_key.pem`** = **RSA 1024-bit, exponent 65537**.
- The `dlget` binary verifies **each module**: messages `module%d signature err. ret=%d`, `secure_download: "verifying download"`.
- Verification goes through a **hardware crypto accelerator** in the SoC: `/dev/dtv/yamshar0` (root of trust likely fused into silicon).

### Why forging a firmware is not possible

| Operation | Key needed | Available? |
|-----------|------------|------------|
| Decrypt / re-encrypt the package | symmetric (public) | ✅ |
| **Verify** a signature | **public** RSA key | ✅ (on the TV) |
| **Create** a signature | **private** RSA key | ❌ **never present on the TV** |

The private key exists **only** in Panasonic's signing infrastructure. A signature scheme is specifically designed to stay secure **even when the attacker fully owns and reads the device**. There is therefore **nothing to extract** (neither over the network nor from flash): the key that would allow forging is simply not there.

### What about a flaw in the verifier?

That would be the only theoretical "keyless" opening. But the verification code (`dlget`, `PEAKSBT`) runs on the **proprietary CPU** (`e_machine 0x1040`), for which **no public disassembler exists** (no binutils of any version — confirmed it is **not** MeP — no Ghidra, no IDA). Static analysis of the verification logic is therefore out of reach without:
- Panasonic's internal toolchain (never released), or
- a full reconstruction of the ISA (a heavy research project), or
- black-box dynamic testing on the hardware (risk of bricking).

As of this study, **no Panasonic VIERA signing key has leaked publicly** and **no repack/bypass method exists** for these plasma sets.

---

## 7. Conclusions

- ✅ The firmware **encryption** is understandable and reversible (public symmetric keys).
- ✅ The **FreeBSD filesystem** can be fully extracted and explored.
- ✅ The technology stack is fully mapped (UniPhier, FreeBSD, AjaxCE, GLISP, CI+ DRM).
- ❌ **Repacking a modified firmware the TV will accept = impossible**: the **RSA** signature requires Panasonic's private key, absent from the device.
- ❌ **Replacing the OS (Android, a homemade system, native Plex…) = impossible**: proprietary CPU with no public toolchain, a closed A/V stack wired to the plasma hardware, a signed bootloader.
- ➡️ To modernize usage: an **external HDMI box** (Android TV / HTPC) remains the sensible path, with the plasma panel used as the display.

Takeaway: the device is locked at a level that even the end of its commercial life does not unlock — not by the encryption, but by the **asymmetric signature** and a **proprietary CPU ISA** that is not publicly available.

---

## 8. Tools

- [`theubusu/sddl_dec`](https://github.com/theubusu/sddl_dec) — `SDDL.SEC` decryption/unpacking (Rust, GPL-3).
- [`theubusu/ufs-dump`](https://github.com/theubusu/ufs-dump) — big-endian UFS extraction (Rust).
- `scripts/analyze.py` (this repo) — entropy and signature analysis of a firmware image.
- Official firmware: Panasonic support (Global Digital AV Support).

---

## 9. Legal and ethical notice

Study carried out on **my own hardware**, for **educational and research** purposes. This repository **does not redistribute any proprietary Panasonic content** (no firmware, binary, filesystem, key or certificate): only my analysis and my scripts. The symmetric decryption keys referenced are already public in third-party tools and are not reproduced here. No signature-bypass technique was found or published. Trademarks and names mentioned belong to their respective owners.

## 10. License

- Text (this `README.md` and the documentation): **CC BY 4.0**.
- Code (`scripts/`): **MIT**.
