#!/usr/bin/env python3
import sys, math, collections

path = sys.argv[1]
with open(path, "rb") as f:
    data = f.read()

n = len(data)
print(f"Fichier: {path}")
print(f"Taille : {n} octets ({n/1024/1024:.2f} Mo)\n")

# --- En-tete ---
print("=== 128 premiers octets ===")
for off in range(0, 128, 16):
    chunk = data[off:off+16]
    hexs = " ".join(f"{b:02x}" for b in chunk)
    asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    print(f"{off:06x}  {hexs:<47}  {asci}")

print("\n=== 64 derniers octets ===")
for off in range(n-64, n, 16):
    chunk = data[off:off+16]
    hexs = " ".join(f"{b:02x}" for b in chunk)
    asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    print(f"{off:06x}  {hexs:<47}  {asci}")

# --- Entropie par blocs de 4 Ko ---
def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    ln = len(b)
    return -sum((v/ln) * math.log2(v/ln) for v in c.values())

BS = 4096
ents = [entropy(data[i:i+BS]) for i in range(0, n, BS)]
mean = sum(ents)/len(ents)
hi = sum(1 for e in ents if e > 7.5)
lo = sum(1 for e in ents if e < 6.0)
print(f"\n=== Entropie (blocs de 4 Ko, {len(ents)} blocs) ===")
print(f"Moyenne : {mean:.3f} bits/octet  (8.0 = aleatoire parfait)")
print(f"Blocs haute entropie (>7.5) : {hi} ({100*hi/len(ents):.1f}%)  -> chiffre/compresse")
print(f"Blocs basse entropie (<6.0) : {lo} ({100*lo/len(ents):.1f}%)  -> texte/code/zeros")
print(f"Min={min(ents):.3f}  Max={max(ents):.3f}")

# profil grossier (24 segments)
print("\nProfil entropie (chaque # = un segment, . = basse, : = moyenne, # = haute):")
seg = max(1, len(ents)//70)
line = ""
for i in range(0, len(ents), seg):
    e = sum(ents[i:i+seg])/len(ents[i:i+seg])
    line += "#" if e > 7.5 else (":" if e > 6.0 else ".")
print(line)

# --- Recherche de signatures connues ---
sigs = {
    b"\x1f\x8b\x08": "gzip",
    b"\x5d\x00\x00": "LZMA (alone)",
    b"\xfd7zXZ\x00": "XZ",
    b"BZh": "bzip2",
    b"hsqs": "SquashFS LE (sqsh)",
    b"sqsh": "SquashFS BE",
    b"UBI#": "UBI",
    b"\x85\x19": "JFFS2 LE",
    b"\x27\x05\x19\x56": "uImage (U-Boot)",
    b"ANDROID!": "Android boot",
    b"\x7fELF": "ELF",
    b"CROMFS": "cromfs",
    b"-rom1fs-": "romfs",
    b"\xd0\x0d\xfe\xed": "FDT/DTB",
    b"\x28\xcf\xbc\xa8": "???",
    b"PK\x03\x04": "ZIP",
}
print("\n=== Signatures connues trouvees ===")
found = False
for sig, name in sigs.items():
    start = 0
    hits = []
    while True:
        idx = data.find(sig, start)
        if idx < 0:
            break
        hits.append(idx)
        start = idx + 1
        if len(hits) > 5:
            break
    if hits:
        found = True
        shown = ", ".join(f"0x{h:x}" for h in hits[:5])
        more = " (+)" if len(hits) > 5 else ""
        print(f"  {name:20} x{len(hits)}{more} @ {shown}")
if not found:
    print("  AUCUNE signature connue -> coherent avec un chiffrement global")
