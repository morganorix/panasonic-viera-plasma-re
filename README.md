# Rétro-ingénierie du firmware Panasonic VIERA plasma (plateforme PEAKS / UniPhier, 2010)

> Étude technique menée **sur mon propre téléviseur**, à des fins **éducatives et de recherche en sécurité défensive**.
> **Aucun firmware, binaire, clé ou fichier propriétaire Panasonic n'est redistribué ici** — ce dépôt ne contient que mon analyse et mes scripts.
> Le firmware officiel se télécharge sur le support Panasonic ; les outils tiers utilisés sont liés vers leurs dépôts d'origine.

---

## 1. Contexte

- **Appareil** : téléviseur plasma Panasonic VIERA série **G20** (2010), modèle de la famille `TX-P42G20` / `GT20` / `VT20`.
- **Plateforme** : Panasonic **PEAKS / UniPhier**, nom de build interne **PAL10LDA2 / EU10LDA2**.
- **Firmware étudié** : update officiel **v2.612** (`P102_2612.zip`, ~24,9 Mo), distribué par Panasonic.
- **Objectif initial** : comprendre pourquoi la partie « smart » (VieraCast) est inopérante (serveurs éteints), puis, par curiosité, auditer entièrement le firmware : technologies, fonctionnement, et niveau de verrouillage.

Les sous-systèmes réseau « smart » de cette génération sont **sortants** (la TV contacte des serveurs Panasonic aujourd'hui hors service) ; il n'existe **pas** de commande réseau entrante (le « network remote control » n'apparaît que sur les modèles 2011+).

---

## 2. Le conteneur `SDDL.SEC`

Le `.zip` officiel se décompresse en un unique fichier **`SDDL.SEC`** (« Secured »), d'entropie ≈ 7,95/8 → **chiffré de bout en bout**.

Analyse de la structure (voir `scripts/analyze.py`) :

- En-tête + table de descripteurs au début du fichier.
- Charge utile découpée en **blocs de 512 Ko**, chacun précédé d'un descripteur ASCII (préfixes de taille type `0021XXXXXX PEAKS.T00/...`).
- Magic de téléchargement `11 22 33 44`.

### Couches de protection du paquet

1. **`decipher()`** — une obfuscation maison (XOR à état, graine `904`, pas de 128 octets). Ce n'est pas de la cryptographie, juste du brouillage ; trivialement réversible.
2. **Chiffrement par bloc** — **3DES** (modèles 2010) ou **AES-128-CBC** (2009 / certains 2010), avec des **clés symétriques**.
3. **zlib** sur certains modules.

Les clés symétriques ont été rétro-ingénierées par la communauté et sont **publiques** (voir `sddl_dec` ci-dessous). Comme il s'agit de chiffrement **symétrique**, « pouvoir déchiffrer » implique « pouvoir re-chiffrer ». Le déchiffrement du paquet n'est donc **pas** l'obstacle (cf. §6).

---

## 3. Déchiffrement et dépaquetage

Réalisé avec l'outil communautaire **[`theubusu/sddl_dec`](https://github.com/theubusu/sddl_dec)** (Rust, GPL-3) — à récupérer depuis son dépôt, non ré-hébergé ici.

```
sddl_dec -v -s SDDL.SEC out/
```

Sortie :

- `SDIT.FDI` — table de description des modules (« Software Download Information Table »).
- Modules **PEAKS** (firmware principal, ~115 segments) et **PEAKSBT** (bootloader).
- Fichiers `*.TXT` listant les modèles ciblés : `TXPGT20E/L/R`, `TXPVTS20E`, `TXPVD20EA` → confirme la plateforme **P102** commune à la série.

---

## 4. Partitions et système de fichiers

Le module `PEAKS.bin` est une image flash FreeBSD. En retirant le padding (magic `D50 ` à l'offset `0x200000`, arguments de boot `root=/dev/fma4`), on le découpe en partitions avec `sddl_dec -p`, puis on extrait les systèmes de fichiers **UFS2 big-endian** avec **[`theubusu/ufs-dump`](https://github.com/theubusu/ufs-dump)** (Rust, option `-p` pour superbloc à `0x2000`, cas « Old Panasonic PEAKS »).

Table de montage (`/etc/fstab`) reconstituée :

| Device | Montage | FS |
|--------|---------|-----|
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

## 5. Architecture et pile technologique

| Couche | Technologie |
|--------|-------------|
| **SoC** | Panasonic **UniPhier** |
| **CPU applicatif** | Cœur **propriétaire Panasonic** (vraisemblablement l'**IPP**, *Instruction Parallel Processor*) — ELF32 **big-endian**, `e_machine = 0x1040`, `e_flags = 0x00034000`, compilé avec un **fork privé de GCC 4.2.1** |
| **Moteur image plasma** | **PEAKS** (« Picture Enhancement Accelerator with Kinetic System ») + microcode `uniphier.rom`, piloté par le démon `pied` |
| **OS** | **FreeBSD** embarqué (userland complet : `init`, `geom`, `newfs`, `fsck_ffs`, `ifconfig`, `bsdtar`…) |
| **Shell** | `sash` |
| **Couche applicative / UI** | **GLISP** — un dialecte **Lisp** maison Panasonic (608 fichiers `.lsp` définissant menus, EPG, télétexte, timer, etc.) |
| **Navigateur (VieraCast)** | moteur **AjaxCE** + interpréteur JavaScript dédié |

### Chaîne de démarrage

```
bootloader PEAKSBT → noyau FreeBSD → /sbin/init → /etc/initrc (config DTV)
    → /usr/target/startrc :
        /usr/local/bin/initcfg
        /usr/pie/bin/pied &
        exec /usr/local/bin/tvsh     (application TV principale)
```

### Fonctionnalités (démons `/usr/local/bin` + modules GLISP)

- **TV / tuner** : scan satellite/terrestre/analogique, EPG, télétexte, sous-titres, **MHEG-5** (TV interactive).
- **Réseau / smart** : `ajaxce` (VieraCast), `dlnad` (serveur DLNA), DHCP, Wi-Fi (`wpa_supplicant`), mise à jour logicielle (`ssu`).
- **Enregistrement** : timer, enregistrement USB, cron.
- **Services tiers** : Skype, Sky, guide Gemstar/Guide Plus.
- **DRM / TV payante** : **CI+** (Common Interface Plus, certificats CAM), **PlayReady/Janus**, lecteur smartcard.

Divers artéfacts internes de la chaîne de build Panasonic subsistent dans le firmware : hostname `target-takehara` (usine plasma de Takehara, Japon), adresses de labo `10.73.x` sur le domaine `tvrl.mei.co.jp`, lignes `gdbserver` commentées.

---

## 6. Analyse des protections (le vrai verrou)

Déchiffrer ≠ pouvoir modifier et réinstaller. Le firmware d'update est **signé** :

- Clé **`/usr/ssl/ssu/public_key.pem`** = **RSA 1024 bits, exposant 65537**.
- Le binaire `dlget` vérifie **chaque module** : messages `module%d signature err. ret=%d`, `secure_download: "verifying download"`.
- La vérification passe par un **accélérateur cryptographique matériel** du SoC : `/dev/dtv/yamshar0` (racine de confiance probablement fusée dans le silicium).

### Pourquoi on ne peut pas forger un firmware

| Opération | Clé nécessaire | Disponible ? |
|-----------|----------------|--------------|
| Déchiffrer / re-chiffrer le paquet | symétrique (publique) | ✅ |
| **Vérifier** une signature | clé **publique** RSA | ✅ (dans la TV) |
| **Créer** une signature | clé **privée** RSA | ❌ **jamais présente sur la TV** |

La clé privée n'existe **que** dans l'infrastructure de signature de Panasonic. Un système de signature est précisément conçu pour rester sûr **même quand l'attaquant possède et lit entièrement l'appareil**. Il n'y a donc **rien à extraire** (ni par le réseau, ni par la flash) : la clé qui permettrait de forger n'est pas là.

### Et une faille dans le vérificateur ?

Ce serait la seule brèche théorique « sans clé ». Mais le code de vérification (`dlget`, `PEAKSBT`) tourne sur le **CPU propriétaire** (`e_machine 0x1040`), pour lequel **il n'existe aucun désassembleur public** (ni binutils toute version — vérifié que ce **n'est pas** du MeP —, ni Ghidra, ni IDA). L'analyse statique de la logique de vérification est donc hors de portée sans :
- le toolchain interne Panasonic (jamais publié), ou
- la reconstruction complète de l'ISA (projet de recherche lourd), ou
- des tests dynamiques en boîte noire sur le matériel (risque de brique).

À la date de cette étude, **aucune clé de signature Panasonic VIERA n'a fuité publiquement** et **aucune méthode de repack/bypass n'existe** pour ces plasmas.

---

## 7. Conclusions

- ✅ Le **chiffrement** du firmware est compréhensible et réversible (clés symétriques publiques).
- ✅ Le **filesystem FreeBSD** s'extrait entièrement et s'explore.
- ✅ La pile technologique est entièrement cartographiée (UniPhier, FreeBSD, AjaxCE, GLISP, DRM CI+).
- ❌ **Repacker un firmware modifié accepté par la TV = impossible** : la signature **RSA** exige la clé privée de Panasonic, absente de l'appareil.
- ❌ **Remplacer l'OS (Android, système maison, Plex natif…) = impossible** : CPU propriétaire sans toolchain public, pile A/V fermée et câblée au matériel plasma, bootloader signé.
- ➡️ Pour moderniser l'usage : une **box HDMI externe** (Android TV / HTPC) reste la voie pertinente, la dalle plasma servant d'écran.

Leçon : l'appareil est verrouillé à un niveau que même sa fin de vie commerciale ne déverrouille pas — non pas par le chiffrement, mais par la **signature asymétrique** et une **ISA CPU propriétaire** indisponible publiquement.

---

## 8. Outils

- [`theubusu/sddl_dec`](https://github.com/theubusu/sddl_dec) — déchiffrement/dépaquetage `SDDL.SEC` (Rust, GPL-3).
- [`theubusu/ufs-dump`](https://github.com/theubusu/ufs-dump) — extraction UFS big-endian (Rust).
- `scripts/analyze.py` (ce dépôt) — analyse d'entropie et de signatures d'une image firmware.
- Firmware officiel : support Panasonic (Global Digital AV Support).

---

## 9. Mentions légales et éthiques

Étude réalisée sur **mon propre matériel**, à des fins **éducatives et de recherche**. Ce dépôt **ne redistribue aucun contenu propriétaire Panasonic** (ni firmware, ni binaire, ni système de fichiers, ni clé, ni certificat) : uniquement mon analyse et mes scripts. Les clés de déchiffrement symétriques évoquées sont déjà publiques dans des outils tiers et ne sont pas reproduites ici. Aucune technique de contournement de signature n'a été trouvée ni publiée. Les marques et noms cités appartiennent à leurs détenteurs respectifs.

## 10. Licence

- Texte (ce `README.md` et la documentation) : **CC BY 4.0**.
- Code (`scripts/`) : **MIT**.
