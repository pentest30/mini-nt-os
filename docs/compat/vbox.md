# Mino sur VirtualBox : ce qui tourne, et le bogue de portabilité ouvert

État du démarrage sur VirtualBox 7.2.22 (hôte Windows 10, 2026-11-06), et
l'analyse du bogue qui y arrête la phase 1. Tout ce qui suit vient de runs
réels, journalisés sur COM1.

## Configuration de la VM « Mino »

```bash
VBoxManage createvm --name Mino --ostype Other_64 --register
VBoxManage modifyvm Mino --firmware efi --ioapic on --memory 256 \
  --cpu-profile "Intel Core i7-6700K" \
  --uart1 0x3F8 4 --uartmode1 file serial.log
VBoxManage storagectl Mino --name IDE --add ide --controller PIIX4
VBoxManage storageattach Mino --storagectl IDE --port 0 --device 0 \
  --type hdd --medium mino.vhd
```

- L'image vient de `cargo xtask image` (GPT : ESP + système), convertie par
  `VBoxManage convertfromraw --format VHD`. **IDE, pas SATA** : le noyau
  n'a que le pilote ATA/IDE PIO (AHCI attend M9) — le firmware lit l'ESP
  où qu'elle soit, mais le noyau doit voir le disque.
- `--cpu-profile "Intel Core i7-6700K"` : les profils AMD n'existent pas
  dans la base de cette VBox ; le chemin SYSENTER (ADR-004) s'applique.

## Ce qui marche déjà sur VirtualBox

Le boot UEFI de VBox charge le loader, qui charge le noyau et le ramdisk.
Jusqu'au bogue, tout le chemin suit :

- HAL complet (GDT/IDT/TSS, APIC, PIT, W^X, SWAPGS, SYSENTER) ;
- Mm (PFN, pools, VAD, pagination à la demande) ; Ke (ordonnanceur, APC/DPC) ;
- **le GPT du disque primaire est lu** : `Io: boot partition 2: LBA 100352`,
  `\GLOBAL??\C: -> \Device\HarddiskVolume1` (FAT32 monté),
  `\SystemRoot -> \Device\HarddiskVolume1\WINDOWS` ;
- **GOP 1024×768** (l'écran journal est peint sur le framebuffer VBox) ;
- `smss` lancé, des processus utilisateur créés et schedulés.

L'écran de l'erreur fatale est lisible et symbolisé (l'écran STOP voulu
par le M0), avec la chaîne d'appels.

## Le bogue : les pages `.text` des processus vus par le CPU diffèrent
## de celles que les mêmes tables de pages rendent au noyau

`process_round` (le self-test Ps de la phase 1, inconditionnel) crée des
processus d'images bâties en mémoire (Pe32Builder) et y fait tourner des
threads de 4 instructions :

```text
64 a1 24 00 00 00    mov eax, fs:[0x24]        ; le TID du thread
a3 10 20 40 00       mov [0x402010], eax       ; .data du processus
83 05 00 20 40 00 01 add dword [0x402000], 1
eb ec                jmp 0x401000
```

Sous VBox, chaque thread s'arrête sur une faute de page **en lecture de
`0xFFFFFFFF`**, avec `rip=0x401006` — l'adresse de l'`A3`, qui est un
**store**. Instrumentation (état des registres, octets lus à `0x401000`
par le noyau via le CR3 courant, contenu du TEB et de `.data` au moment de
l'exception) :

- les octets que le noyau lit à `0x401000` sont **exactement le code
  construit** — la traduction vue du noyau est saine ;
- le TEB à `0x7ffde000` est sain (`ExceptionList=0xFFFFFFFF` initial,
  `StackBase=0x110000`), et `rax` contient **le TID du thread** : la
  première instruction a tourné avec une base FS correcte ;
- **`.data` (`0x402000`) est entièrement à zéro** : le store `A3` n'a
  jamais pris effet ;
- le fault dit *lecture* à `0xFFFFFFFF` : aucune instruction du code
  construit ne peut produire cette combinaison.

Donc : entre le moment où les tables de pages sont écrites et
l'exécution, **le CPU a traduit (ou fetché) `0x401000` autrement** que ne
le fait le noyau au moment du journal — divergence qui ne se produit ni
sur QEMU (TCG), ni à 256 Mio avec la même signature qu'à 512 Mio (les
traces changent avec la carte mémoire : nombre de processus touchés,
point de l'assert qui tombe).

Pistes classées pour la prochaine session :

1. **TLB périmé à travers les commutations de CR3** : un drapeau GLOBAL
   posé sur une entrée couvrant `0x401000` (les PTE utilisateur doivent
   n'être jamais globaux — vérifier aussi les tables de pages elles-mêmes),
   ou un PTE réécrit sans `INVLPG` pendant que la traduction est
   cachée (le `flush_all` de `paging.rs` ne couvre que ses propres
   chemins) ;
2. **PCID** : le profil 6700K l'expose ; vérifier que `CR4.PCIDE` reste
   éteint, ou que chaque écriture de CR3 porte le bit 63 (invalidation)
   si le noyau l'allume ;
3. **cache de descripteur de segment** : la base FS écrite dans la GDT
   n'est vue par le CPU qu'au rechargement du sélecteur ; vérifier
   l'ordre base-écrite/rechargement sur le chemin SYSENTER de
   `hal::ring3` et de la commutation (une base périmée ferait fauter la
   lecture `fs:[0x24]` à l'adresse `base+0x24` — mais `rax` dit qu'elle a
   réussi) ;
4. **régions mémoire de VBox** : la carte (`regions=22`, 512 ou 256 Mio)
   diffère de celle de QEMU ; vérifier dans le chargeur qu'aucune plage
   réservée du firmware (runtime services, NvVars) n'est donnée à
   l'allocateur de trames.

Le moyen le plus court de trancher : journaliser au moment de la faute la
**traduction physique** de `0x401000` vue par le noyau (PTE) et le contenu
de la trame physique via l'HHDM — si la trame physique contient le bon
code, c'est le TLB ; sinon, c'est la table de pages.

## Repro

```bash
cargo xtask image --output mino.img          # features par défaut (test-smss)
VBoxManage convertfromraw --format VHD mino.img mino.vhd
# VM ci-dessus, puis : VBoxManage startvm Mino --type headless
# le journal série montre la batteries de self-tests puis le STOP.
```

Réproduit à l'identique sur trois runs (512 Mio : trois processus
touchés ; 256 Mio : un seul, même signature). Les scénarios QEMU
équivalents (smoke, installed-persistence) restent verts.
