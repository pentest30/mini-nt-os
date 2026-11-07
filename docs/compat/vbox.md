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

## Le correctif DS/ES vérifié (855ea5a) — et le bogue GS suivant

Le correctif du trampoline (charger DS et ES avec le sélecteur utilisateur
avant `iretq`) **fonctionne** : les threads de `process_round` tournent sur
VirtualBox, et les seules terminaisons journalisées sont les fautes
**attendues** des self-tests (écriture à NULL → `0xC0000005 [1, 0]`,
débordement de pile → `0xC00000FD`, garde → `0x80000001` à `0x500000`,
DEP → exécution à `0x600000`, assertion, `#UD`). Les threads démarrent
dans le vrai `ntdll` (`LdrInitializeThunk` à `0x7c901000`) et la faute
volontaire d'écriture à `KUSER_SHARED_DATA` est capturée avec les bons
paramètres (`[0xC0000005, 1, 0x7ffe0000]`).

Le boot s'arrête maintenant à l'assert suivant
(`main.rs`, « GS lost across clock interrupts and a system service ») :
le programme charge GS avec le sélecteur du TEB (0x2b, base = TEB par
`set_teb_base`), prend des interruptions d'horloge et un service
(`NtDelayExecution`), puis relit **GS = 0 (sélecteur nul)** et
`gs:[0x18] = 0`. Sur QEMU (TCG), le même test passe : la base et le
sélecteur GS survivent.

Faits établis par l'instrumentation (états des registres à la faute,
marche matérielle des PTE, vue du hook de faute, descripteurs GDT par
SGDT) :

- le sélecteur GS de l'utilisateur vaut 0 **après** la séquence
  horloge + service (le programme l'avait chargé à 0x2b) ;
- `gs:[0x18]` renvoie 0 (via un sélecteur nul, l'accès #GP est attrapé par
  le SEH du programme, qui saute la seconde sauvegarde — d'où le 0 lu) ;
- CR3, les PTE et le contenu physique des pages `.text`/`.data` sont
  sains au moment de chaque faute ; `CR4.PCIDE` est éteint ;
- l'exception vue n'était **pas** un #PF mais le #GP du hook
  (`general_protection` rend les paramètres figés
  `[EXCEPTION_READ_FAULT, u32::MAX]` — d'où le « 0xffffffff » qui a
  égaré la première analyse) ;
- le descripteur CS utilisateur (entrée 3) est intact : `0x00cffb00...`,
  L=0, D=1 — le mode de compatibilité 32 bits est bien en place.

Pistes pour la prochaine session :

1. **Qui met le sélecteur GS à zéro** : le trampoline charge GS nul à
   l'entrée initiale (conforme à `pcr.rs` : « un programme peut charger
   GS » — le programme le fait) ; les sorties de trap restaurent le
   sélecteur sauvé à l'entrée (`mov gs, eax`). Journaliser `mov eax, gs`
   à chaque entrée de trap (la valeur sauvée) et à chaque sortie — la
   première qui rend 0 localise le chemin ;
2. **le couplage SWAPGS/`mov gs`** : l'ordre `swapgs` puis `mov gs, eax`
   recharge la base depuis le descripteur (le TEB, maintenu par
   `set_teb_base`) — vérifier que `IA32_KERNEL_GS_BASE` porte bien le TEB
   pendant le noyau après le premier passage (il ne semble jamais écrit :
   `pcr.rs` l'initialise à 0 et rien d'autre ne l'écrit) ;
3. **reproduire sur QEMU** : le bogue dépend du minutage des
   interruptions ; injecter les interruptions d'horloge au niveau
   utilisateur (QEMU `-icount` ou le moniteur) peut le rendre visible
   sous QEMU et donc débogable au gdbstub.

## Retest avec le diagnostic intégré (7d8fab8) : la sonde passe, le bogue GS isolé

Sur l'image `mino-vbox3` (branche à `7d8fab8`), boot VirtualBox propre :

- **la sonde KUSER_SHARED_DATA passe intégralement** : le dump de
  `log_shared_data_fault` montre `rip=0x0040109e, cr2=0x7ffe026c,
  err=0x7 (utilisateur|écriture|protection)`, les octets à `rip` =
  `a3 6c 02 fe 7f` (le store `mov [SharedUserData->NtMajorVersion], eax`
  exact), `ds=0x23, es=0x23, fs=0x2b` — **base de segment cachée et flux
  d'instructions sains** : la distinction vouloe par le diagnostic est
  tranchée du côté « rien de périmé » ;
- **l'assert GS échoue** : « GS lost across clock interrupts and a system
  service » — le programme a chargé GS = 0x2b (sélecteur du TEB, base
  maintenue par `set_teb_base`), la première lecture `gs:[0x18]` rend le
  TEB, puis **après des interruptions d'horloge et `NtDelayExecution`**,
  il relit **sélecteur GS = 0 (nul)** et `gs:[0x18] = 0` ;
- les fautes attendues des self-tests (NULL, débordement, garde, DEP)
  continuent d'arriver avec leurs signatures justes.

Le mécanisme à chercher : quel chemin remet le **sélecteur** GS à nul
entre les deux lectures — la paire `swapgs`/`mov gs, eax` de la sortie de
trap (eax = la valeur sauvée à l'entrée), la porte de l'horloge (son
entrée/sortie à elle), ou la sortie SYSEXIT (qui ne recharge pas les
segments) — sur un profil CPU où l'émulation des registres de segment est
stricte. Sur QEMU (TCG), le même enchaînement conserve 0x2b.

À noter, indépendant du noyau : le chargeur gèle parfois **en plein milieu
de sa ligne** « paging: PML4 at » (écran et série au même octet, CPU de la
VM à 0 %, vCPU en HLT), sur la même image qui passe à d'autres boots —
flakiness UEFI/UART de VBox, à rejouer plutôt qu'à déboguer.

## Résolu : le boot complet sur VirtualBox (e0b0b73)

La cause du « GS perdu » était **DS rendu nul** : une transition vers du
code noyau 64 bits invalide les sélecteurs de données sauvegardés, et les
stores du programme (via DS) #GPtaient — le SEH du programme sautait les
sauvegardes, d'où les slots à zéro lus comme « GS = 0 ». Le correctif
`e0b0b73` (recharger DS/ES depuis le SS utilisateur de la trame IRET à
**tous** les retours utilisateur) ferme la famille ouverte par le
correctif du trampoline (855ea5a).

Vérifié sur l'image `mino-vbox3` : `kernel: phase 1 done`, tous les
self-tests (y compris `process_round`, la sonde KUSER_SHARED_DATA et le
test GS), smss (36 services), et le lanceur dessiné sur le framebuffer
VBox. La fenêtre du launcher s'affiche et répond.

## Le boot sur le disque installé : la batterie smoke passe au ramdisk

Sur un boot dont `C:` est le volume **installé** (le disque secondaire où
l'installeur a écrit), la batterie smoke héritée bugcheckait : son programme
`files.exe` ouvre `KERNEL.BIN` relatif à la racine de `C:`, qui ne porte pas
les fichiers de test sur un volume installé. Le fixture déterministe est le
**ramdisk** (le loader y charge `fat.img` à chaque boot, `KERNEL.BIN` y est
toujours) : le programme ouvre désormais `\Device\Ramdisk0\` (le `\` final
fait ouvrir la racine par le parse du périphérique — ouvrir le périphérique
seul rend un Device, pas un File : OBJECT_TYPE_MISMATCH) et ses chemins
relatifs. La batterie passe ainsi quel que soit ce que `C:` porte. De même,
l'ESP virtuelle FAT16 de QEMU ne se monte pas (le lecteur FAT du noyau ne
lit que du FAT32) : la copie des fichiers de boot la saute avec journal
sous QEMU et les copie sur VBox (l'ESP GPT de l'image installée est
FAT32). Dettes notées : un cache de secteurs FAT (la copie d'un arbre
relit la FAT par cluster, lente en PIO) et l'affichage à l'écran des
refus du moteur.

## La copie des fichiers (lot 4-2) : le moteur écrit, le blocage à déboguer

Le moteur de copie est écrit : `io::install::copy_files(number, token)` —
la même revalidation que la préparation, les tables GPT du disque cible
relues (les volumes du plan), les deux fichiers de boot de l'ESP de
démarrage vers l'ESP cible (quand elle est montageable en FAT32 — l'ESP
virtuelle FAT16 de QEMU ne se monte pas : sautés avec journal), puis
l'arbre WINDOWS du volume de démarrage vers le volume système cible, chaque
fichier vérifié à la relecture de son entrée.

**Le blocage restant** : `copy_dir` entre dans `/WINDOWS/SYSTEM32/CONFIG`
et ne ressort pas — aucune sortie pendant des minutes (les deux CPU QEMU,
900 s), la copie de l'arbre ne progresse pas au-delà. Le fixture: la liste
du répertoire CONFIG passe (les entrées sont connues), le premier fichier
est SYSTEM (212 Kio). L'analyse n'a pas identifié la boucle : les chemins
de la copie sont bornés (le cache FAT en mémoire, les écritures
périphériques par cluster). **L'outil : le gdbstub de QEMU (`-s -S`) sur le
scénario installer-ui, point d'arrêt dans `copy_dir`** — la pile et le
compteur de boucle diront quelle itération tourne. Le vCPU est-il en boucle
ou bloqué : `VBoxManage metrics` sur la VM en état de copie a rendu 0 %
(dans HLT?) — sous QEMU, le gdbstub tranchera.

Le cache FAT de `FatVolume` (la dette M4) est en place : la première
copie de la FAT en mémoire, les entrées lues/écrites dedans, les secteurs
sales écrits à chaque copie de FAT au flush et à la drop (un remontage
frais les voit). 48 tests io verts, clippy propre.

## Résolu : la copie et le disque installé sous VirtualBox

Deux causes, l'une derrière l'autre.

**L'installateur tué en pleine copie.** Les échantillons de RIP
(`VBoxManage debugvm Mino getregisters rip`, symbolisés avec le `kernel.elf`
extrait de l'ESP de l'image) ne tombaient que dans des boucles `hlt` et
l'interruption d'horloge : le thread de la copie ne tournait plus. Le
journal série le disait : `[m4] SMSS.EXE: the process did not end within
10 s (of its start or the last key): terminated`. `cargo xtask image`
construisait le noyau avec `test-smss` seul ; la sonde qui lance `smss`
termine `smss`, `csrss` et le programme initial (ici `SETUP1.EXE`) 10 s
après la dernière touche — juste pour un scénario, fatal à une copie de
plusieurs minutes sans touche. Sous QEMU, la copie finissait avant ces 10 s.
La feature noyau `interactive` fait attendre la sonde sans délai ;
`cargo xtask image` la met par défaut (`test-smss,interactive`). Le
scénario `interactive` (`WAIT1.EXE`, 12 s sans touche) le vérifie ; sans la
feature, il échoue (vérifié par mutation).

**Le PIO lent.** Une fois la copie laissée vivre, elle prenait 260 s, et le
démarrage du disque installé lisait `C:` pendant des minutes (tous les
échantillons dans `hal::ata::AtaDrive::read_sectors`). Chaque mot passait
par un `in`/`out` à lui : 256 sorties de VM par secteur sous VT-x. Un
secteur passe maintenant par un seul `rep insw`/`rep outsw` (`hal::ata`).

Mesuré sous VirtualBox (VM `Mino`, 256 Mo, IDE PIIX4, démarrage sans
fenêtre, touches par `VBoxManage controlvm Mino keyboardputscancode 1c 9c`) :

| | Avant | Après |
|---|---|---|
| Copie de l'installation (82 Mo : fichiers de boot 44 Mo, système 37,6 Mo) | tuée à 10 s, puis 260 s | 17 s |
| Démarrage du disque installé jusqu'à `[setup] ready` | plus de 4 min, toujours en lecture | 21 s |

Le disque installé démarre seul en maître primaire : le micrologiciel
trouve `EFI/BOOT/BOOTX64.EFI` sur l'ESP de la cible, le chargeur y charge
`kernel.elf` et `fat.img`, le noyau monte `C:` sur la partition système
(`Io: GPT system partition 2: LBA 100352`).

Quand le média d'installation reste maître primaire et la cible maître
secondaire, le reset de **Finish** peut encore lancer `BOOTX64.EFI` du média.
La copie place désormais `MINO.TAG` sur l'ESP cible. Le chargeur du média
préfère toute ESP qui porte ce marqueur et charge son `kernel.elf` et son
`fat.img` : aucun détachement manuel ni changement d'ordre des disques n'est
nécessaire. Le scénario `installer-finish` garde les deux disques attachés
pendant les deux boots pour reproduire cette topologie VirtualBox.

Restent : au premier démarrage, une cible vierge en maître secondaire
laisse `C:` sur le ramdisk (le noyau essaie le secondaire d'abord, puis ne
revient pas au GPT du primaire) ; après la phase 1, l'ancien `CMD.EXE`
(`syscall.rs`, `nt_read_file`) lit lui-même le clavier PS/2 en boucle `hlt`
et peut prendre des touches à win32k (sans effet avec `interactive`, qui
retient la phase 1 tant que le programme initial tourne).

## Résolu : le curseur qui bute avant le haut de l'écran (la souris absolue)

Avec la souris PS/2 seule, VirtualBox ne transmet que des déplacements. Le
curseur de Mino part du centre de l'écran, le pointeur de l'hôte d'ailleurs :
les deux se décalent, et quand le pointeur de l'hôte sort de la fenêtre de la
VM, le curseur de Mino s'arrête avant le bord (« il ne peut pas aller au
sommet »). Le noyau n'y était pour rien : 2000 px vers le haut envoyés par
l'API (`IMouse::PutMouseEvent`) mènent bien le curseur en y = 0, et le
scénario QEMU équivalent aussi.

La correction est celle des additions invitées : la souris absolue de VMMDev
(`abi::vmmdev`, `hal::pci`, `hal::vmmdev`, pilote `drivers/input/vboxmouse`).
Au démarrage, le thread d'entrée brute trouve VMMDev (PCI 80EE:CAFE, BAR0),
s'annonce (`ReportGuestInfo`, sans quoi VMMDev refuse le reste), puis dit
qu'il lit des positions absolues (`SetMouseStatus`, `GUEST_CAN_ABSOLUTE`).
L'hôte signale chaque position par un paquet PS/2 vide ; à chaque paquet, le
pilote lit `GetMouseStatus` et, si l'intégration de la souris de l'hôte est
active (`HOST_WANTS_ABSOLUTE`), en fait un `MOUSE_MOVE_ABSOLUTE`
(0 à 0xFFFF), que win32k ramène à l'écran (`mouse::absolute_position`). Les
boutons et la molette restent ceux du paquet. L'hôte cache son pointeur :
c'est le curseur logiciel de win32k qui se voit.

Vérifié sous VirtualBox 7.2 (VM `Mino`, souris `ps2mouse`) :
`[boot] raw input thread: VirtualBox's absolute mouse (VMMDev)`,
`IMouse.AbsoluteSupported` passe à 1 ; `PutMouseEventAbsolute(101, 51)` met
la pointe de la flèche en (100, 50) ; un clic absolu sur Next de l'assistant
donne `[setup] click primary`. Sous QEMU, pas de VMMDev : la souris reste
relative (scénarios `mouse`, `keyboard`).

Pas encore : `SetPointerShape` (la forme du curseur chez l'hôte), le nouveau
protocole (l'interruption de VMMDev au lieu du paquet PS/2 vide),
`ReportGuestInfo2`.
