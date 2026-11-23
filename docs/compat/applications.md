# Applications Win32 x86 : validation fonctionnelle

Branche `feat/m7-classic-apps`, base main `abfe106`, suite de la PR #127.
Les exécutables de référence sont ceux de ReactOS 0.4.16 (`51bfc703`), déjà
épinglés et vérifiés par `xtask fetch-userland`. Aucun binaire Microsoft.

| Application | Parcours validé | État de cette campagne |
|---|---|---|
| Bloc-notes | Nouveau document, saisie au clavier, Enregistrer sous, contenu exact sur disque, fermeture normale, réouverture et rendu | PASS QEMU AMD et Intel |
| Calculatrice | Lancer, `12 + 30 = 42`, fermer, relancer, `6 × 7 = 42`, rendu du résultat | PASS QEMU AMD et Intel (`calculator`) |
| Démineur | Drapeau au clic droit, F2, fermeture, relance | PASS QEMU AMD et Intel (`minesweeper`) |
| Gestionnaire des tâches | Fermer, relancer, naviguer entre Applications et Processus | PASS QEMU AMD et Intel (`desktop-launch`) |

## La liste du M7 (premier critère)

Le premier critère du M7 ([05](../05-feuille-de-route.md#m7--bureau-et-applications)) demande dix applications
libres de l'ère XP qui s'installent et s'exécutent. La liste a été arrêtée le 2026-11-17. Règles du choix :
logiciels libres, en 32 bits, dans une version qui tourne sur XP ; ni réseau (M9), ni DirectX, ni OpenGL (M8) ;
les installeurs du M7 (MSI, NSIS) et Inno Setup, le plus répandu chez les logiciels libres ; des toolkits variés,
pour que chaque application teste autre chose. Elles sont rangées de la plus simple à la plus lourde.

| # | Application | Licence | Installeur | Ce qu'elle teste | Parcours |
|---|---|---|---|---|---|
| 1 | 7-Zip 9.20 (2010) | LGPL | MSI | `msiexec` de ReactOS, Win32, `msvcrt` | installer, archiver un fichier, l'extraire, comparer (fait par `7z.exe`, le 2026-11-22) |
| 2 | Notepad++ 7.9.2 (2020) | GPL | NSIS | Scintilla, onglets, Rechercher et Remplacer | taper, remplacer, enregistrer, rouvrir |
| 3 | KeePass 1.18 (2010) | GPL | Inno Setup | MFC, cryptographie, dialogues | créer une base et une entrée, enregistrer, rouvrir avec le mot de passe |
| 4 | WinMerge 2.12.4 (2009) | GPL | Inno Setup | MFC, vues côte à côte | comparer deux fichiers, fusionner une différence, enregistrer |
| 5 | SumatraPDF 2.5.2 (2014) | GPL | le sien | rendu de pages, défilement | ouvrir un PDF fourni, page suivante, zoom |
| 6 | AbiWord 2.4.1 (2005) | GPL | NSIS | traitement de texte, polices, RTF | taper, mettre en gras, enregistrer en `.rtf`, rouvrir |
| 7 | PeaZip 3.9.1 (2011) | LGPL | Inno Setup | Lazarus et Free Pascal (LCL) | ouvrir une archive, l'extraire |
| 8 | Dev-C++ 4.9.9.2 (2005) | GPL | NSIS | Delphi (VCL), processus `gcc` lancés | ouvrir un projet, le compiler, lancer le programme |
| 9 | GIMP 2.6.12 (2011) | GPL | Inno Setup | GTK2, nombreuses DLL, fontconfig | ouvrir une image, appliquer un filtre, exporter en PNG (fait en Script-Fu, le 2026-11-22) |
| 10 | Apache OpenOffice 4.1.17 (2026) | Apache 2.0 | NSIS, qui déballe son installeur MSI | très grosse application, runtimes de Visual C++ (WinSxS, à mesurer) | Writer : taper, enregistrer en `.odt`, rouvrir |

### Les installeurs épinglés

Les fichiers viennent des sources officielles des projets. Le type d'installeur est lu dans le fichier (marqueur MSI,
NSIS ou Inno Setup), sans l'exécuter. 7-Zip est un paquet MSI ; les autres sont des PE i386 qui demandent au plus
Windows 4.0 (5.1, XP, pour SumatraPDF).

| Application | Fichier | Source | Octets | SHA-256 |
|---|---|---|---:|---|
| 7-Zip | `7z920.msi` | SourceForge `sevenzip`, `/7-Zip/9.20/` | 1 122 816 | `fe4807b4698ec89f82de7d85d32deaa4c772fc871537e31fb0fccf4473455cb8` |
| Notepad++ | `npp.7.9.2.Installer.exe` | GitHub, publication `v7.9.2` de `notepad-plus-plus` | 3 853 600 | `a797da6e8cebe364becc30d3d5d540897166e7674a0fc8e386fd9593d0838f43` |
| KeePass | `KeePass-1.18-Setup.exe` | SourceForge `keepass`, `/KeePass 1.x/1.18/` | 1 533 148 | `10d63bb8185657893d5ac3cd31f12beb48a5457ac14bd8e93220f5ce21fa03f5` |
| WinMerge | `WinMerge-2.12.4-Setup.exe` | SourceForge `winmerge`, `/stable/2.12.4/` | 3 212 078 | `155896d41247f4cb933d4b24bd67ee8fd02bf2268ca4db189dc8e56b88f263c4` |
| SumatraPDF | `SumatraPDF-2.5.2-install.exe` | `files.sumatrapdfreader.org`, `/software/sumatrapdf/rel/2.5.2/` | 4 262 896 | `d1effcab0de7c5a7d706c35f80cb042c1fbc9e5f64e0d0268a741862ad93dd1a` |
| AbiWord | `abiword-setup-2.4.1.exe` | SourceForge `abiword`, `/OldFiles/` | 5 277 618 | `9b7b2ee39dbfd01a72b094aec5574e762cc295f0b974a08df6c8e015d1b91fb5` |
| PeaZip | `peazip-plain-3.9.1.WINDOWS.exe` | SourceForge `peazip`, `/3.9.1/` | 5 679 767 | `ee48b114ec1cd772937a0d1578540b526b99ea87ac16d9212f1f84824727a0a8` |
| Dev-C++ | `devcpp-4.9.9.2_setup.exe` | SourceForge `dev-cpp`, `/Binaries/Dev-C++ 4.9.9.2/` | 9 326 468 | `98ca778d39ce72d1d8dd8c362a19ff5c63d8b827cd02dfbf139d4d0fd6328c40` |
| GIMP | `gimp-2.6.12-i686-setup-2.exe` | `download.gimp.org`, `/pub/gimp/v2.6/windows/` | 21 221 232 | `9df479d366fb1682800c776c0cdb4d9f69345374f47e226ed004508b92856327` |
| Apache OpenOffice | `Apache_OpenOffice_4.1.17_Win_x86_install_en-US.exe` | Apache, `downloads.apache.org/openoffice/4.1.17/binaries/en-US/` | 143 243 640 | `dd56646e4cb7183c9144b9ee1c9ae1f4d24edbb5a92b04f5d9573ac00f80a992` |

Comparées à une empreinte publiée par la source, et égales : les MD5 de SourceForge (7-Zip, KeePass, WinMerge,
AbiWord, PeaZip, Dev-C++) et le SHA-256 d'Apache (OpenOffice). Pas encore comparées : GIMP (son `.md5`, sur
`download.gimp.org`, ne répondait plus au moment de la vérification), Notepad++ et SumatraPDF (aucune empreinte
publiée lue).

### Écarts et points ouverts

- **Notepad++** : la 5.9 (2011) n'est plus servie par une source officielle joignable (le site ne garde que les
  versions récentes et GitHub n'a pas de 5.x). La 7.9.2 est la dernière version annoncée pour XP : à confirmer en
  l'exécutant.
- **AbiWord** : `abisource.com`, qui sert la 2.8, ne répond pas ; la 2.4.1 vient du SourceForge du projet.
- **OpenOffice** : le miroir SourceForge d'OpenOffice.org 3.3.0 (2011) était trop lent pour ses 143 Mo. La liste
  prend Apache OpenOffice 4.1.17, dont la configuration requise annonce encore Windows XP
  ([sys_reqs_aoo41](https://www.openoffice.org/dev_docs/source/sys_reqs_aoo41.html)). Comme Notepad++, c'est une
  version récente qui tourne sur XP, pas une version de l'époque.
- **InstallShield** : la feuille de route le nomme parmi les installeurs du M7, mais aucun logiciel libre de la liste
  ne s'en sert (c'est un outil payant). À trancher : une application gratuite mais non libre, hors de la liste, ou
  une ADR qui le retire des installeurs du M7.
- **GIMP et OpenOffice** sont les plus lourdes : beaucoup de DLL, et les runtimes de Visual C++ par WinSxS pour
  OpenOffice. Elles viennent en dernier.

### Le banc d'essai

`cargo xtask fetch-apps [--app ID]` télécharge les installeurs épinglés (`xtask/src/apps.rs` : source, taille,
SHA-256) dans `third_party/apps/<id>/`, ou vérifie une copie déjà là, et les estampille (`<fichier>.sha256`). Un
scénario `app = ID` (`tests/boot/app-<id>/`) fait un disque système `C:` plus grand (`mkfat --free-mib`,
`fatfs::build_with_free`) : les fichiers du scénario, le reste de l'arbre de ReactOS (`userland::whole_tree` : tout
sauf `Fonts` et `system32/config`, que le disque de démarrage fournit), l'installeur et `C:\APPS\PROBE.TXT`. Le disque
RAM reste celui des autres scénarios, que le chargeur limite à 64 Mio. Sans l'installeur, le scénario est sauté.

`APPBENCH.EXE` (`tests/native/appbench.c`) prend la place de `winlogon` et lit `PROBE.TXT`. Il lance l'installeur en
silencieux (`msiexec /qn` avec son journal, NSIS `/S`, Inno Setup `/VERYSILENT` avec son journal, SumatraPDF `/s`).
Il répond par le bouton par défaut à une boîte de dialogue restée 10 s sans changer (8 fois au plus), et relance
visible un NSIS silencieux qui échoue tout seul (il ne dit rien). Il imprime les fenêtres à l'écran, le journal de
l'installeur et ce qu'il a mis sous `Program Files`, puis lance le programme installé, attend sa fenêtre et le ferme.
Il ne juge rien : le noyau journalise chaque service sans handler à son premier appel, et chaque exception qui termine
un processus. Les marqueurs d'un scénario sont un plancher, ce qui marche aujourd'hui : l'installeur démarre ; pour
Dev-C++, ses fichiers sont copiés et son programme démarre.

### Les essayer à la main : `cargo xtask image --apps`

```bash
cargo xtask fetch-apps
cargo xtask image --apps --output mino-apps.img                    # les dix
cargo xtask image --app keepass --app notepadpp --output mino.img   # ou quelques-unes
```

L'image est celle de `cargo xtask image` (GPT : ESP, puis le volume système), avec le vrai `winlogon` de ReactOS
(`--initial-command system`, la seule commande permise avec `--apps`) et le shell (`explorer.exe` et ses imports sur
le disque RAM, comme `shell = explorer`). `C:` y est un volume à part, fait comme celui d'un scénario `app = ID`
(`apps_disk`) : les fichiers du disque RAM, tout l'arbre de ReactOS, les installeurs choisis dans `C:\APPS` sous
leur nom publié, et la place libre de leurs installations, la somme de leurs `free_mib` (`xtask/src/apps.rs`). Le
disque RAM de l'ESP reste celui d'une image ordinaire (64 Mio au plus) ; le noyau prend `C:` sur la partition
système. Un installeur que `fetch-apps` n'a pas vérifié est signalé et sauté ; un identifiant inconnu est une
erreur. `install::create` copie le volume système par flux : il ne passe plus par la mémoire.

| Application | Installeur | Place libre prévue |
|---|---:|---:|
| 7-Zip, Notepad++, KeePass, WinMerge, SumatraPDF | 1 à 4 Mo chacun | 64 Mio chacune |
| AbiWord, PeaZip | 5 et 6 Mo | 96 Mio chacune |
| Dev-C++ | 9 Mo | 192 Mio |
| GIMP | 21 Mo | 320 Mio |
| Apache OpenOffice | 143 Mo | 1 024 Mio |
| **Les dix** | **199 Mo** | **2 048 Mio** |

Avec les dix (mesuré le 2026-11-19) : `C:` a 1 075 fichiers et fait 2 541 Mio (l'arbre de ReactOS, les
installeurs, 2 048 Mio libres), l'ESP 59 Mio (dont le disque RAM, 53 Mio), l'image 2 602 Mio ; tout tient,
OpenOffice compris. Le noyau garde en mémoire la première FAT entière (clusters de 512 octets : 20 Mio pour ce
volume), et `mkfat` construit le volume en mémoire sur l'hôte (2,5 Go). Mémoire de la machine : celle de
l'application la plus lourde (`memory_mb` : 768 Mio avec OpenOffice, 512 avec GIMP, 256 sinon) ; `xtask`
l'imprime.

Le premier démarrage est celui de l'installation (`minoinit` : profils, enregistrement COM, ruches vidées sur le
disque, puis redémarrage), le second ouvre la session d'`Administrator` (AutoAdminLogon) et montre le bureau
d'`explorer`. Un installeur se lance par Win+R (`C:\APPS\KeePass-1.18-Setup.exe` ; pour 7-Zip, `msiexec /i
C:\APPS\7z920.msi`) ou depuis le Poste de travail. Ce qu'on peut en attendre est le bilan du banc (plus bas, le
2026-11-19) : KeePass s'installe et ouvre sa fenêtre, Notepad++ s'arrête sur son avertissement Authenticode, AbiWord
et Dev-C++ s'installent mais leurs programmes plantent, les autres ne s'installent pas. Une différence avec le banc :
ici l'installeur tourne sous le jeton d'`Administrator`, dans sa session, pas sous celui de System ; le profil
introuvable de SumatraPDF peut changer.

**Essai sous QEMU** (2026-11-19, AMD, 768 Mio, l'image des dix) : le premier démarrage va jusqu'au redémarrage en
133 s ; au second, la session s'ouvre et le bureau s'affiche (ses quatre icônes, la barre des tâches, l'horloge).
Win+R complète `C:\APPS\KeePass-1.18-Setup.exe` et le lance dans la session : sa boîte « Select Setup Language »
s'ouvre, mais son texte et sa liste sont des carrés. Inno Setup 5.3 est un programme ANSI, et win32k n'a pas encore
de CALLPROCDATA (« the procedure of class 0xc009 asked in the other character set », voir
[`m6-fenetres.md`](m6-fenetres.md), étape 33) ; le banc, silencieux, ne montre pas cette boîte.

**Ce qu'une session écrit survit à l'arrêt de la machine** (depuis le 2026-11-19). Avant, le noyau gardait la FAT
de `C:` en mémoire et ne l'écrivait qu'à un vidage explicite (NtFlushBuffersFile, ou l'écriture d'une ruche) ; les
ruches ne s'écrivaient qu'à NtFlushKey et NtUnloadKey ; NtShutdownSystem ne faisait que le redémarrage, sans rien
vider. Ce que le second démarrage écrivait dans la ruche SOFTWARE (la clé du profil d'`Administrator` sous
`ProfileList`) et ce qu'un installeur copiait restaient en mémoire : au troisième démarrage du même disque, la
session ne s'ouvrait plus (« ReactOS could not load the locally stored user profile » : IncrementRefCount de
`userenv` ne trouvait pas cette clé, Error 2 ; une boîte qui ne répondait ni au clavier ni à son délai), et trois
fichiers écrits pendant les sessions (le `.tmp` de KeePass sous `Local Settings\Temp`, `RECYCLED\INFO2`…) avaient
dans la FAT du disque une chaîne qui finissait sur un cluster libre.

Maintenant, un thread système du noyau, l'écrivain paresseux (`kernel/ntoskrnl/src/lazy_writer.rs`), fait chaque
seconde ce que font l'écrivain paresseux du cache et l'écriture différée des ruches de NT (CcLazyWriteScan,
CmpLazyFlush de ReactOS, comme spécification) : il réécrit les ruches qui n'ont pas changé depuis 5 s
(CmpLazyFlushIntervalInSeconds), ou qui attendent depuis 30 s sans cesser de changer (`cm::lazy_flush`), puis vide
les volumes dont quelque chose attend : les secteurs modifiés de la FAT, le cache du disque
(`io_manager::lazy_writer`). Le vidage d'un volume se fait sous son verrou, entre deux opérations : la FAT écrite
est celle d'un volume cohérent. NtShutdownSystem demande SeShutdownPrivilege, comme ReactOS, puis réécrit tout avant
le redémarrage, l'arrêt (ShutdownNoReboot : le processeur s'arrête, « It is now safe to turn off your computer » sur
le port série) ou l'extinction (ShutdownPowerOff : l'état S5 de l'ACPI, `hal::acpi` ; essayé sous QEMU, qui
s'arrête ; pas encore sous VirtualBox ; sans `\_S5_`, le processeur s'arrête). Couper le courant perd au plus les dernières secondes ;
quelques secondes sans écriture, et le disque est cohérent. La FAT n'a pas de journal, ni les ruches de `.LOG` : une
coupure pendant une écriture peut encore laisser une chaîne ou une ruche à moitié écrite.

Le scénario `power-cut` le vérifie sur le disque de `logon` : l'installation, puis une session ouverte dont xtask
coupe le courant (QEMU tué) une fois qu'`explorer` a listé son bureau et qu'un passage de l'écrivain paresseux n'a
rien laissé en attente (`power-cut = 2 => …`, la feature `trace-lazy-writer`), puis un troisième démarrage du même
disque, où la session s'ouvre (`expect-last`) ; la FAT relue après lui n'a aucune chaîne coupée. Sous QEMU (le
2026-11-19), les trois démarrages prennent 137 s (AMD) et 122 s (Intel) ; sans l'écriture différée des ruches (une
mutation), le troisième s'arrête sur « IncrementRefCount() failed (Error 2) » ; une ruche se réécrit sur le disque ATA en 10 à 210 ms.

Le disque n'a donc plus à être immuable. Démarrer l'image une fois, jusqu'au redémarrage de l'installation (QEMU
s'arrête de lui-même, `-no-reboot`), puis la convertir pour VirtualBox ; un disque `immutable` reste le moyen de
repartir à chaque essai de l'état d'après l'installation :

```bash
cargo xtask run --image mino-apps.img --memory 768 --headless   # l'installation (1 min 40 s), puis QEMU s'arrête
VBoxManage convertfromraw --format VDI mino-apps.img mino-apps.vdi
VBoxManage storageattach Mino --storagectl IDE --port 0 --device 0 --type hdd --medium mino-apps.vdi
```

(avec `--mtype immutable` en plus, VirtualBox jette les écritures de chaque session à la mise en marche suivante.)
La VM est celle de [`vbox.md`](vbox.md) (EFI, IDE PIIX4 en maître primaire, profil de CPU Intel), avec la mémoire
ci-dessus. Le VDI est dynamique : les secteurs à zéro de la place libre n'y sont pas écrits (520 Mio pour l'image des
dix, convertie en 2 s par VirtualBox 7.2.22). Pour éteindre, attendre quelques secondes après la dernière écriture,
puis couper la machine : le bouton ACPI de VirtualBox n'est pas encore entendu (pas de SCI), et l'arrêt par le menu
Démarrer (`ExitWindowsEx`, puis `winlogon` et NtShutdownSystem) n'est pas encore essayé. Sous QEMU seul, relancer
`cargo xtask run --image` sur l'image elle-même, ou sur une copie prise après l'installation. Le parcours sous
VirtualBox n'est pas encore essayé.

### Bilan du 2026-11-17

Sur `main` `5ca4cab`, AMD (`int 2Eh`), un passage par application (`cargo xtask test --boot --scenario app-<id>`).

| Application | Ce qui se passe | Service sans handler appelé juste avant |
|---|---|---|
| 7-Zip (MSI) | `msiexec` sort en 3 s avec 1627 (ERROR_FUNCTION_FAILED), son journal vide | NtLockFile |
| Notepad++ (NSIS) | silencieux : code 2 en 14 s ; visible : « Error! Can't initialize plug-ins directory » | NtQueryInformationFile (classe 0x23) ; aussi NtAccessCheck |
| KeePass (Inno) | « Unable to create a temporary file. Setup aborted. » | NtSetInformationFile (classe 0x13), NtQueryInformationFile (0x23) |
| WinMerge (Inno) | le même message | les mêmes |
| SumatraPDF | l'installeur plante en 3 s (0xC0000005) | NtQueryInformationProcess (classe 7, ProcessDebugPort) |
| AbiWord (NSIS) | comme Notepad++ | NtQueryInformationFile (0x23) |
| PeaZip (Inno) | comme KeePass | les mêmes |
| Dev-C++ (NSIS) | la boîte de bienvenue (répondue), le même message de plugins, mais ses fichiers sont copiés dans `C:\Dev-Cpp` (111 Mo) ; huit processus d'aide finissent sur un accès mémoire en `0x7C97B92E` (ntdll) ; `devcpp.exe` démarre et s'arrête sur « Exception EReadError in module devcpp.exe at 0001D967 » | pendant l'installation : NtAreMappedFilesTheSame, NtGdiCreatePaletteInternal, NtUserEnumDisplayMonitors, NtUserSetClassLong, NtGdiGetOutlineTextMetricsInternalW, NtUserUnregisterClass ; au lancement : NtGdiDoPalette, NtGdiGetTextCharsetInfo, NtGdiGetDCDword, NtGdiGetCharSet, NtUserGetObjectInformation |
| GIMP (Inno) | comme KeePass | les mêmes |
| Apache OpenOffice (NSIS) | la vérification de ses 143 Mo atteint 100 % en 440 s ; l'extraction écrit ~90 Mo jusqu'à la fin du délai (1500 s) | aucun bloquant vu |

Au démarrage de chaque installeur (CreateProcess, puis l'interface) : NtIsProcessInJob, NtApphelpCacheControl,
NtUserNotifyProcessCreate, NtSetInformationThread (classe 9), NtQueryDefaultUILanguage, NtUserCallOneParam (0x31),
NtUserCallHwnd, NtUserSystemParametersInfo (0x100A), NtUserSetThreadState, NtUserCallNoParam (0xF) : aucun n'arrête
seul un installeur.

Ce que le bilan désigne, dans l'ordre où il débloque le plus d'applications (des pistes, pas encore des causes
vérifiées) :

1. **NtSetInformationFile, classe 0x13** (FileAllocationInformation, que `SetEndOfFile` envoie après
   FileEndOfFileInformation) : les quatre Inno Setup. Fait le 2026-11-18 (plus bas).
2. **Le dossier de plugins de NSIS** (Notepad++, AbiWord, Dev-C++) : NtQueryInformationFile classe 0x23
   (FileAttributeTagInformation) est le seul service sans handler de la phase qui échoue. La classe est faite le
   2026-11-18 ; `DeleteFileW` va alors jusqu'à FileDispositionInformation (classe 0xd), qui ne l'est pas (la
   suppression, plus bas).
3. **NtLockFile** : `msiexec` (7-Zip, puis OpenOffice, dont l'installeur NSIS lance un MSI).
4. **SumatraPDF** : l'accès mémoire qui suit NtQueryInformationProcess(ProcessDebugPort).
5. **Dev-C++** : l'EReadError, puis le GDI et le USER qui lui manquent (palettes, métriques des polices, moniteurs).
6. **La lenteur des gros fichiers** : la vérification d'OpenOffice lit 143 Mo en 440 s. Deux suspects, à mesurer :
   le `kernel32` de ReactOS (variante DBG) écrit deux `DbgPrint` par ReadFile sur le port série (12 525 lignes), et
   un fichier de 143 Mo fait 280 000 clusters de 512 octets dans la FAT.

### Les quatre Inno Setup, le 2026-11-18

Ce qui manquait : FileAllocationInformation (`io_manager::File::set_allocation_size` : sous la fin du fichier, le
fichier est coupé là ; au-dessus, la taille ne change pas et le volume doit avoir les clusters qui manquent, sans
que la réservation soit gardée) et FileAttributeTagInformation (`File::attribute_tag_information` : les attributs,
l'étiquette 0). Le chargeur d'Inno Setup extrait son `setup.tmp` dans `C:\WINDOWS\TEMP\is-XXXXX.tmp\` en lui donnant
d'abord sa taille (SetFilePointer puis SetEndOfFile) : c'est la seconde classe de `SetEndOfFile` qui échouait
(« Error 1: Incorrect function »).

Un second défaut, de USER, gardait ensuite le chargeur jusqu'à la limite du banc (300 s, 900 s pour GIMP, à 27 s
du délai du scénario) après la fin de `setup.tmp` : il l'attend par `MsgWaitForMultipleObjects(1, &hProcess, FALSE,
INFINITE, QS_ALLINPUT)` et recommence tant qu'elle rend 1 ; `setup.tmp` envoie des messages à la fenêtre du chargeur
(`/SL5="$20060,…"`), et le bit de changement de `QS_SENDMESSAGE` restait levé après le dernier, si bien que
`user32` rendait 1 sans attendre. `win32k::queue` l'efface maintenant avec son bit de réveil quand il ne reste
plus de message envoyé, comme ClearMsgBitsMask. Le chargeur finit alors seul, avec le code de `setup.tmp`.

Sur la branche du banc, AMD, un passage par application :

| Application | Inno Setup | Ce qui se passe |
|---|---|---|
| KeePass | 5.3.10 | `setup.tmp` démarre et écrit son journal, « User privileges: None », puis « You must be logged in as an administrator when installing this program. » (OK supposé, en silencieux) : EAbort, le chargeur rend 1 en 11 s |
| WinMerge | 5.2.3 | la même chose, en 12 s |
| PeaZip | 5.4.2 | la même chose, en 14 s |
| GIMP | 5.4.3 | la même chose (« … or as a member of the Power Users group »), en 27 s |

Les planchers de leurs scénarios sont relevés là : la version d'Inno Setup et l'installeur d'origine dans le
journal, la fin du chargeur avec son code ; « Unable to create a temporary file » et un installeur arrêté par le banc
y sont interdits.

Ce qui venait ensuite, pour les quatre (fait le même jour, section suivante) :

1. **NtAccessCheck** (Se) : Inno Setup demande si l'utilisateur est administrateur (et, pour GIMP, de Power Users)
   par `CheckTokenMembership` d'`advapi32`, qui fait NtAccessCheck sur un descripteur dont la DACL donne l'accès 1 au
   SID du groupe ; sans handler, le groupe passe pour absent. Le banc tourne sous le jeton de System, où
   Administrators est activé : NtAccessCheck suffirait à passer ce point. Notepad++ l'appelle aussi.
2. **La suppression** (Io) : à sa sortie, le chargeur efface `setup.tmp` (`DeleteFileW` :
   FileAttributeTagInformation, puis FileDispositionInformation, classe 0xd, sans handler) ; le fichier et son
   répertoire restent dans `C:\WINDOWS\TEMP`. Sans effet sur l'issue aujourd'hui ; une installation qui remplace ou
   efface des fichiers en aura besoin, et NSIS pour son dossier de plugins (point 2 du bilan).

### NtAccessCheck et l'effacement, le 2026-11-18

Ce qui est fait :

- **NtAccessCheck** (`se::access`, `sys::security`) : SeAccessCheck d'XP (ReactOS comme spécification) ; les
  privilèges d'abord (`ACCESS_SYSTEM_SECURITY`, `WRITE_OWNER`), les droits du propriétaire, une DACL absente ou nulle
  qui accorde tout, les ACE dans l'ordre (refus, autorisation, « héritage seulement » ignorées, droits génériques
  par la correspondance de l'objet), `MAXIMUM_ALLOWED`. Le service rend le vrai résultat : le mode permissif de
  l'ADR-011 ne concerne que les ouvertures d'Ob. `CheckTokenMembership` trouve Administrators dans le jeton de
  System : « User privileges: Administrative ».
- **L'effacement** (Io, FAT) : FileDispositionInformation et FILE_DELETE_ON_CLOSE le mettent en attente, sur ce
  que le volume garde d'un fichier ouvert (son FCB : les objets fichiers qui ont un handle) ; le fichier part avec
  le dernier handle (`Volume::cleanup` : son entrée, celles de son nom long, même sur deux clusters, et ses
  clusters) ; une ouverture d'un fichier en attente rend `STATUS_DELETE_PENDING` ; un fichier en lecture seule
  (`STATUS_CANNOT_DELETE`), un répertoire qui tient quelque chose (`STATUS_DIRECTORY_NOT_EMPTY`) et la racine ne
  s'effacent pas.
- **Le banc** : il imprime aussi les 12 premières lignes du journal de l'installeur (sa version, qui l'exécute), et
  entre elles et les 40 dernières, celles qui disent une erreur (« error », « fail », « exception », « rolling
  back », « abort ») ; il répond à une boîte par son bouton par défaut (DM_GETDEFID : Oui d'une question), plus
  seulement par IDOK.

Sur la branche, AMD, un passage par application :

| Application | Ce qui se passe |
|---|---|
| KeePass (Inno 5.3.10) | **installée** en 10 s : Setup rend 0, ses fichiers sont dans `C:\Program Files\KeePass Password Safe` sans temporaires laissés ; `KeePass.exe` démarre, puis finit sur un accès mémoire non géré (0xC0000005) |
| WinMerge (Inno 5.2.3) | Setup copie ses fichiers, puis l'enregistrement d'une DLL échoue (« RegSvr32 failed with exit code 0x3 ») : Abandonner, supposé en silencieux, et retour arrière ; Setup rend 5 |
| PeaZip (Inno 5.4.2) | Setup crée son répertoire temporaire, puis finit sur STATUS_BAD_STACK (0xC0000028, levée par RtlUnwind de `ntdll`) en 8 s, avant de commencer l'installation |
| GIMP (Inno 5.4.3) | de même, après son script (associations, pages de l'assistant) |
| Notepad++ (NSIS) | **installé** en 66 s (le dossier de plugins : un fichier temporaire effacé, puis un répertoire de son nom) ; `notepad++.exe` démarre, puis finit sur 0xC0000005 |
| AbiWord (NSIS) | **installé** en 108 s ; `AbiWord.exe` démarre, puis finit sur 0xC0000005 |
| Dev-C++ (NSIS) | **installé** en 459 s : ses fichiers, puis « Do you want to install Dev-C++ for all users on this computer ? » (Oui), et NSIS rend 0 ; `devcpp.exe` s'arrête toujours sur « EReadError … Code: 120 » (ERROR_CALL_NOT_IMPLEMENTED, en lisant le glyphe d'un bouton) |

L'apitest NtAccessCheck de `ntdll` passe de nouveau (`rostests` : 44/84 sur un hôte chargé, où
NtProtectVirtualMemory dépasse ses 20 s ; le plancher reste 44) ; `kernel32` reste à 16/29.

Les planchers des sept scénarios sont relevés à ce qui marche : les fichiers installés et le programme démarré pour
KeePass, Notepad++, AbiWord et Dev-C++ ; « User privileges: Administrative » et la fin de Setup pour les autres. Y
sont interdits « Unable to create a temporary file », « User privileges: None », « Can't initialize plug-ins
directory » et un installeur arrêté par le banc.

Ce qui venait ensuite, dans l'ordre où cela débloque le plus (le premier point est fait le lendemain, section
suivante) :

1. **L'accès mémoire des programmes installés** (KeePass, Notepad++, AbiWord ; peut-être SumatraPDF, dont
   l'installeur finit de même) : le filtre des exceptions non gérées de `kernel32` le prend (d'où
   NtQueryInformationProcess(ProcessDebugPort), puis NtRaiseHardError, puis la fin du processus avec 0xC0000005),
   si bien que rien ne journalise l'adresse. ProcessDebugPort en est une conséquence, pas la cause. Une trace
   temporaire de `sys::exceptions` (adresse, registres, octets du code) trouvera l'instruction et sa DLL.
2. **STATUS_BAD_STACK d'Inno Setup 5.4** (PeaZip, GIMP) : RtlUnwind trouve un cadre SEH hors des limites de pile
   du TEB, ou mal aligné. KeePass (5.3) et WinMerge (5.2) ne le rencontrent pas. Les limites du TEB suivent bien la
   croissance de la pile (`AddressSpace::extend_user_stack`) ; à chercher du côté des rappels du mode utilisateur
   (une exception levée dans une procédure de fenêtre appelée par win32k et attrapée au-dessus).
3. **L'enregistrement des DLL** (WinMerge) : Inno lance son aide d'enregistrement, qui rend 3 sur
   `ShellExtensionU.dll` ; à suivre par les services sans handler de ce processus.
4. **Le renommage** (NtSetInformationFile classe 0xa, FileRenameInformation) : Inno installe chaque fichier sous un
   nom temporaire puis le renomme ; sans renommage, il copie puis efface. Pas bloquant, mais lent et à faire.
5. **Les raccourcis** : CoCreateInstance(CLSID_ShellLink) rend REGDB_E_CLASSNOTREG sur le disque du banc (les
   serveurs COM de `shell32` ne sont enregistrés que par `minoinit`, au premier démarrage d'une installation) ;
   Inno passe outre.

### Le plantage des programmes installés, le 2026-11-19

La cause : la liste des tas du processus (`ProcessHeaps`) suivait le PEB à 0x210, la taille du PEB d'XP. Le mode
utilisateur de ReactOS est construit pour Server 2003, dont le PEB a ses champs de stockage local aux fibres (FLS)
de 0x20C à 0x22F et fait 0x230 : `ntdll` y met son bitmap des index FLS (`FlsBitmap`, en 0x218), FlsAlloc de
`kernel32` le lit, et le noyau de ReactOS place la liste des tas après eux (`Peb + 1`). Chaque tas qu'un processus
crée s'inscrivait sur ces champs ; au quatrième (celui d'un CRT, de MFC), `Peb->FlsBitmap` désignait un tas, et
FlsAlloc, que le CRT de MSVC appelle à son démarrage, lisait l'adresse 0 dans RtlFindClearBits. Une trace
temporaire de `sys::exceptions` (adresse, registres, octets du code, pile) et la pile que le filtre des exceptions
de `kernel32` imprime l'ont montré : `ntdll!RtlFindClearBits` ← `RtlFindClearBitsAndSet` ← `kernel32!FlsAlloc` ←
`KeePass.exe`. `abi::peb32` a maintenant les champs FLS (0x230), et la liste des tas commence après eux
(`PROCESS_HEAPS_OFFSET`) ; les champs de version restent ceux d'XP (ADR-003).

Les nombreux accès invalides en `ntdll!strncpy` (0x7C97B92E) que la trace montre aussi viennent des `TRACE` de
ReactOS, qui lisent un identifiant de ressource comme une chaîne : ils sont rattrapés, sauf dans les processus
d'aide de Dev-C++ (huit, qui finissent ainsi).

Sur la branche, AMD, un passage par application :

| Application | Ce qui se passe |
|---|---|
| KeePass | ne plante plus : sa fenêtre principale s'ouvre (arbre, liste, New, Open, Save…) ; son titre se lit « K » ; elle ne se ferme pas sur WM_CLOSE en 15 s, le banc la termine |
| Notepad++ | ne plante plus : il montre « Authenticode check failed: signing certificate or hash is not recognized » (« DLL signature verification failed ») : il vérifie la signature de sa propre DLL |
| AbiWord | plante encore, ailleurs : `libAbiWord.dll` lit l'adresse 0x3C (le champ d'un objet nul), juste après NtGdiGetOutlineTextMetricsInternalW et NtGdiGetCharWidthW, sans handler |
| SumatraPDF | l'installeur ne plante plus : il ne trouve pas `ktmw32.dll` (une DLL de Vista), puis `userenv` rend l'erreur 2 (un profil introuvable), et il rend 1 en 5 s |
| Dev-C++ | inchangé : `devcpp.exe` s'arrête sur EReadError (code 120) |

Les planchers de KeePass et de Notepad++ attendent la fenêtre du programme et interdisent sa fin sur 0xC0000005.

Ce qui vient ensuite, dans l'ordre où cela débloque le plus :

1. **Authenticode** (Notepad++) : WinVerifyTrust et la chaîne de certificats de `wintrust` et `crypt32` de ReactOS.
2. **NtQueryInformationProcess, classe 7** (ProcessDebugPort ; AbiWord et SumatraPDF) : rendue sans handler, sa
   sortie reste ce qu'on lui donne et AbiWord lit son débogueur au pointeur nul (sa faute à `0x3C`, dans
   `AbiWord.exe`).
3. **Le profil que `userenv` ne trouve pas** (SumatraPDF) : le banc remplace `winlogon` et tourne sous le jeton
   de System, sans session ouverte.
4. **KeePass** : WM_CLOSE de sa fenêtre principale, et son titre.
5. Et toujours : l'enregistrement de DLL de WinMerge, le renommage (FileRenameInformation), EReadError de Dev-C++,
   les processus d'aide de Dev-C++.

### STATUS_BAD_STACK d'Inno Setup 5.4, le 2026-11-20

Ce qui manquait, en deux couches.

**La pile.** `RtlUnwind` de `ntdll` refuse tout cadre SEH posé sous `StackLimit` (`STATUS_BAD_STACK`), et la
croissance de pile de Mino laissait les deux désaccordés : la faute de garde committe la page touchée mais la
limite ne suivait pas, et la première page de la réserve restait au-dessus d'une pile utilisable.
`mm::fault::stack_extension` récrit : la limite suit toujours la page touchée, la garde ne descend que s'il
lui reste une page (la première page de la réservation ne se commite jamais), et une violation d'accès dans
la réserve étend la pile aussi — `MiCheckForUserStackOverflow` est appelé des deux, et une pile pleine n'a
plus de garde. Les deux services rendent `STATUS_STACK_OVERFLOW` à la première page de la réserve. Le smoke
vérifie les deux (`overflow` pousse jusqu'au dépassement, `guarded` hors de la pile).

**Le filtre des messages de débogage.** `NtQueryDebugFilterState` de Mino rendait `TRUE` pour tous les
composants et tous les niveaux, si bien que le `DbgPrintEx` de `ntdll` formatait chaque message chez
l'appelant avant de l'envoyer. Or le TRACE de `LCMapStringW` (locale.c:3812 du payload) pousse **`srclen` à
la place du pointeur que `debugstr_wn` devrait rendre** : le `%s` du format recevait `0x100`, et le
`strlen` du formateur lisait l'adresse 0x100, hors de toute projection — un accès mémoire de plus à chaque
`LCMapStringW` du traitement d'exception de Delphi. Le filtre suit XP maintenant (`Kd_WIN2000_Mask = 1` de
ReactOS : le niveau ERROR seul passe — celui du `DbgPrint` sans composant, de `DPRINT1` et de minoinit) ; le
TRACE de locale.c ne se formate plus du tout. Les autres niveaux attendent la clé de registre `Debug Print
Filter` (pas encore lue).

**Ce qui reste.** L'installeur finit toujours sur `STATUS_STACK_OVERFLOW`, mais sans plus aucune exception
de débogage dans la boucle : son propre code recurse (chaque niveau refaute à `0x401dc7`, lisant la page
`0xf46f61` de son tas, non projetée chez Mino) et la récursion épuise la réserve d'un fil. C'est le
blocage suivant : pourquoi la page du tas que la cible tient projetée ne l'est pas ici — le commit du tas ou
un pointeur au-delà du bloc.

**Scénarios réajustés** pour les lignes de TRACE que le filtre ne laisse plus imprimer : `logon` (le
marqueur du listage du bureau prend la ligne ReadDirectoryChangesW d'explorer), `power-cut` (sa chaîne
`expect-last`, et le déclencheur de la coupure), `smss` (les trois `Pipe name` de npipe.c, dont la preuve
est déjà dans les sondes `[m4]` des deux appels). Tests hôtes : `stack_extension` récrit ; le smoke attend
FALSE pour (0xC8, 2).

### Les métriques des polices, le 2026-11-20

Ce qui manquait : NtGdiGetCharWidthW (GreGetCharWidthW : l'avance de chaque glyphe, arrondie au pixel —
`win32k::gdi::fontobj::char_widths`, par `font::advances`) et NtGdiGetOutlineTextMetricsInternalW
(`IntGetOutlineTextMetrics` de `freetype.c` : la partie fixe de 216 octets — la structure de ReactOS s'arrête au quatrième nom — puis les quatre noms en chaînes
larges, leurs positions dans `otmp*` ; `glyph::Font::outline_numbers` lit `OS/2`, `hhea`, `head` et `post`,
`win32k::font::outline` met les nombres à la hauteur du LOGFONT, `fontobj::outline_metrics` les assemble ; la
`gdi32` de ReactOS relit ces noms comme des chaînes larges, et son GetOutlineTextMetricsA les convertit).
AbiWord passe alors `libAbiWord.dll` — ses cadres de faute — et sa faute monte dans `AbiWord.exe` : le
ProcessDebugPort du point 3. Les largeurs restent entières : `GCW_INDICES` et les flottants de GetCharWidth,
que personne du banc ne demande, attendent. Le scénario `app-abiword` interdit désormais les deux services
non faits ; tests hôtes `fontobj::tests::char_widths_are_the_advances_of_the_glyphs` et
`an_outline_text_metric_carries_its_names_and_numbers`.

### NtLockFile : 7-Zip s'installe, le 2026-11-20

`msiexec` ouvre son paquet par le stockage structuré d'`ole32` (StgOpenStorage), qui verrouille des plages
d'octets loin derrière la fin du fichier (`0x7FFFFF00` et au-delà, LockFileEx avec LOCKFILE_FAIL_IMMEDIATELY) et
boucle tant qu'elles sont en conflit. NtLockFile et NtUnlockFile sont faits : `io::file_lock`, le FILE_LOCK du FCB
de chaque fichier, d'après FsRtl de ReactOS (`fsrtl/filelock.c`) et la documentation publique de LockFileEx, sans
portage de code ; NtReadFile et NtWriteFile respectent les verrous ; ceux d'un objet fichier partent avec son
dernier handle.

`msiexec` allait alors plus loin et s'arrêtait encore deux fois (une trace temporaire de ses services, non
commitée) :

- CreateDirectoryW de `C:\WINDOWS\Installer\`, où il copie le paquet : `kernel32` garde le `\` final, et
  NtCreateFile rendait `STATUS_OBJECT_NAME_INVALID` (un dernier composant vide). Comme vfatfs, un `\` final est
  permis à un répertoire (FILE_DIRECTORY_FILE) et refusé à un fichier (`io_manager::split_to_create`).
- `ProgramFilesFolder` vide : `msi` le lit dans `ProgramFilesDir`, que syssetup écrit à l'installation de
  ReactOS (InitializeProgramFilesDir) ; `mino.inf` ne l'avait pas, et 7-Zip s'installait dans le répertoire
  courant de `msiexec`, `C:\WINDOWS\System32\7-Zip`. `ProgramFilesDir` et `CommonFilesDir` sont dans `mino.inf`.

Sur la branche, AMD : `msiexec` rend 0 en 11 s, `C:\Program Files\7-Zip` tient ses programmes, `7z.dll` et ses langues, `7zFM.exe`
ouvre « 7-Zip File Manager » et se ferme avec 0. Le parcours (archiver un fichier, l'extraire, comparer) est fait
depuis : voir [plus bas](#le-parcours-de-7-zip-le-2026-11-22). OpenOffice, dont l'installeur NSIS lance un MSI, n'a pas été remesuré (1 500 s de banc).
### Authenticode : le banc dans une session, le 2026-11-21

Notepad++ 7.9.2 vérifie la signature de ses propres DLL (`SciLexer.dll`) : WinVerifyTrust, puis le certificat du
signataire par CryptQueryObject, CryptMsgGetParam, CertFindCertificateInStore, CertNameToStr,
CertGetCertificateContextProperty et CertGetNameString (`verifySignedfile.cpp` de Notepad++). Sous le banc, il
montrait « DLL signature verification failed » (« Unknown exception occurred ») puis « Authenticode check failed:
signing certificate or hash is not recognized ».

- CryptQueryObject rendait CRYPT_E_NO_MATCH : `crypt32` lit bien la table des certificats du PE, mais ne décode pas
  le PKCS#7 faute de fournisseur cryptographique. CryptAcquireContext de `rsaenh` (repris de Wine) demande le nom
  de l'utilisateur, même en CRYPT_VERIFYCONTEXT ; GetUserNameW demande à LSA (`\pipe\lsarpc`), et le banc, qui
  remplaçait `winlogon`, tournait sans `lsass` : RPC_S_SERVER_UNAVAILABLE.
- FormatMessage de ReactOS ne connaît pas `0x80092009` : le message d'erreur de Notepad++ concaténait un tampon
  nul, faute attrapée par son `catch (...)` (compilé en `/EHa`).
- La ruche SOFTWARE épinglée n'a aucune clé `Cryptography` (fournisseurs, fournisseurs de confiance, SIP), que
  `syssetup` pose à l'installation de ReactOS par les DllRegisterServer de `syssetup.inf`.

Correctifs : `minoinit` enregistre aussi `cryptnet`, `mscat32`, `msisip`, `rsabase`, `rsaenh`, `softpub` et
`wintrust` ; et le banc tourne dans une vraie session (choix du mainteneur) : la clé `session = APPBENCH.EXE` garde
le vrai `winlogon`, `minoinit` installe au premier démarrage, l'ouverture de session automatique a lieu au second,
et `userinit` lance le banc comme shell de l'utilisateur (`Winlogon\Shell` de la ruche du scénario), sous son jeton,
avec `lsass` et son profil. Le scénario `authenticode` (`tests/native/auth1.c`) refait les appels de Notepad++ sur
son installeur, signé du même certificat : WinVerifyTrust rend 0, le signataire est « Notepad++ ».

Notepad++ s'arrêtait alors sur « Exception On WM_CREATE » (« Unknown exception ») : GetNumaHighestNodeNumber de
`kernel32` échouait, NtQuerySystemInformation(SystemNumaProcessorMap, 55) n'étant pas servie. Elle l'est, comme
`ex/sysinfo.c` de ReactOS (un nœud, les processeurs de SystemBasicInformation). Notepad++ ouvre « new 1 -
Notepad++ » et se ferme avec 0. Son parcours (taper, remplacer, enregistrer, rouvrir) reste à faire.

### La page de progression des NSIS, le 2026-11-21

Le wizard visible (le banc en session, l'installateur sans `/S`) montre la page de progression abîmée :
l'en-tête blanc sans son titre, des restes de l'image de la page d'accueil à gauche (la zone libérée non
repeinte), la barre de progression dont le texte avance mais pas le remplissage. Reproduit dans le scénario
`app-npp-interactive` (l'installeur de Notepad++ 7.9.2 poussé par la souris de QEMU : les clics au bout
Volgende/I Agree/Install, les captures en screen.ppm converties en PNG).

La mesure (la trace temporaire des services win32k de l'installateur : 52 526 appels) : les dessins passent
par les services déjà faits (BitBlt 398, StretchDIBits 149, IntersectClipRect 717, GetRandomRgn 687) et les
manquants du symptôme sont **NtGdiSaveDC, NtGdiRestoreDC, NtGdiExtCreatePen** (faits le 2026-11-21, plus
haut), puis NtGdiGetTransform (10 appels), NtGdiSetLayout (7), NtUserSetClassLong, NtUserCallOneParam
0x20/0x28, NtGdiSetDIBitsToDeviceInternal, NtUserSelectPalette, NtGdiGetDCforBitmap. **NtGdiSaveDC et
NtGdiRestoreDC** : la pile d'états du DC (`gdi::dc::save_state`/`restore_state`, d'après DC_vRestoreDC de
ReactOS comme spécification) — les niveaux relatifs négatifs, les poses d'après effacées, la région visible
hors de l'état sauvé (« Get/SetDCState() don't change hVisRgn field », DC_vCopyState), le bitmap seulement
pour un DC en mémoire. **NtGdiExtCreatePen** (`Pen::ext_create`) : PS_NULL et BS_NULL rendent le stylo nul,
un cosmétique d'un pinceau non plein refusé, les longs de style d'utilisateur lus puis jetés (les pointillés
se dessinent en approximations). **L'effacement parent** (`paint::expose`) : ce qu'un enfant découvre dans
son parent s'efface avec le fond de sa classe (le « erasing what a child window uncovers in its parent » tirait
à chaque wizard, et les restes de l'image d'accueil restaient sur le cadre).

**La page de progression reste abîmée après tout cela** : les captures montrent l'en-tête vide et la barre au
début, avec le texte qui avance (« Pak uit: cxmi… 57 % »). Le diagnostic continue : les exposés de
l'installeur tracent des rectangles aux coordonnées du bureau (391, 229)-(888, 543) quand le wizard se voit à
(0, 0)-(497, 378) — la divergence des espaces de coordonnées entre les régions de peinture et les rectangles
des fenêtres est la piste suivante, avec les restes du bitmap hors du rectangle de la page.

### CALLPROCDATA : Inno Setup 5.4 installe, le 2026-11-21

Les installeurs Inno Setup 5.4 (PeaZip 5.4.2, GIMP 5.4.3, tous deux ANSI) finissaient sur `STATUS_STACK_OVERFLOW`,
et en session sur une boîte de Delphi « EAccessViolation ». Le bilan précédent y voyait une page du tas que Mino ne
projetait pas. Mesuré cette fois :

- une trace temporaire (jamais commitée) des services et des exceptions des processus de l'installeur (le nom
  d'image d'EPROCESS est tronqué à 15 caractères : `peazip-plain-3.`, pour le chargeur comme pour `setup.tmp`) ;
- le `setup.tmp` récupéré du disque d'un ancien run (son entrée effacée de `Local Settings\Temp`, ses clusters
  contigus), désassemblé : `0x401dc7` est `InsertFree` du gestionnaire de mémoire de Delphi (la taille d'un bloc
  libre écrite à sa fin), et l'adresse impaire `0xf46f61` n'est pas une page oubliée mais une taille de bloc
  corrompue ; à la faute suivante, la liste libre vaut `0x67610074` et `0x4e0065`, du texte UTF-16 ;
- juste avant, le contrôle mesurait les caractères `0x3a43 0x505c 0x6f72…` : « C:\Program Files\PeaZip » en ANSI,
  lu comme de l'UTF-16.

Le TEdit de Delphi prend la procédure d'Edit par GetClassInfoA et l'appelle par CallWindowProcA ; le manifeste de
`setup.tmp` fait d'« Edit » celui de `comctl32` 6 (une classe Unicode sans FNID, `EDIT_Register`), et win32k
rendait sa procédure telle quelle à l'appelant ANSI. Le contrôle lisait donc son texte ANSI en UTF-16, et son
WM_GETTEXT écrivait deux octets par caractère dans le tampon ANSI que Delphi avait alloué pour la longueur. ReactOS
rend là une procédure d'appel (CALLPROCDATA), que CallWindowProcA convertit : c'est fait, avec deux écarts de la
même règle trouvés par le scénario de test (la classe d'un contrôle de `user32` vue par la procédure du client du
jeu demandé ; un contrôle créé en ANSI est une fenêtre ANSI). Le détail est à l'étape 47 de
[`m6-fenetres.md`](m6-fenetres.md), le test est le scénario `ansi-controls`.

Le banc après le correctif, AMD, en session :

| Application | Avant | Maintenant |
|---|---|---|
| PeaZip | `setup.tmp` finit sur `STATUS_STACK_OVERFLOW` en 11 s | l'installation commence et copie 78 fichiers dans `C:\Program Files\PeaZip`, puis ne peut créer `res\themes\nographic-embedded\fm-theme.bmp` (« The system cannot find the path specified ») et revient en arrière (code 5) : le répertoire, au nom long de 18 caractères, est sur le disque sans son nom long (seule l'entrée 8.3 `NOGRAP~1`), alors que `firecrystal.theme.7z`, de 20 caractères, a le sien |
| GIMP | la boîte « EAccessViolation », l'installeur terminé par le banc après 900 s | **s'installe** : code 0 en 558 s, « Installation process succeeded », 116 Mio écrits ; `gimp-2.6.exe` démarre puis lit l'adresse `0xC` dans `libgdk-win32-2.0-0.dll` juste après NtUserEnumDisplayMonitors, sans handler (aucun moniteur) |
| KeePass | son titre se lit « K » | son titre se lit « KeePass » ; il ne se ferme toujours pas sur WM_CLOSE |
| AbiWord | (le 2026-11-20) `libAbiWord.dll` lit `0x3C` | ouvre « Untitled1 - AbiWord » et se ferme avec 0 — déjà sur la base de la branche (`9014bc5`), pas l'effet de CALLPROCDATA |
| WinMerge, Dev-C++, Notepad++, SumatraPDF, 7-Zip | — | inchangés : WinMerge et Dev-C++ plantent au lancement de leur programme (0xC0000005, « Application Error »), Notepad++ ouvre « new 1 », SumatraPDF n'est pas trouvé où le banc le cherche, 7-Zip ouvre son gestionnaire |

Les installeurs Inno déplacent chaque fichier par MoveFile, que `kernel32` fait par une copie puis un effacement
(« Forcing copy, renaming not supported by FSD » : FileRenameInformation, la classe 0xa de NtSetInformationFile,
n'a pas de handler) : 1 729 fois pour GIMP. Le plancher de PeaZip attend « Starting the installation process. » et
interdit la fin sur `STATUS_STACK_OVERFLOW` ; celui de GIMP attend l'installation réussie et le programme lancé. Son
journal (650 Ko) dépasse le tampon du banc, qui n'en imprime que les 64 derniers Kio : le plancher ne peut plus
attendre la version d'Inno ni les privilèges, écrits au début (à corriger dans `appbench.c`).

La suite pour ces applications : le nom long d'un répertoire créé (PeaZip), NtUserEnumDisplayMonitors (GIMP),
FileRenameInformation (tous les Inno).

### Un nom long dans un trou, le 2026-11-21

PeaZip copiait ses fichiers puis ne pouvait créer `res\themes\nographic-embedded\fm-theme.bmp` (« The system cannot
find the path specified »). Les emplacements du répertoire `themes` sur le disque du run (lus emplacement par
emplacement, les effacés compris) : les deux entrées de nom long de `nographic-embedded` dans les emplacements 2
et 3, son entrée 8.3 `NOGRAP~1` dans le 10, entre elles les entrées de deux fichiers. Les emplacements 2 et 3 étaient
un trou : Inno déplace chaque fichier installé par MoveFile, que `kernel32` fait par une copie puis un effacement
(FileRenameInformation manque), et l'effacé laisse ses emplacements libres. `io::fat` mettait chaque entrée d'un nom
dans le premier emplacement libre, une à une : le nom long, séparé de son entrée 8.3, n'était plus reconnu, et le
répertoire ne se trouvait plus par son nom long, celui que PeaZip demande ; son alias `NOGRAP~1` se trouvait encore
(`FatVolume::find_entry` compare l'entrée 8.3 seule).

Comme `vfatFindDirSpace` de `vfatfs` (FATAddEntry), les entrées d'un nom prennent maintenant une suite
d'emplacements libres consécutifs (`FatVolume::add_entries`, d'un cluster au suivant au besoin) ; un trou trop
court est sauté, un trou qui suffit est repris, et sans suite assez longue le répertoire grandit avant que rien ne
soit écrit. PeaZip s'installe (code 0 en 91 s, « Installation process succeeded »), `peazip.exe` ouvre sa fenêtre
« PeaZip » et se ferme avec 0 sur WM_CLOSE ; plancher relevé. Test hôte
`a_long_name_takes_a_run_of_free_slots_past_a_short_hole`, qui échoue sans le correctif (l'entrée 8.3 à
l'emplacement 7, la disposition du disque de PeaZip).

Vu en chemin, au lancement de `peazip.exe` : NtUserSetClassLong et NtUserChildWindowFromPointEx sans handler, une DIB
section de 24 bits refusée (« not yet ») ; la fenêtre s'ouvre quand même. Son parcours (ouvrir une archive,
l'extraire) reste à faire.

### EnumDisplayMonitors : le GIMP s'ouvre, le 2026-11-22

`gimp-2.6.exe` lisait l'adresse `0xC` dans `libgdk-win32-2.0-0.dll` juste après NtUserEnumDisplayMonitors, sans
handler : il rendait 0, EnumDisplayMonitors de `user32` (qui demande le compte, puis les listes) ne rappelait rien, et
gdk restait sans moniteur. Fait comme `monitor.c` de ReactOS (`sys::monitor::nt_user_enum_display_monitors`,
`win32k::monitor::search_area`, `intersecting`, `enumerate`) : le nombre de moniteurs que coupe la zone — le
rectangle donné à l'écran, ou depuis la borne de la région visible du DC, ou cette borne ; ni l'un ni l'autre :
tout l'écran virtuel —, leurs handles et la partie coupée de chacun. Scénario `enum-monitors`
(`tests/native/enummon1.c`, AMD et Intel) ; deux mutations le font échouer (sans handler ; les rectangles d'un DC
non ramenés à son coin).

Une première relance sans la PR 162 a fini sur `STATUS_DLL_NOT_FOUND` : `libgimpbase-2.0-0.dll` avait son nom long
coupé (« libgimpbase-2 » : la seconde partie dans un trou du répertoire `bin`, le défaut de la PR 162), la
disposition des trous changeant d'un run à l'autre. Sur la PR 162, le GIMP s'installe (code 0) et `gimp-2.6.exe`
ouvre sa fenêtre « GIMP Startup » (`gdkWindowToplevel`) ; il ne se ferme pas en 15 s sur WM_CLOSE, le banc le
termine. Plancher relevé (la fenêtre attendue, toute fin du programme par lui-même interdite).

Vu ensuite dans son démarrage : NtUserGetThreadDesktop, NtUserGetObjectInformation, NtUserFindWindowEx,
NtUserGetDoubleClickTime, NtUserMapVirtualKeyEx, NtGdiModifyWorldTransform, NtGdiSaveDC et NtGdiRestoreDC (pris par
une autre session) sans handler, une DIB section de 1 bit refusée.

### SetThreadPriority : le GIMP interroge ses greffons, le 2026-11-22

Laissé plus longtemps derrière sa fenêtre « GIMP Startup » (le banc la fermait 16 s après), le GIMP montrait une
boîte « Error » de GLib : « g_thread_set_priority_win32_impl: error Incorrect function. during SetThreadPriority ».
SetThreadPriority de `kernel32` est NtSetInformationThread(ThreadBasePriority, classe 3), sans handler :
`STATUS_NOT_IMPLEMENTED`, que `kernel32` traduit en ERROR_INVALID_FUNCTION, et GLib s'arrête. Fait comme ReactOS
(`ps/query.c`, KeSetBasePriorityThread, KeQueryBasePriorityThread ; `sys::process::nt_set_information_thread`,
`ps::ethread::base_priority_of`, `EThread::set_base_increment`, `base_increment`) : un incrément de -2 à 2, ou ±16
(la saturation que `kernel32` passe pour THREAD_PRIORITY_TIME_CRITICAL et THREAD_PRIORITY_IDLE), tout incrément
dans un processus temps réel, sinon `STATUS_INVALID_PARAMETER` ; la priorité de base est celle du processus plus
l'incrément, gardée dans la classe du processus (de 1 à 15, ou de 16 à 31 en temps réel) ; le thread garde sa
saturation, que ThreadBasicInformation (GetThreadPriority) rend comme ±16. Scénario `thread-priority`
(`tests/native/prio1.c`, AMD et Intel) ; deux mutations le font échouer (la classe refusée ; la saturation oubliée) ;
test hôte `a_thread_base_priority_stays_in_its_process_class`.

Sans l'erreur, le GIMP interroge ses greffons à son premier démarrage : un processus chacun (`wind.exe`,
`whirl-pinch.exe`… `color-exchange.exe`, dans l'ordre inverse de l'alphabet), 152 en 300 s. Le banc laisse
maintenant à un programme le temps de démarrer (`program_seconds` de `xtask/src/apps.rs`, `settle=` de `PROBE.TXT` ;
5 s par défaut, 600 s pour le GIMP), et imprime ses fenêtres chaque minute. Le GIMP ouvre alors sa boîte à outils (« Toolbox »), la
fenêtre « Layers, Channels, Paths, Undo - Brushes, Patterns, Gradients » et celle de l'image (« GNU Image
Manipulation Program »), entre 440 et 560 s après son lancement, et se ferme avec 0 sur WM_CLOSE ; plancher relevé
(la boîte à outils, la fermeture). KeePass, au délai par défaut, ne change pas.

Restent à son démarrage, sans handler : NtUserGetThreadDesktop, NtUserGetObjectInformation, NtUserFindWindowEx,
NtUserGetDoubleClickTime, NtUserMapVirtualKeyEx, NtGdiModifyWorldTransform, NtGdiGetRegionData,
NtGdiExtCreateRegion ; une DIB section de 1 bit refusée. Son parcours (ouvrir une image, un filtre, l'export PNG)
reste à faire.

### Le parcours du GIMP, le 2026-11-22

Le parcours de la liste (« ouvrir une image, appliquer un filtre, exporter en PNG ») tourne en Script-Fu, sans
interface : `gimp-console-2.6.exe -i -d -f -b "(load \"C:/APPS/ROUTE.SCM\")" -b "(gimp-quit 0)"`. Le script ouvre
`C:\APPS\ROUTE.BMP` (32 × 32, la moitié gauche noire, la droite blanche, écrit par `xtask` :
`apps::half_black_bmp`), le floute (`plug-in-gauss`, rayon 10), l'exporte en `ROUTE.PNG` (`file-png-save`), rouvre le
PNG et lit le pixel de la frontière : gris (142). Chaque étape passe par un greffon, donc un processus (`file-bmp`,
`blur-gauss`, `file-png`, `script-fu`), et ses messages vont à la sortie de `gimp-console`. Le banc a pour cela une
commande de parcours par application (`route` de `xtask/src/apps.rs`, `route=` et `route-seconds=` de `PROBE.TXT`,
ses fichiers dans `C:\APPS`) : il la lance après le programme, sa sortie et ses erreurs dans
`C:\APPS\ROUTE.LOG`, puis imprime son code de fin, sa sortie et ce qu'est `ROUTE.PNG`. Résultat : « batch command
executed successfully », code 0 en 144 s, `ROUTE.PNG` un PNG de 149 octets.

L'attente du programme est devenue déterministe : au-delà de 5 s, le banc attend que le programme montre une autre
fenêtre que sa première (puis 10 s), au plus `program_seconds` (900 s pour le GIMP) ; un premier run, sur un hôte
chargé, avait vu la boîte à outils arriver juste après les 600 s fixes d'avant.

Plancher du GIMP : son installation, sa boîte à outils, sa fermeture par WM_CLOSE, puis chaque étape du parcours, le
pixel gris et le PNG ; interdits : un parcours qui ne démarre pas ou dépasse son délai.

### Le parcours de 7-Zip, le 2026-11-22

Le parcours de la liste (« archiver un fichier, l'extraire, comparer ») passe par la ligne de commande de 7-Zip,
`7z.exe`, dans un fichier de commandes que `cmd.exe` exécute : `C:\WINDOWS\system32\cmd.exe /c C:\APPS\ROUTE.CMD`.
`xtask` écrit dans `C:\APPS` le texte à archiver, `ROUTE.TXT` (2 000 lignes numérotées, 133 790 octets :
`apps::route_text`), et `ROUTE.CMD` (lignes CRLF) : `7z a` crée `ROUTE.7Z`, `7z t` le teste, `7z x -y -oC:\APPS\OUT`
l'extrait, `fc /b` compare l'extrait à l'original ; chaque étape qui échoue termine `cmd.exe` avec son propre code
(`exit 1` à `exit 4`). Pas `exit /b N` : le `cmd` de ReactOS 0.4.16 ne le transmet pas. Un fichier de commandes y
rend le code de sa dernière commande (`Batch`, `base/shell/cmd/batch.c`), et `exit /b` dans un fichier rend 0
(`CommandExit`, `internal.c`, qui ne pose que `nErrorLevel`) : `cmd /c` finissait avec 0 quand `fc` trouvait une
différence. C'est le `cmd` épinglé, pas le noyau ; `exit N` arrête l'interpréteur avec N. Le banc décrit le fichier que fait le parcours, quel qu'il soit (`route-output=` de `PROBE.TXT`, `output` de
`apps::Route`) : sa taille, s'il est un PNG et ses six premiers octets. Rien à corriger dans le noyau : du premier
coup, « Everything is Ok » aux trois commandes, « FC: no differences encountered », code 0 en 2 à 12 s, `ROUTE.7Z` de
2 202 octets qui commence par la signature de 7z (`37 7a bc af 27 1c`). Le scénario passe en 73 s (AMD, noyau déjà
construit).

Plancher de 7-Zip : son installation, son gestionnaire de fichiers, puis chaque étape du parcours (compression, test,
extraction, comparaison, la ligne finale du fichier de commandes), le code 0 et la signature de l'archive ; interdits :
un parcours qui ne démarre pas ou dépasse son délai. Vérifié par mutation : `fc /b` qui compare `ROUTE.TXT` à
`ROUTE.CMD` trouve la différence, le fichier de commandes finit avec 4 et le scénario échoue (la comparaison, la
ligne finale et le code 0 manquent) ; avec `exit /b 4`, il finissait avec 0.

### La suite

**Mise à jour du 2026-11-20 : ProcessDebugPort** (`fix/ps-process-debug-port`).
La classe 7 de NtQueryInformationProcess est maintenant servie : un HANDLE i386 nul,
aucun processus de Mino ne pouvant encore avoir de débogueur utilisateur attaché.
Le scénario `process-debug-port` vérifie le contrat mémoire, les handles, les droits
et CheckRemoteDebuggerPresent sur AMD et Intel ; retirer le handler le fait échouer.

Mesure sur le banc après le correctif (AMD) :

- AbiWord s'installe (code 0), démarre, puis finit encore sur 0xC0000005. Le journal
  donne maintenant le diagnostic de la faute : lecture de `0x3c`, EIP `0x102b119f`
  (`libAbiWord.dll+0x2b119f`), avec EAX et ESI nuls. Les cadres suivants sont dans
  `libAbiWord.dll` (`+0x2b5d3a`, `+0x2b522d`, …). **La correction du contrat n'a
  donc pas débloqué l'éditeur** : l'attribution précédente du plantage au seul
  ProcessDebugPort était insuffisante. Suite : retrouver l'objet nul et l'API qui
  devait le produire, à partir de cette instruction et de ses appelants.
- SumatraPDF : l'installeur rend toujours 1 ; `userenv/profile.c:1841` signale
  Error 2. Suite : tester sous une vraie session avec un profil utilisateur, au
  lieu du jeton System du banc. ProcessDebugPort n'est plus un service manquant.
- Les deux scénarios passent leurs planchers actuels et fsck.vfat déclare leurs
  volumes propres. Cela ne valide ni l'utilisation ni la fermeture des applications.

Corriger les blocages dans cet ordre, chacun avec un test, et remonter le plancher du scénario de chaque
application débloquée. Une fois une application installée : les DLL qu'elle importe (`userland::import_closure`), et
son parcours (`docs/compat/applications.md`, colonne « Parcours »), sur AMD et Intel.

## Bloc-notes

`tests/boot/notepad-save` lance `NOTEPAD2.EXE`, une sonde qui démarre le vrai
Bloc-notes. QEMU tape `Hello, Mino!`, une nouvelle ligne, puis `Line 2`, Ctrl+S
et le chemin `C:\MINO-NOTE.TXT`. Seul le Bloc-notes écrit le fichier ; la sonde
vérifie ses 20 octets, attend sa fermeture normale, lance un nouveau processus
sur ce fichier et les vérifications d'écran contrôlent le texte relu.

La sonde vérifie aussi le remplacement/restauration d'une procédure de fenêtre
Unicode (GWLP_WNDPROC), nécessaire aux fenêtres ATL utilisées par le shell.
Elle ne remplace ni `comdlg32`, ni `shell32`, et ne désactive pas l'autocomplétion.

Reproduction avant la PR #127 (main `3942dd5`) : fenêtre Save As visible, puis assertion
`atlwin.h:1118`, `::IsWindow(m_hWnd)`. Le fichier n'est pas créé et le nouveau
scénario échoue sur `[apps] FAIL: saved file contents`. L'ancien scénario
`notepad` valide uniquement la saisie et Ctrl+G, pas l'enregistrement.

Correctifs : GWLP_WNDPROC remplace/restaure une procédure cliente dans le
processus propriétaire, publie le nouveau pointeur dans WND et rend l'ancien.
Les conversions ANSI/Unicode et les procédures serveur nécessitent encore
des thunks ; ces cas rendent explicitement ERROR_CALL_NOT_IMPLEMENTED.
Alt+F4 poste SC_CLOSE à la fenêtre de premier niveau (sauf CS_NOCLOSE), puis
laisse l'application traiter normalement WM_CLOSE. Aucun processus n'est tué.

Validation : `notepad-save` passe sur AMD (`int 2Eh`) et Intel (`SYSENTER`),
y compris CS_NOCLOSE et le refus du subclassing interprocessus. Le fichier est sur le volume de démarrage
en RAM de ce scénario : ce test ne prouve pas la persistance après reboot.
Reprise : `cargo xtask test --boot --scenario notepad-save`.

## Calculatrice

`CALC1.EXE` lance `calc.exe` ; les touches viennent de QEMU. Le contrôle
statique de sortie doit contenir exactement `42.` après chaque calcul. La
capture vérifie les glyphes `42.` du second processus. Le premier processus
doit avoir quitté normalement, code 0, avant la relance.

Cause de l'échec initial (affichage bloqué à `0.`) : `post_key_press` appelle
GetClassName avant de transmettre un clic au bouton ; le service absent
renvoyait 0. NtUserGetClassName lit maintenant le nom non versionné de la
classe dans la table des atomes, respecte la capacité en UTF-16, termine par
NUL et rend le nombre d'unités copiées. Les accès passent par les helpers de
mémoire utilisateur. La sonde couvre GetClassNameW/A, troncature sans écrire
au-delà, capacité d'un seul NUL, pointeur et HWND invalides. La résolution des
superclasses de RealGetWindowClass reste à faire.

MapVirtualKeyEx reste absent ; ce n'est pas le blocage observé ici : ToAsciiEx
peut encore traduire ces touches par la disposition chargée. Pas de
validation des fonctions scientifiques, de l'aide HTML ou du presse-papiers.

La sonde attend l'existence de l'afficheur **et** sa valeur, puis une réponse
à WM_NULL avec délai maximal. L'existence du titre seul ne garantit pas que
les contrôles du dialogue sont créés : une course à la relance, détectée lors
du passage sur le nouveau main, faisait échouer la première version de la sonde.

## Démineur

`MINE1.EXE` lance `winmine.exe` (titre WineMine). La sonde lit les 256 pixels
de la première case, sans écrire dans le jeu. Un clic droit PS/2 doit faire
apparaître le rouge du drapeau et changer la case. F2 doit restituer les
256 pixels de la case couverte. Alt+F4 doit terminer le processus normalement ;
la relance doit afficher une case identique. La capture contrôle le relief
de la case et le visage. La souris est déplacée hors de la case après le
clic. Une partie gagnée/perdue et le son ne sont pas validés.

## Portée

Ces parcours portent sur les binaires x86 épinglés, pas sur toute application
XP. Les images de test incluent désormais `calc.exe`, `winmine.exe` et leurs
imports. La CI exécute les trois nouveaux scénarios et `desktop-launch` sur
les deux chemins d'appels système, ainsi que le lancement du Bloc-notes et
les clics du menu du bureau. `desktop-click` sélectionne désormais Settings :
depuis la PR #129, Text Editor lance réellement une application et ferme le
menu, contrairement à l'hypothèse de l'ancien test. Commande de la campagne :

```sh
cargo xtask test --boot --scenario notepad-save --scenario calculator --scenario minesweeper --scenario desktop-launch --scenario desktop-notepad --scenario desktop-click
```

Bilan sur la base `abfe106` : 1 098 tests hôte réussis, `cargo xtask lint`
propre ; 59 scénarios QEMU AMD distincts validés après reprises ciblées.
Les deux scénarios `rostests` et `rostests-kernel32` sont sautés, sans leur
arbre ReactOS de tests. Les six scénarios applications/bureau passent aussi en local sur Intel :
12 parcours AMD/Intel au total. La campagne applications est également verte en CI.

Le passage général a détecté les deux anciens défauts de sondes décrits
ci-dessus. `installed-boot` a été repris avec OVMF CODE/VARS en pflash :
le firmware combiné ajoutait `NVVARS` dans l'ESP. Les contrôles GPT, FAT et
des fichiers copiés n'ont pas été assouplis. Les derniers scénarios, interrompus
par un disque de travail plein, ont été repris après libération des images
temporaires ; l'union des passages réussis couvre les 59 scénarios.
Pas de validation VirtualBox dans cette campagne.

Captures QEMU réelles : [Bloc-notes rouvert](../images/notepad-save.png),
[Calculatrice après relance](../images/calculator.png),
[Démineur après relance](../images/minesweeper.png).

Pour un essai manuel dans une image reconstruite avec cette branche : ouvrir
le bureau live puis Terminal et lancer `C:\WINDOWS\SYSTEM32\CALC.EXE` ou
`C:\WINDOWS\SYSTEM32\WINMINE.EXE`. Le menu Text Editor lance déjà le Bloc-notes
depuis la PR #129. Ces commandes manuelles ne constituent pas une validation
supplémentaire VirtualBox.
