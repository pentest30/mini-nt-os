# Le chantier « installation et formatage » : journal des étapes

Comment chaque étape s'est faite, ce que les binaires réels de ReactOS ont
révélé, et ce qui manque. La méthode est celle du M4 : lancer le binaire
vrai, lire ce qu'il demande, l'implémenter, le tester par un scénario boot
et par mutation. À mettre à jour à chaque étape.

Le plan (F1 à F7) et les décisions structurantes sont dans l'ADR-22 ; la
passation dit où en est le travail.

## F1 : `NtQueryDirectoryFile`, l'énumération des répertoires

`DIR1.EXE` (`tests/native/dir1.c`, MinGW, lié aux `kernel32` et `user32`
de ReactOS) prend la place de `winlogon.exe`, comme `GUI1.EXE`, puis
énumère par le `FindFirstFileW`/`FindNextFileW` de kernel32 : le scénario
`dir` (`tests/boot/dir/scenario.txt`) l'attend.

Fait :

- `abi::file` : `FILE_BOTH_DIR_INFORMATION` (le layout d'XP x86, asserté :
  `short_name` à 0x46, `file_name` à 0x5E, 0x60 octets — un `WCHAR[1]`
  s'aligne sur 2, pas sur 4) ; `STATUS_NO_SUCH_FILE` et
  `STATUS_NO_MORE_FILES` dans `ntstatus`.
- `io::name` : le filtre d'une énumération (`?`, `*`, sans casse, et les
  deux cas de DOS : `*.*` nomme tout, `*.` nomme les sans-extension).
- `io::fat` : `DirEntryInfo` tient l'entrée complète — son nom, son nom
  8.3, **où elle est** (son offset dans le flux du répertoire : l'index
  où une énumération reprend), ses dates — et le label de volume ne sort
  plus d'un répertoire.
- `io::volume` : `Volume::enumerate`, la première entrée à partir d'un
  index que le motif (`None` : tout) garde ; `.` et `..` ne viennent
  jamais, comme XP ; chaque appel relit le répertoire depuis le début (un
  scan qui sert plusieurs entrées d'une lecture viendra).
- `io::file` : le file object garde où son énumération reprend (un de plus
  que l'index de la dernière entrée rendue : les entrées sont sur des
  offsets de 32 octets) et **le motif qu'on lui a donné** — le
  `FindNextFileW` de kernel32 n'en renvoie pas.
- `sys::file` : `NtQueryDirectoryFile`, `FileBothDirectoryInformation`
  seul (les autres classes, journalisées une fois, rendent
  `STATUS_INVALID_INFO_CLASS`).

Ce que les binaires réels ont révélé :

- **L'ordre des arguments** du `NtQueryDirectoryFile` de ReactOS n'est pas
  celui d'XP : `ReturnSingleEntry` vient **avant** le motif, et
  `RestartScan` est le dernier (`…, Length, FileInformationClass,
  ReturnSingleEntry, FileName, RestartScan`). La table générée suit
  ReactOS (ADR-002) : le déstructurage aussi, désormais.
- **Les méta-caractères de DOS** : le `FindFirstFile` de kernel32 réécrit
  l'étoile d'un motif avant l'extension en `<` (`C:\*.EXE` arrive comme
  `<.EXE`). `io::name` les connaît : `<` nomme n'importe quoi jusqu'au
  dernier point (exclu), `>` un caractère, rien au dernier point.
- **`ShortNameLength` en octets** : le kernel32 épinglé copie ce compte
  d'octets en caractères larges (`NTDL` pour `NTDLL.DLL` quand il compte
  des caractères) — le noyau écrit donc des octets, comme ce kernel32 le
  lit.
- **Une première requête sans correspondance rend `STATUS_NO_SUCH_FILE`**
  (le `ERROR_FILE_NOT_FOUND` de `FindFirstFile`), et non
  `STATUS_NO_MORE_FILES`, qui finit un scan qui a rendu des entrées.
- Le premier appel de `FindFirstFile` vient avec `ReturnSingleEntry` et
  `RestartScan` à vrai ; `FindNextFile` sans motif (le file object le
  garde) ni redémarrage.

Pas encore :

- Une seule classe d'information (`FileDirectoryInformation`,
  `FileIdBothDirectoryInformation`… rendues par `STATUS_INVALID_INFO_CLASS`
  journalisé) ; `NtNotifyChangeDirectoryFile`, que l'explorateur demandera.
- Un scan qui sert plusieurs entrées d'une seule lecture du répertoire
  (chaque entrée relit) ; les dates d'accès en écriture (elles restent à
  zéro) ; `FileIndex` au-delà de 4 Gio de répertoire.
- Le test de l'énumération d'un fichier ouvert (rend
  `STATUS_NOT_A_DIRECTORY`) : `user32` n'en demande pas.


## F3 : formatage FAT32 incrémental

`fatfs::format::format` formate un volume vide par le trait `WriteSectors`
(écriture d'un secteur de 512 octets et `flush`, erreurs du périphérique
conservées). Les LBA sont relatifs au volume : l'appelant devra fournir une
vue bornée de la partition, démontée et exclusivement tenue.

- `Geometry::for_sectors` calcule les deux FAT et les clusters avant toute
  écriture, sans débordement même pour `u32::MAX`. Les volumes trop petits
  pour FAT32 ou dont les numéros de clusters atteindraient les valeurs
  réservées sont refusés. Un cluster fait un secteur, comme dans `image`.
- Les secteurs réservés, les deux FAT et le répertoire racine sont remis à
  zéro ; les entrées réservées de la FAT et le cluster racine sont alloués.
  Les en-têtes de démarrage et FSInfo, avec leurs copies, viennent des mêmes
  fonctions que `image::build`. Les compteurs FSInfo restent « inconnus ».
- C'est un **formatage rapide**, avec une mémoire de travail constante : les
  clusters libres ne sont ni lus ni effacés. Ce n'est pas un effacement des
  anciennes données. Une erreur d'écriture ou de vidage échoue l'opération ;
  le volume peut alors être partiellement formaté.
- Tests : égalité octet par octet avec l'image vide de `image::build`, ancien
  contenu des métadonnées effacé et données libres conservées, deux FAT et
  copies des en-têtes identiques, montage par `io-manager`, `fsck.vfat`,
  limites de géométrie et erreurs d'écriture/vidage. Quatre mutations
  (racine non allouée, seconde FAT omise, erreur de vidage ignorée, validation
  de taille retirée) sont détectées par les tests.

Pas encore : raccordement à un périphérique du noyau, démontage/exclusion,
IOCTL de formatage (la partie noyau de l'ADR-022 reste proposée), tailles de
clusters supérieures à 512 octets, label et identifiant de volume configurables,
partitionnement GPT (F4).


## F4 : GPT, MBR protecteur et volumes bornés

`libs/gpt` est une crate `no_std` avec `alloc`, sans dépendance externe ni
`unsafe`. Elle encode les champs explicitement (pas de structure Rust
projetée sur le disque), suivant le format GPT 1.0 de la spécification UEFI,
chapitre 5. Les GUID sont des octets dans l'ordre EFI ; les noms sont les
36 unités UTF-16 du disque.

- `Layout::new` valide le GUID du disque, les identifiants et indices des
  partitions, leurs limites et leurs chevauchements avant toute écriture.
  La géométrie canonique réserve 128 entrées de 128 octets, un en-tête et
  un tableau à chaque bout du disque. Le lecteur accepte 128 à 4096 entrées
  de 128 octets ; une autre taille d'entrée est refusée explicitement.
- `gpt::write`, derrière `ReadSectors`/`WriteSectors`, écrit le tableau et
  l'en-tête de secours, vide le périphérique, puis la copie principale,
  puis le MBR protecteur et un dernier vidage. Chaque en-tête et chaque
  tableau portent leur CRC-32 IEEE. Le MBR porte une unique partition 0xEE
  couvrant le disque, avec saturation à `u32::MAX` pour les grands disques.
  Le contenu des partitions et l'espace libre ne sont pas touchés.
- `gpt::read` vérifie le MBR protecteur, signatures, révision, taille,
  champs réservés, adresses des deux en-têtes, limites des tableaux, CRC et
  entrées. Une copie valide permet de lire malgré la corruption ou l'erreur
  de lecture de l'autre ; `Source` indique laquelle. Deux copies valides
  mais différentes sont refusées. Aucune réparation automatique n'écrit sur
  le disque. Les MBR hybrides sont refusés.
- `io::partition::PartitionDevice` translate les LBA d'un volume et refuse
  lectures et écritures hors de sa plage, ainsi que les tampons de mauvaise
  taille. Les erreurs de vidage atteignent le périphérique sous-jacent.
  Au démarrage, la première partition **Basic Data** d'un disque GPT devient
  `\Device\HarddiskVolume1` et `C:` si elle porte du FAT32 ; les partitions
  EFI sont ignorées. Un GPT reconnu mais invalide ne retombe jamais sur le
  lecteur FAT brut. Les disques FAT32 sans table restent pris en charge.
- `disk = system-gpt` dans un scénario fait placer le FAT de démarrage dans
  une partition à LBA 2048 (alignement de début à 1 Mio). Les GUID fixes de
  ces images sont réservés aux tests : un installateur doit en générer de
  nouveaux. Après les démarrages, `xtask` valide **les deux** copies GPT et
  extrait la partition pour `fsck.vfat`, sans modifier l'image testée.
  `gpt-persistence` écrit puis relit `C:\PERSIST\DATA.TXT` après un
  redémarrage, sur AMD (`int 2Eh`) et Intel (`SYSENTER`). L'ESP de QEMU reste
  distincte : ce scénario ne prétend pas tester un disque d'installation
  unique avec ESP et volume système.

Validation : tests unitaires des CRC (dont le vecteur indépendant
`123456789`), récupération de chaque copie, conflits, tailles et offsets
malveillants, erreurs d'E/S, entrées invalides malgré des CRC recalculés,
chevauchements et slots libres ; tests croisés GPT/FAT/Io (EFI ignorée,
FAT relue, reformatage d'une partition sans toucher GPT ni sa voisine,
corruption sans repli brut). Cinq mutations sont détectées : CRC d'en-tête
ignoré, CRC de tableau ignoré, copie de secours omise, contrôle de
chevauchement retiré et limite de partition retirée. `sgdisk -v` valide
également les images de persistance GPT avec « No problems found ».

Limites : secteurs logiques de 512 octets ; une seule partition système
montée, pas encore de noms de périphériques pour toutes les partitions,
ni IOCTL de création/modification de table, ni politique de montage fondée
sur les attributs GPT, ni notification de changement
ou verrouillage/démontage des volumes. Une réécriture GPT n'est pas atomique
et demande un disque démonté et exclusivement tenu. Le MBR traditionnel,
les tables hybrides et les secteurs de 4 Kio restent hors de cette étape.
La création de l'image d'installation complète (ESP et système) et le
raccordement des opérations de disque aux interfaces NT viennent ensuite.


## Image de développement unique (ESP + système)

`cargo xtask image [--output FILE] [--features F]` construit une image GPT
avec deux volumes FAT32 : une ESP et le système. Les deux débuts de partition
sont alignés à 1 Mio. `xtask::install::Plan` calcule et vérifie les tailles
avant de créer le fichier de destination ; la disposition est affichée et
peut servir à une future page de revue. Cette fonction pure n'exécute aucune
E/S. Le fichier doit être neuf ; un échec d'écriture tente de supprimer uniquement le
fichier qui vient d'être créé par cette opération.

L'ESP contient `EFI/BOOT/BOOTX64.EFI`, `kernel.elf` et `fat.img` (le disque
RAM initial dont le chargeur existant a besoin). Le second volume contient
les fichiers du système. Les GPT sont relues après écriture et comparées au
plan. Les GUID sont fixes pour ces images de développement : un installateur
réel devra en générer de nouveaux. Les clones ne sont pas des installations
indépendantes identifiées de façon unique.

La commande exige l'espace utilisateur ReactOS épinglé et utilise
`test-smss` par défaut pour atteindre la sonde de démarrage actuelle ; cela
ne promet pas encore un bureau complet. Exemple :

```bash
cargo xtask fetch-userland
cargo xtask image --output target/mino.img
cargo xtask run --image target/mino.img
```

`run --image` utilise cette image telle quelle, sans construire le noyau ou
recréer ses volumes ; `--features`, `--add` et `--data-dir` ne se combinent
pas avec ce mode. L'OVMF et le processeur se choisissent comme auparavant.

Au démarrage, le noyau préfère toujours le disque système secondaire quand
il est présent (anciens scénarios) ; sinon il cherche un GPT sur le disque
primaire. Un disque primaire FAT brut, comme l'ESP virtuelle des anciens
tests, n'est pas pris pour le volume système. Les journaux indiquent le
canal réellement choisi.

`installed-persistence` utilise `disk = installed` : le disque GPT remplace
la FAT virtuelle de QEMU ; aucun second disque ne porte `C:`. OVMF démarre
notre chargeur depuis sa vraie ESP, et le noyau monte la partition Basic
Data sur le même disque. Deux démarrages vérifient la persistance d'un
fichier, les deux GPT et le volume système avec `fsck.vfat`, sur AMD et Intel.

Il s'agit d'un constructeur d'image côté hôte. Le premier contrat noyau de
l'installateur en mode utilisateur existe maintenant :
`IOCTL_MINO_SETUP_QUERY` rend en lecture seule un disque ATA secondaire sûr,
sa capacité et un plan GPT/FAT immuable. Le média primaire et le disque qui
porte le système courant sont exclus ; la géométrie de chaque volume est
validée par `fatfs::format`. Aucune commande d'écriture, de verrouillage ou
de démontage n'est encore exposée. La copie avec progression et reprise reste
à faire. L'interface native est décrite dans
[`install-ui.md`](install-ui.md) et le brief visuel réutilisable dans
[`design/installer-ui-prompt.md`](../design/installer-ui-prompt.md).


Validation de cette étape : `cargo xtask lint` propre, 740 tests hôte et
32 scénarios QEMU réussis (les scénarios restants ont été repris après
nettoyage d'un espace temporaire saturé). Les deux commandes publiques
`image` et `run --image` ont été exercées, cette dernière jusqu'au retour de
la sonde SMSS sur un GPT primaire réel. Une destination déjà existante est
refusée et ses octets restent intacts. `sgdisk` vérifie les GPT ;
`fsck.vfat` vérifie l'ESP et le volume système des images de persistance.

## Lot 2 : `IOCTL_MINO_SETUP_PREPARE`, la préparation du disque cible

La seconde commande du contrat privilégié (`abi::setup`) écrit, une fois
revérifiée, les tables GPT du plan sur le disque cible — et rien d'autre :
elle ne formate pas et ne copie rien.

- `abi::setup` : `IOCTL_MINO_SETUP_PREPARE`
  (CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS),
  `0x8000A004`), la demande `SetupPrepare` de 16 octets encodés (version,
  numéro de disque, jeton), refusée pour une autre version du contrat.
- `io_manager::install::prepare` : le média de démarrage (maître primaire)
  et le disque qui porte le système courant sont refusés avant toute
  écriture ; le maître secondaire est reprové, le plan recalculé par le
  même `Plan::guided` que l'aperçu, et le jeton reverifié — la capacité
  entre dans son empreinte, un disque qui a changé rend le jeton faux.
  Un disque qui porte déjà des tables (MBR protecteur) est refusé sans
  être touché : la revue de l'interface reste la dernière étape
  réversible. Puis `libs/gpt::write` écrit la copie de secours d'abord,
  les deux en-têtes GPT et le MBR protecteur, avec un flush entre les
  copies ; la relecture par `libs/gpt::read` exige les deux copies valides
  (`Source::Both`) et les plages du plan.
- Les GUID du disque et des partitions sont **déterministes**, tirés du
  jeton (FNV-1a, rôles distincts, version 4, variante RFC 4122) : la même
  demande écrit les mêmes octets, et une comparaison d'images s'y
  retrouve. L'ESP porte le type EFI System (emplacement 1, « ESP »), le
  volume système Basic Data (emplacement 2, « MINO »).
- `sys::file` : la préparation rend `STATUS_ACCESS_DENIED` (disque
  protégé), `STATUS_NO_SUCH_DEVICE`, `STATUS_REVISION_MISMATCH` (jeton),
  `STATUS_OBJECT_NAME_COLLISION` (déjà des tables),
  `STATUS_INVALID_PARAMETER` (capacité) ou `STATUS_IO_DEVICE_ERROR`,
  chacune journalisée. Le handle d'ancrage reste `FILE_READ_ATTRIBUTES` ;
  l'autorité d'écrire vient du jeton.

Le self-test noyau `install_prepare_self_test` (phase 1) l'exerce sur
chaque démarrage : refus du disque protégé (les scénarios à disque
système, où le secondaire porte `C:`), constat sans cible, puis, sur le
disque cible de 96 Mio (`disk = target`), jeton faux refusé sans un octet
écrit, préparation réussie et relue (ESP 2048..83967, système
83968..196574), seconde passe refusée (`NotBlank`). Le scénario
`installer-prepare` attend ces marqueurs sur AMD et Intel. Tests hôte :
cinq tests de `prepare_disk` (écriture et relecture, jeton faux sans un
octet écrit, disque occupé intact, drapeaux protégés et capacité réduite,
GUID déterministes).

Restent : le formatage des deux vues bornées (F3, `fatfs::format` est
prêt), la copie des fichiers, les événements de progression vers l'UI, le
verrou exclusif et le démontage de la cible pendant l'écriture, puis la
souris.
