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
