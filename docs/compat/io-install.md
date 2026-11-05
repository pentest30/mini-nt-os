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
