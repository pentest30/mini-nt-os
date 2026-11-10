# M9 — NTFS en lecture seule

`libs/ntfs` prépare un sous-lot de M9 en parallèle de M6. La bibliothèque
Rust `no_std` + `alloc` n'a aucune dépendance externe et interdit `unsafe`.
Elle lit des fichiers **par numéro MFT ou chemin** sur une interface de lecture
fournie par l'appelant. `kernel/io` l'adapte maintenant aux partitions et aux
objets Volume/File du noyau. `win32k` n'est pas modifié. Les critères de sortie
de M9 restent inchangés : ce lot est un montage de données en lecture seule.

## Montage dans Mino

`Volume::mount_partition` reconnaît NTFS par sa signature, sur une partition
dont la capacité est connue. Un NTFS corrompu ne retombe pas sur FAT32.
La détection existante choisit la première partition GPT Basic Data du disque
ATA attaché, ou le volume brut sans GPT. Elle ne parcourt pas toutes les
partitions. Les secteurs physiques de 512 octets sont requis.

Un volume NTFS devient `\Device\HarddiskVolume1`, accessible par `D:`.
Il ne remplace pas le volume FAT de `C:` ou de `SystemRoot`. Le démarrage et
l'installation de Mino sur NTFS ne font pas partie de ce lot.

L'adaptateur traduit les lectures en octets en lectures de secteurs, y compris
les lectures non alignées, après vérification de la plage entière. Chaque
opération crée son lecteur indépendant : aucune allocation ou lecture NTFS
n'est faite sous un spinlock de volume. Les appels se font à PASSIVE_LEVEL.
Ce choix relit la MFT et `$UpCase` plutôt que de maintenir un cache partagé ;
le média doit rester stable pendant le montage (pas de retrait ni d'écriture
externe). Un cache et le démontage sont des travaux ultérieurs.

Les appels de fichiers permettent ouverture relative ou absolue, lecture,
énumération, tailles 64 bits, dates de STANDARD_INFORMATION, label, espace
libre via `$Bitmap` et identification du système de fichiers. Les records
internes réservés 0 à 15 ne sont pas énumérés comme fichiers utilisateur ; les
alias DOS sont rattachés aux entrées Win32. L’énumération NtQueryDirectoryFile conserve les unités UTF-16 brutes,
y compris les surrogates isolés, dans les noms longs et les alias DOS.
La capture des chemins par le gestionnaire d’objets et le helper `list()`
restent limités aux noms représentables en UTF-8 ; l’ouverture d’un nom
contenant un surrogate isolé reste à implémenter.
Les motifs d'énumération utilisent le moteur existant d'Io ; la résolution des
composants utilise bien `$UpCase` du volume.

Toutes les mutations, même sur un disque physiquement inscriptible, échouent
avec `STATUS_MEDIA_WRITE_PROTECTED` : ouverture demandant des droits de
modification, création, écrasement, écriture, taille et attributs/dates.
`GENERIC_READ` et `MAXIMUM_ALLOWED` permettent la lecture : les droits
de mutation sont retirés du maximum avant insertion dans la table des handles.
Une demande explicite de ces droits reste refusée, même avec MAXIMUM_ALLOWED.
NtWriteFile sur un handle ainsi réduit échoue avec `STATUS_ACCESS_DENIED`.
Un flush NTFS est sans effet et ne sollicite pas le périphérique.
FileFsAttributeInformation annonce `NTFS` et `FILE_READ_ONLY_VOLUME`.
Les ACL NTFS ne sont pas interprétées. Les informations communes à FAT/NTFS
restent un sous-ensemble : allocation arrondie au cluster, un lien déclaré et
date de changement représentée par la dernière écriture.

## Contrat et périmètre

- `ReadAt` expose seulement la taille d'une partition et une lecture exacte
  à un offset en octets, relatif à cette partition. L'adaptateur doit borner ses
  accès et maintenir une vue stable du volume pendant sa lecture.
- `Geometry::read` valide le boot NTFS, les secteurs de 512 octets, les clusters
  de 512 octets à 64 Kio, la taille signée des enregistrements FILE (512 octets
  à 64 Kio) et les positions de la MFT et de son miroir.
- `Volume::open` lit le premier FILE à l'emplacement annoncé, vérifie les
  fixups USA de chaque secteur, reconstitue le flux DATA de `$MFT`, puis vérifie
  que son mapping ramène bien au même premier enregistrement.
- `Volume::record`, `file_size` et `read_file` permettent de lire les records
  alloués et les flux DATA sans nom. La MFT et les fichiers peuvent être
  fragmentés ; les déplacements LCN négatifs sont acceptés et bornés.
- Les fichiers résidents et non résidents sont lus sans charger tout leur
  contenu en mémoire. Une lecture retourne le nombre d'octets effectivement
  copiés ; à EOF elle retourne zéro. Le reste du tampon est inchangé.
- La partie située après la taille initialisée est rendue comme des zéros,
  sans exposer les octets résiduels du disque. Une erreur d'E/S peut laisser
  un tampon partiel, que l'appelant doit abandonner.

Les signatures, longueurs d'attributs, arithmétiques, limites du volume et
couverture des mapping pairs sont vérifiées. Les boucles avancent dans un
record borné ; au plus 4096 runs sont acceptés par flux. Ces validations ne
constituent pas un fsck ni une vérification des droits d'accès NT.

## Répertoires et chemins

`read_directory(record)` énumère les noms de l'index `$I30`, avec les alias DOS
comme entrées séparées ; l'ordre retourné n'est pas contractuel. Le lecteur
accepte INDEX_ROOT résident et les blocs INDX de INDEX_ALLOCATION. Il vérifie
les fixups, les VCN, les limites des entrées, les références du répertoire
parent et les bits d'allocation du BITMAP. Les cycles ou enfants partagés sont
refusés. Les VCN sont exprimés en secteurs quand un bloc d'index est plus petit
qu'un cluster. Le parcours accepte au plus 4096 blocs et 65536 noms.

`lookup_path(path)` retourne une `FileReference` (numéro MFT + séquence).
`read_path(path, offset, buffer)` lit directement le fichier. Chaque référence
traversée est vérifiée : un record libéré ou dont la séquence a changé n'est
pas utilisé. `referenced_record(reference)` expose aussi ce contrôle. Une simple
énumération retourne les références indexées sans ouvrir tous leurs records.

Les chemins sont relatifs à la racine du volume, avec ou sans séparateur initial.
`/` et `\` séparent les composants ; `.` et `..` sont acceptés, sans sortir de
la racine. Un séparateur final exige un répertoire. Les lettres de lecteur,
le NUL et la syntaxe ADS avec `:` sont refusés. Limites : 4096 unités UTF-16,
64 composants non vides et 255 unités UTF-16 par nom.

La comparaison sans casse utilise les 65536 entrées de `$UpCase` (record 10),
chargées à la première recherche et gardées pour la vie du volume. Sa taille,
son initialisation et son idempotence sont vérifiées. Aucune substitution par
la casse de l'hôte n'est faite. Des noms équivalents selon `$UpCase` qui pointent
vers des fichiers distincts donnent une erreur explicite d'ambiguïté ; le mode
POSIX sensible à la casse n'est pas proposé. L'énumération conserve les noms
UTF-16 bruts, y compris les unités qui n'ont pas de représentation UTF-8 valide.

Le parcours visite l'ensemble de l'index du répertoire, pas seulement une
branche de recherche. Ce choix simplifie la validation ; son coût est linéaire
et il ne vérifie pas l'ordre de tri de l'arbre comme le ferait un fsck.

## Limites explicites

Les `ATTRIBUTE_LIST` résidentes ou non résidentes sont prises en charge quand
leur mapping complet figure dans le record de base. Le lecteur assemble les
extents DATA, INDEX_ROOT, INDEX_ALLOCATION et BITMAP référencés dans d'autres
records FILE. Il vérifie les séquences, le lien de chaque extension à son
fichier de base, l'identifiant, le type et le nom de l'attribut ainsi que la
continuité des VCN. Les tailles du premier extent font foi ; le delta LCN
repart de zéro dans chaque extent. Les trous et recouvrements sont refusés.

La liste est limitée à 1 Mio et 4096 entrées ; chaque résolution accepte
au plus 64 records FILE, base comprise, et 4096 runs au total. Seules les
références du flux demandé sont ouvertes, après validation structurelle de
toute la liste. Les listes imbriquées dans une extension sont refusées.
`record()` expose uniquement les records de base ; les extensions sont
résolues en interne pour lire le fichier ou son index.

Refus des secteurs autres que 512 octets, attributs compressés, sparse ou
chiffrés et reparse points. Une liste dont le mapping est lui-même réparti
sur plusieurs records reste hors périmètre.
Le flux `$MFT` doit être intégralement initialisé, avec son premier extent DATA
dans le record de base. Son ATTRIBUTE_LIST peut référencer des extensions :
le bootstrap ouvre un record seulement quand tous ses octets sont couverts par
les mappings déjà validés, puis ajoute ses extents connus. Les dépendances
peuvent se résoudre hors ordre des VCN. Chaque itération charge un record
distinct, avec la même limite de 64 records (base comprise). Une dépendance
inaccessible donne `Unsupported("unreachable MFT extension")` ; aucune adresse
physique n'est devinée et aucun scan du disque n'est tenté. La couverture complète
et contiguë est exigée avant de publier le volume. Le miroir est localisé mais
ne sert pas à récupérer une MFT corrompue.

Pas encore de flux nommés, de journal, de récupération ou d'écriture.
Un volume valide qui sort de ce périmètre peut être refusé.
Aucune promesse de montage général de volumes NTFS existants à ce stade.

## Validation reproductible

```sh
cargo test -p ntfs
cargo clippy -p ntfs --all-targets -- -D warnings
# Outils ntfs-3g sur PATH : mkntfs, ntfscp, ntfsls, ntfscat et ntfsinfo.
cargo test -p ntfs --test mkntfs -- --ignored
cargo test -p io-manager --test ntfs -- --ignored
# Avec QEMU, OVMF, MinGW/LLVM et le userland ReactOS épinglé :
cargo xtask test --boot --scenario ntfs-readonly
```

Les tests synthétiques couvrent la MFT fragmentée, les runs vers l'arrière,
les fixups au milieu des données résidentes, les trous d'initialisation, EOF,
les erreurs d'E/S, les métadonnées tronquées ou incohérentes, les dépassements
et les fonctionnalités refusées. Un balayage de mutations d'octets exerce
les bornes du lecteur sur les métadonnées du boot et de plusieurs records.

Le bootstrap MFT dispose d'images synthétiques à trois extents, avec listes
résidentes/non résidentes et dépendances successives ou hors ordre VCN. Les
tests effacent l'ancienne disposition contiguë et lisent ensuite des chemins
à travers la MFT reconstituée. Ils couvrent les records chevauchant des runs,
les erreurs d'E/S, les références étrangères/périmées, les fixups corrompus,
la couverture incomplète, la limite de 64 records et les mutations d'octets.
Un lecteur instrumenté interdit toute E/S vers un record partiellement mappé
ou une dépendance circulaire. Les images ntfs-3g ci-dessous vérifient les
régressions sur volumes réels ; elles ne constituent pas une validation
indépendante d'une MFT dont DATA est réparti entre plusieurs records.

Le test `mkntfs` est ignoré par défaut pour ne pas imposer les outils ntfs-3g
à chaque build. Le workflow séparé `.github/workflows/ntfs-readonly.yml`
lance explicitement ce test en CI quand ce composant change. Il crée trois images
temporaires de 32 Mio, avec des clusters de 512, 4096 puis 8192 octets. Chaque
image reçoit un petit fichier résident, un fichier non résident de 131195 octets
et 160 fichiers supplémentaires pour exercer un index à plusieurs blocs.
L'ajout de 40 flux nommés au petit fichier force une ATTRIBUTE_LIST, dont
`ntfsinfo` confirme la présence ; le lecteur relit toujours son flux sans nom.
Ce cas ne prouve pas à lui seul la lecture de DATA réparties entre records :
les tests synthétiques couvrent ces extents, les listes résidentes/non résidentes,
les index déplacés en extension, les références étrangères ou périmées, les
trous/recouvrements et les limites de taille et de nombre d'entrées. Le test réel
compare les numéros avec `ntfsls`, les recherches par chemin en majuscules et
les contenus avec les originaux et `ntfscat`, puis supprime les images.
Les chemins imbriqués, noms accentués, références périmées, cycles, BITMAP,
blocs tronqués et erreurs de `$UpCase` sont couverts par les tests synthétiques.
Il ne monte aucun système de fichiers et ne requiert pas root.
Validé avec ntfs-3g 2022.10.3 (paquet Debian 1:2022.10.3-5+deb13u3).

Le test d'adaptateur monte une vraie image mkntfs à un offset non nul, ouvre et
lit via `File`, vérifie Unicode/EOF/métadonnées/énumération et refuse toutes les
mutations. Le périphérique instrumenté compte zéro écriture et zéro flush,
y compris à la destruction du volume. Le scénario `ntfs-readonly` crée une
partition GPT/NTFS et fait appeler les vrais services NT par `NTFS1.EXE`, lié
à ntdll. Il vérifie aussi que C: reste sur le ramdisk FAT et que le SHA-256 de
tout le disque attaché reste inchangé après chaque boot (AMD et Intel).
Les deux tests incluent un nom contenant le surrogate isolé 0xD800 dans
FILE_NAME et $I30 : l’énumération restitue exactement ses unités UTF-16.
Ils vérifient aussi les ouvertures GENERIC_READ/MAXIMUM_ALLOWED, la lecture
et le refus d’écriture par les droits du handle (STATUS_ACCESS_DENIED).

## Suite, en PR distinctes

1. Cache partagé à verrou bloquant, démontage et choix de plusieurs partitions ;
   étendre les informations et la sémantique des noms exposées par Io.
2. Étendre les fonctionnalités restantes selon les volumes de référence,
   notamment les listes dont le mapping lui-même est réparti entre records.

L'intégration partage les objets de fichiers d'Io, les informations de volume
des services NT et le harness QEMU. Aucun code USER, GDI ou pilote d'entrée
M6 n'est modifié. Le code est original ; les structures disque sont décodées
par offsets, sans portage de code Microsoft ou de ntfs-3g.
