# M9 préparatoire — NTFS en lecture seule

`libs/ntfs` prépare un sous-lot de M9 en parallèle de M6. La bibliothèque
Rust `no_std` + `alloc` n'a aucune dépendance externe et interdit `unsafe`.
Elle ne monte aucun volume dans Mino : elle lit des fichiers **par numéro MFT ou chemin**
sur une interface de lecture fournie par l'appelant. Le noyau et `win32k` ne
sont pas modifiés. Les critères de sortie de M9 restent inchangés.

## Contrat et périmètre

- `ReadAt` expose seulement la taille d'une partition et une lecture exacte
  à un offset en octets, relatif à cette partition. L'adaptateur doit borner ses
  accès et maintenir une vue stable du volume pendant sa lecture.
- `Geometry::read` valide le boot NTFS, les secteurs de 512 octets, les clusters
  de 512 octets à 64 Kio, la taille signée des enregistrements FILE (512 octets
  à 64 Kio) et les positions de la MFT et de son miroir.
- `Volume::open` lit le premier FILE à l'emplacement annoncé, vérifie les
  fixups USA de chaque secteur, charge le flux DATA de `$MFT`, puis vérifie
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
Le flux `$MFT` doit être intégralement initialisé et décrit dans son premier
record, sans ATTRIBUTE_LIST : son bootstrap ne peut pas encore résoudre les
extensions de sa propre table. Le miroir est localisé mais ne sert pas à
récupérer une MFT corrompue.

Pas encore de flux nommés, de journal, de récupération ou d'écriture.
Un volume valide qui sort de ce périmètre peut être refusé.
Aucune promesse de montage général de volumes NTFS existants à ce stade.

## Validation reproductible

```sh
cargo test -p ntfs
cargo clippy -p ntfs --all-targets -- -D warnings
# Outils ntfs-3g sur PATH : mkntfs, ntfscp, ntfsls, ntfscat et ntfsinfo.
cargo test -p ntfs --test mkntfs -- --ignored
```

Les tests synthétiques couvrent la MFT fragmentée, les runs vers l'arrière,
les fixups au milieu des données résidentes, les trous d'initialisation, EOF,
les erreurs d'E/S, les métadonnées tronquées ou incohérentes, les dépassements
et les fonctionnalités refusées. Un balayage de mutations d'octets exerce
les bornes du lecteur sur les métadonnées du boot et de plusieurs records.

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

## Suite, en PR distinctes

1. Bootstrap d'une MFT dont les données sont réparties entre records, avec
   validation de la progression et des références ; garder les refus pour
   les fonctionnalités restantes.
2. Adaptateur de partition et montage dans Io, à PASSIVE_LEVEL (allocations et
   E/S bloquantes), avec scénarios QEMU. Coordonner alors les changements
   partagés de `Cargo.toml`, de l'initialisation et du harness.

Le développement actuel partage seulement les manifests Cargo et la note de
passation avec les autres chantiers. Aucun fichier `abi`, USER, GDI ou pilote
M6 n'est modifié. Le code est original ; les structures disque sont décodées
par offsets, sans portage de code Microsoft ou de ntfs-3g.
