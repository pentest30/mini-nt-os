# M9 préparatoire — NTFS en lecture seule

`libs/ntfs` prépare un sous-lot de M9 en parallèle de M6. La bibliothèque
Rust `no_std` + `alloc` n'a aucune dépendance externe et interdit `unsafe`.
Elle ne monte aucun volume dans Mino : elle lit des fichiers **par numéro MFT**
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

## Limites explicites

Refus des secteurs autres que 512 octets, attributs compressés, sparse ou
chiffrés, reparse points, ATTRIBUTE_LIST et enregistrements d'extension.
Le flux `$MFT` doit être intégralement initialisé et décrit dans son premier
record. Le miroir est localisé mais ne sert pas à récupérer une MFT corrompue.

Pas encore de recherche par chemin, de parcours des index de répertoires,
de traitement de `$UpCase`, de flux nommés, de journal, de récupération ou
d'écriture. Un volume valide qui sort de ce périmètre peut être refusé.
Aucune promesse de montage général de volumes NTFS existants à ce stade.

## Validation reproductible

```sh
cargo test -p ntfs
cargo clippy -p ntfs --all-targets -- -D warnings
# Outils ntfs-3g sur PATH : mkntfs, ntfscp, ntfsls et ntfscat.
cargo test -p ntfs --test mkntfs -- --ignored
```

Les tests synthétiques couvrent la MFT fragmentée, les runs vers l'arrière,
les fixups au milieu des données résidentes, les trous d'initialisation, EOF,
les erreurs d'E/S, les métadonnées tronquées ou incohérentes, les dépassements
et les fonctionnalités refusées. Un balayage de mutations d'octets exerce
les bornes du lecteur sur les métadonnées du boot et de plusieurs records.

Le test `mkntfs` est ignoré par défaut pour ne pas imposer les outils ntfs-3g
à chaque build. Le workflow séparé `.github/workflows/ntfs-readonly.yml`
lance explicitement ce test en CI quand ce composant change. Il crée deux images temporaires de 32 Mio, avec des clusters
de 512 puis 4096 octets, et y copie un petit fichier résident et un fichier
non résident de 131195 octets. Il obtient leurs numéros via `ntfsls`, compare
les octets avec les originaux et avec `ntfscat`, puis supprime les images.
Il ne monte aucun système de fichiers et ne requiert pas root.
Validé avec ntfs-3g 2022.10.3 (paquet Debian 1:2022.10.3-5+deb13u3).

## Suite, en PR distinctes

1. Index de répertoires INDEX_ROOT/INDEX_ALLOCATION, références et séquences
   FILE, puis recherche de chemins avec les règles de casse NTFS.
2. ATTRIBUTE_LIST et données réparties sur plusieurs records, si nécessaires
   aux images de référence ; garder les refus pour les fonctionnalités restantes.
3. Adaptateur de partition et montage dans Io, à PASSIVE_LEVEL (allocations et
   E/S bloquantes), avec scénarios QEMU. Coordonner alors les changements
   partagés de `Cargo.toml`, de l'initialisation et du harness.

Le développement actuel partage seulement les manifests Cargo et la note de
passation avec les autres chantiers. Aucun fichier `abi`, USER, GDI ou pilote
M6 n'est modifié. Le code est original ; les structures disque sont décodées
par offsets, sans portage de code Microsoft ou de ntfs-3g.
