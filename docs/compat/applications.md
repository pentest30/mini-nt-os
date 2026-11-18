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
| 1 | 7-Zip 9.20 (2010) | LGPL | MSI | `msiexec` de ReactOS, Win32, `msvcrt` | installer, archiver un fichier, l'extraire, comparer |
| 2 | Notepad++ 7.9.2 (2020) | GPL | NSIS | Scintilla, onglets, Rechercher et Remplacer | taper, remplacer, enregistrer, rouvrir |
| 3 | KeePass 1.18 (2010) | GPL | Inno Setup | MFC, cryptographie, dialogues | créer une base et une entrée, enregistrer, rouvrir avec le mot de passe |
| 4 | WinMerge 2.12.4 (2009) | GPL | Inno Setup | MFC, vues côte à côte | comparer deux fichiers, fusionner une différence, enregistrer |
| 5 | SumatraPDF 2.5.2 (2014) | GPL | le sien | rendu de pages, défilement | ouvrir un PDF fourni, page suivante, zoom |
| 6 | AbiWord 2.4.1 (2005) | GPL | NSIS | traitement de texte, polices, RTF | taper, mettre en gras, enregistrer en `.rtf`, rouvrir |
| 7 | PeaZip 3.9.1 (2011) | LGPL | Inno Setup | Lazarus et Free Pascal (LCL) | ouvrir une archive, l'extraire |
| 8 | Dev-C++ 4.9.9.2 (2005) | GPL | NSIS | Delphi (VCL), processus `gcc` lancés | ouvrir un projet, le compiler, lancer le programme |
| 9 | GIMP 2.6.12 (2011) | GPL | Inno Setup | GTK2, nombreuses DLL, fontconfig | ouvrir une image, appliquer un filtre, exporter en PNG |
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

### La suite

Les installeurs ne sont pas dans le dépôt : ils ont été téléchargés dans `third_party/apps/<application>/` (ignoré
par Git). Restent à faire, application par application :

1. une commande `xtask` qui télécharge les installeurs épinglés et vérifie leur SHA-256, comme `fetch-userland` ;
2. une fois chaque application installée, les DLL qu'elle importe (`userland::import_closure`), pour savoir ce que
   ReactOS doit fournir et ce qui passe par WinSxS ;
3. un scénario qui l'installe sur le disque système, suit son parcours et vérifie le résultat, sur AMD et Intel.

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
