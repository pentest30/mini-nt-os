# M8 — Direct3D sous la pile de ReactOS épinglée (spike)

Le premier critère du M8 ([05](../05-feuille-de-route.md#m8--multimédia-et-jeux)) passe par Direct3D. L'ADR-006
prévoit la pile de la version épinglée : `d3d8`, `d3d9` et `ddraw` de Wine, wined3d, puis `opengl32` de Mesa en
rendu logiciel, puis GDI. Ce spike (2026-11-24) vérifie ce qu'elle donne sous Mino avec une sonde minimale.

## La sonde

`tests/native/d3d1.c` (`D3D1.EXE`, commande initiale du scénario `d3d9-spike`) : une fenêtre, Direct3DCreate9, les
formats de pixel de son DC, un device D3D9 en mode fenêtré, un effacement bleu, un triangle rouge, Present ; chaque
étape imprime son résultat. Elle importe `d3d9.dll` (`tests/native/d3d9.def`) : `xtask` met maintenant sur le disque
de démarrage les DLL que les programmes de `tests/native` importent au-delà de la fermeture de l'espace utilisateur
(`userland::program_imports`) — `d3d9`, `d3dwine` (le wined3d de ReactOS), `opengl32` — sans alourdir les autres
scénarios.

## Ce que la pile épinglée contient

| DLL | Ce que c'est |
|---|---|
| `d3d8.dll`, `d3d9.dll`, `ddraw.dll` | Wine, au-dessus de `d3dwine.dll` |
| `d3dwine.dll` | wined3d (Wine), qui importe `opengl32.dll` |
| `opengl32.dll` | l'`opengl32` de ReactOS avec Mesa intégré en rendu logiciel (« Mesa ReactOS SW Implementation ») |
| `d3dx9_*`, `d3dcompiler_43`, `dinput`, `dinput8`, `dsound`, `winmm`, `quartz` | présents |
| `drivers/`: `portcls.sys`, `ks.sys`, `sysaudio.sys`, `hdaudbus.sys`, `ac97.sys` | pilotes de ReactOS (le son passera par l'ADR à écrire, ADR-008 : pilotes en Rust) |

## Ce qui a bloqué, dans l'ordre

1. **La fenêtre cachée de wined3d** : il enregistre sa classe avec l'instance de sa DLL, puis la crée avec une
   instance nulle (« Failed to create a window »). Corrigé par la PR 175 (une instance nulle trouve la classe privée
   de toute instance), que cette branche fusionne.
2. **WindowFromDC et NtGdiGetDCDword(GdiGetIsMemDc)** : `opengl32` distingue le DC d'une fenêtre d'un DC en mémoire
   avant de proposer ses formats (« Failed to find a suitable pixel format »). Faits dans cette branche, comme ReactOS :
   `ONEPARAM_ROUTINE_WINDOWFROMDC` (0x1F : `win32k::dce::window_from_dc`, IntWindowFromDC) et NtGdiGetDCDword
   (`dcutil.c` : GdiGetJournal, GdiGetEMFRestorDc, GdiGetIsMemDc ; les autres index refusés et journalisés une fois).
   wined3d crée alors son contexte GL et lit `GL_RENDERER` « Mesa ReactOS SW Implementation ».
3. **Aucun format de pixel retenu — bloquant, par conception de la pile épinglée.** Sans l'extension
   WGL_ARB_pixel_format, wined3d énumère les formats par DescribePixelFormat et écarte tout format
   `PFD_GENERIC_FORMAT` (`wined3d_adapter_init_fb_cfgs`, `directx.c`) ; or les 36 formats de l'`opengl32` épinglé
   sont tous génériques (mesuré : drapeaux `0x7c`, `0x465`…, `PFD_GENERIC_FORMAT` partout). wined3d n'a aucun
   format (« No suitable pixel formats found », un WARN) et **Direct3DCreate9 rend NULL**. Ce n'est pas un manque de
   Mino : ReactOS lui-même a besoin d'un pilote OpenGL installable (ICD) pour Direct3D.

## La suite : un ICD Mesa (ADR-025)

L'`opengl32` de ReactOS (`dll/opengl/opengl32/icdload.c`) charge un ICD de deux façons :

- **par le registre, sans le noyau** : la valeur par défaut de `HKCU\SOFTWARE\ReactOS\OpenGL` nomme un pilote, décrit
  sous `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\OpenGLDrivers\<nom>` (`Dll`, `Version`, `DriverVersion`,
  `Flags`) — ce que règle `openglcfg.cpl` ;
- par le pilote d'affichage : ExtEscape(QUERYESCSUPPORT, puis OPENGL_GETINFO), NtGdiExtEscape côté noyau (pas fait).

Un ICD Mesa en rendu logiciel (Gallium llvmpipe, licence MIT), i386, donnerait des formats non génériques et
WGL_ARB_pixel_format : wined3d les retiendrait. C'est un binaire hors de ReactOS épinglé : l'ADR-025 (acceptée,
elle complète l'ADR-006) en décide — construit pour XP par `xtask` depuis des sources épinglées de Mesa, annoncé par
le pilote d'affichage (NtGdiExtEscape) et décrit dans `mino.inf`. Les autres pistes
écartées : remplacer l'`opengl32` de ReactOS (sort de la frontière de l'ADR-002) ; modifier wined3d pour garder les
formats génériques (binaire épinglé modifié, et GDI est la voie la plus lente) ; DXVK (écarté par l'ADR-006).

## L'essai d'un ICD Mesa (2026-11-24, rien de commité)

Un ICD Mesa llvmpipe i386 déjà construit (`opengl32sw.dll` de la publication 17.0.1.391-2 de `pal1000/mesa-dist-win`,
licence MIT, archive `mesa-17.0.1-391-x86.zip`, SHA-256
`ca04f7190b8c3bc3d9f1f206e9fcdb3c7886d2282bff93d20ecfe8c6b8ae7daa`), posé dans `C:\APPS` d'un disque du banc, la
sonde écrivant les clés de `openglcfg.cpl` (`HKCU\SOFTWARE\ReactOS\OpenGL` = `MesaSW` ;
`OpenGLDrivers\MesaSW` : `Dll`, `Version` 2, `DriverVersion` 1, `Flags` 1).

- La DLL vise Vista (sous-système 6.0) et importe deux fonctions que ReactOS épinglé n'a pas : SHGetKnownFolderPath
  (nulle part) et GetFinalPathNameByHandleW (dans `kernel32_vista.dll`, pas dans `kernel32`). Pour l'essai seulement,
  une copie renommait ces imports (SHGetFolderPathW, GetFullPathNameW).
- **La voie marche** : `opengl32` lit la clé (« Overriding the default OGL ICD with MesaSW »), charge l'ICD (ses
  `api-ms-win-*` redirigés vers `kernel32` par ApiSetResolveToHost), DescribePixelFormat donne 84 formats dont 48 non
  génériques, et wined3d lit `GL_RENDERER` « Gallium 0.4 on llvmpipe (LLVM 3.9, 128 bits) ».
- **Puis l'ICD lit un pointeur nul** (0xC0000005 en `opengl32sw+0x336414`, `[[ebx+0x10]+4]`), dans un parcours
  de l'arbre du compilateur GLSL de Mesa (un nœud dont le type est nul) que wined3d déclenche en préparant ses shaders.
  **Ce n'est pas un manque de Mino.** La DLL, construite par MSVC pour Vista, a une TLS implicite (section `.tls`,
  39 accès par `fs:[0x2C]` et `_tls_index`) : l'état de ses statiques locales initialisées une fois (« magic
  statics » de MSVC, dont les types GLSL) y vit. Le chargeur d'XP — et `ntdll` de ReactOS épinglé
  (`LdrpAllocateTls` seulement au démarrage du processus) — n'alloue pas de TLS implicite à une DLL chargée par
  LoadLibrary, ce que fait `opengl32` ; Vista le fait. `_tls_index` vaut 0, l'état lu est celui du bloc TLS de
  l'exécutable, une statique passe pour initialisée et reste nulle.
- **Vérifié** : quand la sonde importe l'ICD (chargé au démarrage du processus, sa TLS allouée par le chargeur, et
  `opengl32` le retrouvant par son nom), tout passe — Direct3DCreate9, GetDeviceCaps (shaders 3.0), CreateDevice(HAL),
  Clear, DrawPrimitiveUP, Present — et **le triangle rouge sur fond bleu s'affiche** (capture du 2026-11-24). Les
  seuls services sans handler sur ce chemin étaient NtGdiGetDeviceGammaRamp (wined3d s'en passe) et ceux du
  format de pixel, faits depuis (ci-dessous).
- **NtGdiDescribePixelFormat, NtGdiSetPixelFormat et NtGdiSwapBuffers** : `opengl32` demande à chaque ICD chargé
  (`IntGetIcdData`, `icdload.c`) si win32k fait l'OpenGL à sa place (GdiDescribePixelFormat). Chez ReactOS, ils
  passent au pilote d'affichage (DrvDescribePixelFormat…), que le framebuffer n'a pas : aucun format, rien à poser
  ni à échanger. Faits ainsi dans Mino (`sys::gdi`) ; le format de pixel d'une fenêtre est gardé par `opengl32`
  (`wgl_dc_data`) et par l'ICD, pas par win32k.

Ce que l'essai règle pour l'ADR : la voie du registre suffit (pas de NtGdiExtEscape), llvmpipe tient la pile jusqu'au
triangle, et Mino n'a rien d'autre à fournir pour lui. Ce qu'il laisse : l'ICD retenu doit se charger sous un
chargeur d'XP par LoadLibrary — sans imports de Vista et **sans TLS implicite** (Mesa construit pour XP depuis ses
sources épinglées : MinGW, dont `__thread` passe par TlsAlloc, ou MSVC avec `/Zc:threadSafeInit-` et sans
`__declspec(thread)`). Allouer la TLS implicite au chargement dynamique serait changer le `ntdll` épinglé, hors de la
frontière de l'ADR-002.

## L'ICD construit pour XP : `cargo xtask icd-build` (étape 1 du spike « ICD XP »)

`xtask/src/icd.rs` construit `third_party/mesa-icd/mesaicd.dll` depuis des sources épinglées (taille et SHA-256) :
Mesa 20.3.5 (la dernière version qui a les variables de condition d'XP ; la 21.0 prend celles des systèmes
suivants), LLVM 11.1.0 (bibliothèques X86 et `llvm-config` seulement : ses outils appellent des fonctions plus
récentes qu'XP) et zlib 1.2.11 (le wrap de Mesa, lié en statique, pris du cache de paquets de Meson, sans réseau).
Les archives `.tar.xz` passent par `xz -dc` (dans un fichier : un tube depuis le `xz` de MSYS2 se bloque) et un
lecteur tar de `xtask` (`xtask/src/tar.rs` : un lien devient la copie de sa cible, ce qui marche sous Windows sans
privilège ; le `tar` de Windows ne lit pas le xz).

- **La chaîne** : un GCC MinGW-w64 i686 dont `__thread` est émulé (`__emutls_get_address`, TlsAlloc). `xtask` le
  vérifie avant de construire : le GCC 16 de MSYS2, configuré `--enable-tls`, compile une TLS native (`%fs:44`,
  `__tls_index`), que le chargeur d'XP n'alloue pas à une DLL chargée par LoadLibrary ; il est refusé. Vérifié
  avec le GCC 14.3.0 de winlibs (i686, posix, dwarf, msvcrt). C'est la précision que l'ADR-025 laissait à la
  construction (« la chaîne MinGW-w64 i686 ») ; `--toolchain DIR` désigne son répertoire `bin`.
- **Les corrections de Mesa** (`icd::PATCHES`, chacune trouvée exactement le nombre de fois attendu, sinon la
  construction s'arrête) : en-têtes d'XP (`_WIN32_WINNT` et `WINVER` à 0x0501, au lieu de 0x0A00) ; pas de
  `dlopen` ni de `dladdr` sous Windows (une libdl sans `<dlfcn.h>` faisait compiler `dladdr`) ; pas de `dumpbin`
  exigé ; les types récents de `gldrv.h` compilés quel que soit `WINVER` (DrvSetCallbackProcs ne copie que les
  rappels que donne `opengl32`).
- **Les fonctions récentes de LLVM** (`xtask/icd-src/xpcompat.c`) : GetFinalPathNameByHandleW,
  GetLogicalProcessorInformationEx, Get/SetThreadGroupAffinity, SetFileInformationByHandle, K32EnumProcessModules
  et K32GetProcessMemoryInfo (`psapi` sous XP), SHGetKnownFolderPath. Chacune est définie sous son nom et sous son
  slot d'import, appelle la vraie fonction quand le système l'a, et sinon échoue comme pour une demande non prise en
  charge.
- **LLVM vu de Mesa** : un sous-projet Meson (`subprojects/llvm`, écrit par `xtask` d'après `llvm-config`, comme
  `docs/meson.rst` de Mesa le décrit pour Windows) et pas `llvm-config` lui-même, dont Meson coupe la sortie aux
  espaces (le chemin du dépôt peut en avoir un) ; pour la même raison, `Remarks.dll` et `LTO.dll` de LLVM, inutiles
  à Mesa, ne sont pas construites (leur `.def` passe à l'éditeur de liens sans guillemets).
- **L'édition de liens** : tout en statique (ni `libgcc`, ni `libstdc++`, ni `libwinpthread` à côté), versions
  de sous-système et d'OS 5.1.
- **Les vérifications** (`icd::check`), avant le tampon : version de sous-système au plus 5.1 ; chaque import
  trouvé dans les exports de la DLL du même nom du `system32` épinglé ; pas de modèle de TLS au-delà des marqueurs
  du CRT de MinGW (8 octets au plus) ni de lecture de `fs:[2Ch]` dans le code. La DLL de 50 Mio passe :
  sous-système 5.1, 275 imports trouvés, un modèle de TLS de 4 octets, 0 lecture de `fs:[2Ch]` (construite en
  11 minutes une fois LLVM construit).
- **Essayée sous Mino** (le 2026-11-24, la DLL que `icd-build` a construite et vérifiée ; crochets d'essai non
  commités : `C:\APPS` d'un disque du banc, clés d'`openglcfg.cpl`) : `opengl32` la charge par LoadLibrary, sans
  import de la sonde, et **le triangle s'affiche**.

À faire avant d'en dépendre dans un scénario :
- ~~Le noyau lit une image en un seul bloc~~ : `io::File::image_contents` allouait la DLL (une cinquantaine de Mio)
  d'un tenant dans le tas du noyau, ce qui échouait avec les 256 Mio du banc (STOP, « memory allocation of 52755544
  bytes failed », depuis NtCreateSection) ; l'essai avait pris 1 Gio. **Corrigé** (`claude/image-read`, ADR-024
  précisée) : une section d'image ne lit que ses en-têtes, ses pages viennent du fichier à la faute, et son fichier
  ne s'écrit ni ne s'efface tant qu'elle vit. Vérifié le 2026-11-25 avec les mêmes crochets d'essai, sans
  `memory = 1024` : l'ICD se charge avec 256 Mio (143 Mio libres au démarrage) et le triangle s'affiche.
- Le disque RAM de démarrage ne dépasse pas 64 Mio : l'ICD ira sur un disque système plus grand (comme `app =`).
- Les avis de licence (Mesa, LLVM, zlib) sont copiés dans `third_party/mesa-icd/licences/` ; ils iront sur le
  disque avec la DLL.
- Un hôte Linux demanderait une construction croisée de LLVM (`llvm-config` et `tblgen` de l'hôte) : pas encore,
  `icd-build` s'y arrête en le disant.

## Vu en chemin

- NtGdiGetDeviceGammaRamp (0x10ab) n'a pas de handler : wined3d le demande à la création du device et s'en passe.
- NtGdiExtEscape (0x108e) n'a pas de handler : `opengl32` demande QUERYESCSUPPORT pour OPENGL_GETINFO et, sans
  réponse, prend son rendu logiciel. À faire si l'on choisit la voie du pilote d'affichage.
- Un crochet de type 4 (WH_CALLWNDPROC) est posé par la pile sans être encore appelé par win32k.

## Le scénario

`d3d9-spike` est un plancher : la sonde démarre, voit les 36 formats génériques, et wined3d lit le renderer de Mesa ;
il vérifie ce que win32k dit des formats de pixel (aucun décrit, posé ni échangé ; un DC en mémoire et un handle
faux) et interdit les deux échecs corrigés et les cinq services sans handler. Retirer WindowFromDC le fait échouer
(vérifié). Quand l'ICD sera là, le plancher montera jusqu'au triangle (`screen` sur ses pixels).
