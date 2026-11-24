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

## La suite : un ICD Mesa (décision à prendre)

L'`opengl32` de ReactOS (`dll/opengl/opengl32/icdload.c`) charge un ICD de deux façons :

- **par le registre, sans le noyau** : la valeur par défaut de `HKCU\SOFTWARE\ReactOS\OpenGL` nomme un pilote, décrit
  sous `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\OpenGLDrivers\<nom>` (`Dll`, `Version`, `DriverVersion`,
  `Flags`) — ce que règle `openglcfg.cpl` ;
- par le pilote d'affichage : ExtEscape(QUERYESCSUPPORT, puis OPENGL_GETINFO), NtGdiExtEscape côté noyau (pas fait).

Un ICD Mesa en rendu logiciel (Gallium llvmpipe, licence MIT), i386, donnerait des formats non génériques et
WGL_ARB_pixel_format : wined3d les retiendrait. C'est un binaire hors de ReactOS épinglé : **une ADR qui complète
l'ADR-006** doit en décider (d'où il vient — construit depuis les sources de Mesa ou une distribution binaire
vérifiée —, sa version épinglée, sa licence, sa place sur le disque, les clés de `mino.inf`). Les autres pistes
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
- **Puis l'ICD lit un pointeur nul** (0xC0000005 en `opengl32sw+0x336414`, la lecture de `[[ebx+0x10]+4]`) : la
  structure du format de pixel de la fenêtre est vide. Mesa importe SetPixelFormat et GetPixelFormat de `gdi32`, et
  chez ReactOS comme chez NT c'est le noyau qui garde le format de pixel d'une fenêtre : **NtGdiSetPixelFormat,
  NtGdiGetPixelFormat et NtGdiDescribePixelFormat n'ont pas de handler dans Mino** (le dernier est journalisé pendant
  l'essai). C'est le prochain travail côté Mino, borné : win32k garde le format de chaque fenêtre et le rend.

Ce que l'essai règle pour l'ADR : la voie du registre suffit (pas de NtGdiExtEscape), et un llvmpipe tient la pile.
Ce qu'il laisse : un binaire qui importe des fonctions de Vista ne se charge pas sur ReactOS épinglé sans être
modifié ; l'ICD retenu doit être construit pour XP (depuis les sources de Mesa, version épinglée) ou choisi sans
ces imports.

## Vu en chemin

- NtGdiExtEscape (0x108e) n'a pas de handler : `opengl32` demande QUERYESCSUPPORT pour OPENGL_GETINFO et, sans
  réponse, prend son rendu logiciel. À faire si l'on choisit la voie du pilote d'affichage.
- Un crochet de type 4 (WH_CALLWNDPROC) est posé par la pile sans être encore appelé par win32k.

## Le scénario

`d3d9-spike` est un plancher : la sonde démarre, voit les 36 formats génériques, et wined3d lit le renderer de Mesa ;
il interdit les deux échecs corrigés et les deux services sans handler. Retirer WindowFromDC le fait échouer
(vérifié). Quand l'ICD sera là, le plancher montera jusqu'au triangle (`screen` sur ses pixels).
