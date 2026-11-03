# M6 : les fenêtres, avec le vrai `user32`

Observations du début du M6 ([05](../05-feuille-de-route.md#m6--win32k-avec-le-spike-s3-en-premier)) : ce que fait un
programme Win32 de test, lié au `user32` de ReactOS 0.4.16, quand il enregistre des classes et crée des fenêtres sur
le win32k de Mino. À mettre à jour à chaque étape.

## Le banc d'essai : `GUI1.EXE` à la place de `winlogon.exe`

`winlogon` s'arrête avant sa première fenêtre (son serveur RPC demande les tubes nommés, puis viennent `services`,
`lsass` et `msgina` : [`m5-csrss.md`](m5-csrss.md)). Le scénario `gui` donne donc à `smss` un autre programme à lancer
comme commande initiale : `tests/native/gui1.c`, compilé par MinGW (sous-système WINDOWS 5.1, sans runtime C, entrée
`GuiStartup`), lié à `ntdll`, `kernel32` et `user32` par des bibliothèques d'importation tirées de
`tests/native/*.def`. La clé `initial-command = GUI1.EXE` du scénario le met sur le disque à la place de
`WINDOWS\SYSTEM32\WINLOGON.EXE` (`xtask`, `put_initial_command`). `smss` le lance comme il lancerait `winlogon`,
`csrss` en fait un processus CSR, et son `user32` se connecte à `csrss` et à win32k comme celui de `winlogon` (dont
le rappel ClientThreadSetup).

Comme `winlogon`, le programme s'inscrit comme processus de logon (RegisterLogonProcess), crée `WinSta0` et le bureau
`Default`, s'y place et y passe (SwitchDesktop : le fond du bureau est peint). Chaque étape, et chaque message que
reçoit sa procédure de fenêtre, va au port de débogage (`DbgPrint`), où le scénario les cherche ; il se termine avec
un statut qui dit où il s'est arrêté.

## Étape 1 : les classes de fenêtres

`RegisterClassExW` de `user32` enregistre d'abord ses contrôles du système (RegisterSystemControls : Button, ListBox,
Edit, Static, Ghost… avec leur FNID et `CS_GLOBALCLASS`), puis la classe demandée, par NtUserRegisterClassExWOW.
Pour chacun, `LoadCursorW` cherche un curseur partagé (NtUserFindExistingCursorIcon) puis en crée un (NtGdiOpenDCW) :
ces services manquent, la classe n'a pas de curseur, et l'enregistrement continue.

| Partie | Ce qu'elle fait |
|---|---|
| `win32k::atom` | la table des atomes de USER (gAtomTable), aux règles de RtlAddAtomToAtomTable : atome entier (de 1 à `0xBFFF`, ou `#` et des chiffres) sans entrée ; nom en chaîne de 255 caractères au plus, atome à partir de `0xC000`, le même sans tenir compte de la casse, compte de références, place réutilisée |
| `win32k::class` | les classes privées et publiques de chaque processus (les plus récentes d'abord) ; à son premier enregistrement, les classes du système à procédure du serveur (bureau, menus, sélecteur de tâches, barres de défilement, titres d'icônes, fenêtres de messages) ; deux atomes par classe (nom et version) ; une procédure du client qui est celle d'une classe à procédure du serveur donne cette procédure (`CSF_SERVERSIDEPROC`) ; la recherche de CreateWindowEx (privée de l'instance, publique, puis celles de `user32`) ; le `CLS` dans le tas de chaque bureau où la classe aura une fenêtre |
| NtUserRegisterClassExWOW (`sys::class`) | les refus de ReactOS (drapeau autre que `CSF_ANSIPROC` : `ERROR_INVALID_FLAGS` ; taille de `WNDCLASSEXW`, longueurs impaires, octets de plus négatifs ou qui débordent, instance nulle, nom vide qui n'est pas un atome : `ERROR_INVALID_PARAMETER`) ; une classe privée de la même instance, ou publique, du même nom : `ERROR_CLASS_ALREADY_EXISTS` ; rend l'atome du nom |
| NtUserGetClassInfo (`sys::class`) | le `WNDCLASSEXW` de la classe que CreateWindowEx trouverait (instance nulle : celle de `user32`), procédure vue par le client (ANSI ou non), `CS_GLOBALCLASS` ôté d'une classe à FNID ; rend l'atome du nom ; sans classe : `ERROR_CLASS_DOES_NOT_EXIST` |

Le programme enregistre sa classe (atome `0xC00A`, après celles des contrôles), la retrouve telle qu'il l'a donnée
(`GetClassInfoExW`), retrouve la classe Button de `user32` (globale, mais sans `CS_GLOBALCLASS` puisqu'elle a un
FNID), ne trouve pas une classe jamais enregistrée (1411) et ne peut pas enregistrer la sienne deux fois (1410). Il
s'arrête à NtUserCreateWindowEx (statut 3).

Écarts : ni objets curseur et icône (les handles sont gardés, `spicn` et `spcur` restent nuls), ni pinceaux (un
pinceau du système vaut sa couleur plus un, comme pour la classe du bureau) ; le nom de menu reste dans le client
(les pointeurs de `CLSMENUNAME`) ; le compte des fenêtres d'une classe n'est pas tenu dans le `CLS` ; pas de
`atomSysClass` dans le `SERVERINFO` ; ni désenregistrement (NtUserUnregisterClass), ni procédures d'appel (une
classe Unicode demandée en ANSI rend sa procédure, journalisé une fois).

Tests : hôte (`win32k::atom` : casse, atomes entiers, longueurs, références et réutilisation ; `win32k::class` :
recherche par nom et par atome, instance, classes globales, celles de `user32` en dernier, refus d'un double,
atomes rendus, classes du système une fois, procédure du serveur reprise) ; le scénario `gui`, sur les deux CPU.
