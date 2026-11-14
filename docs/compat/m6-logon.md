# M6 — le logon, de NtCreateToken à `userinit`

Premier critère de sortie du M6 ([05](../05-feuille-de-route.md#m6--win32k-avec-le-spike-s3-en-premier)) : « `winlogon`
(ouverture de session automatique), `userinit` et `explorer` affichent le bureau, la barre des tâches et le menu
Démarrer ». L'étape 27 du M5 ([`m5-csrss.md`](m5-csrss.md)) menait le second démarrage du scénario `logon` jusqu'à
NtCreateToken : `msgina` ouvre la session d'`Administrator` par LsaLogonUser, `msv1_0` valide le compte, et `lsasrv`
fait le jeton de la session. Ce document suit la suite, jusqu'à `userinit.exe` qui cherche le shell.

La spécification suivie est ReactOS 0.4.16 (le comportement de ses DLL et services, et `ntoskrnl/se`, `ntoskrnl/config`,
`ntoskrnl/ex/locale.c`, `ntoskrnl/ps/security.c` comme description) ; aucun code n'en est porté.

## Ce que le logon demandait, dans l'ordre

Chaque ligne est un arrêt du scénario `logon`, sa cause, et ce qui l'a levé.

1. **NtCreateToken** (`se::Token::create`, SepCreateToken ; `sys::security::nt_create_token`). `lsasrv` fait le
   jeton primaire de l'utilisateur : son SID et ses groupes, ses privilèges, son propriétaire par défaut (l'utilisateur,
   ou un groupe qui porte `SE_GROUP_OWNER` : sinon `STATUS_INVALID_OWNER`), son groupe principal (l'utilisateur ou un de
   ses groupes : sinon `STATUS_INVALID_PRIMARY_GROUP`), sa DACL par défaut, sa source, sa session d'ouverture (que le
   moniteur de références doit connaître : `STATUS_NO_SUCH_LOGON_SESSION`), sous `SeCreateTokenPrivilege`. Tout est
   capturé (`se::capture_sid`, `se::capture_acl`, partagés avec la capture des descripteurs). Un jeton d'emprunt
   d'identité prend son niveau de la qualité de service des attributs. LsaLogonUser réussit.
2. **FileEaInformation** (NtQueryInformationFile, classe 7). `userenv` fait le profil d'`Administrator` en copiant
   celui de `Default User` (CopyDirectory) ; CopyFileW demande la taille des attributs étendus avant de copier, et la
   classe manquait (erreur 87, profil refusé). Ni la FAT ni NPFS n'en ont : 0.
3. **NtLoadKey** (`cm::load_hive`, `sys::registry::nt_load_key`). `userenv` monte le `NTUSER.DAT` du profil en
   `\REGISTRY\USER\<SID>` par RegLoadKeyW, qui donne la clé relativement au handle de `HKEY_USERS` (le SID seul) :
   la ruche est lue par Io, montée sous une clé virtuelle ouverte, et NtFlushKey la réécrit dans ce fichier.
   `SeRestorePrivilege`, que `userenv` active.
4. **NtUnloadKey** (`cm::unload_hive`). `userenv` charge la ruche pour la préparer, la décharge, puis la recharge
   pour la session : sans le déchargement, le second chargement trouvait le nom pris (erreur 183). La ruche est
   réécrite si elle a changé, puis démontée ; les clés encore ouvertes la gardent.
5. **NtDuplicateToken** (`se::Token::duplicate_as`). ImpersonateLoggedOnUser fait une copie d'emprunt d'identité du
   jeton de l'utilisateur, que `winlogon` emprunte pour préparer sa session. `EffectiveOnly` ne garde que les groupes
   et privilèges actifs. Un `DesiredAccess` nul donne à la copie les droits du handle copié : c'est ce que
   DuplicateTokenEx demande pour la copie primaire de CreateProcessAsUser (sans cela, le handle n'avait aucun droit, et
   l'assignation du jeton était refusée, `STATUS_ACCESS_DENIED`).
6. **Les paramètres régionaux de l'utilisateur**. SetDefaultLanguage de `winlogon` lit
   `HKCU\Control Panel\International\Locale` et le redonne par NtSetDefaultLocale(UserProfile). La ruche DEFAULT du
   LiveCD a la clé, vide (c'est l'installation de ReactOS qui l'écrit) : la couche Mino pose `Locale` = `00000409`
   (`tools/mkhive/mino.inf`), qui passe dans `NTUSER.DAT` de `Default User`, puis dans chaque profil. NtSetDefaultLocale
   écrit maintenant la valeur de l'utilisateur dans son profil (RtlOpenCurrentUser : la ruche du SID du jeton effectif,
   `.DEFAULT` sans elle), et `ex::locale` sépare les paramètres de l'utilisateur de ceux du système (ceux du système
   tant que rien ne les fixe) ; NtQueryDefaultLocale répond selon `UserProfile`. Sans la valeur, `winlogon` fermait la
   session sans un mot (ses avertissements ne sont pas compilés dans la version publiée). `winsrv` dit alors « We are
   logged on ».
7. **ProcessAccessToken** (NtSetInformationProcess, classe 9 ; `sys::security::assign_primary_token`,
   `ps::EProcess::set_primary_token`). `msgina` lance `userinit.exe` par CreateProcessAsUserW : le processus est créé
   suspendu, puis reçoit le jeton primaire de l'utilisateur (`TOKEN_ASSIGN_PRIMARY`, un jeton primaire,
   `SeAssignPrimaryTokenPrivilege` actif).

`userinit.exe` (sur le disque depuis cette étape) tourne alors sous le jeton de l'utilisateur : il se connecte à
`csrss` et à win32k, charge la disposition de clavier, applique les paramètres de l'utilisateur
(UpdatePerUserSystemParameters), puis cherche le shell de `Winlogon\Shell`, `C:\WINDOWS\explorer.exe`, qui n'est pas
sur le disque : « Failed to start default shell », puis la boîte « Userinit failed to start the shell! ».

## `explorer`

`xtask` met maintenant les programmes du répertoire Windows de ReactOS sur le disque, dans `WINDOWS` (`explorer.exe`),
avec leurs imports (`browseui.dll`…) dans la fermeture de `system32` (`userland::WINDOWS_PROGRAMS`). `userinit` le
lance, et win32k convertit son thread. **Où le logon s'arrête aujourd'hui** : `explorer` lève une exception dès ses
premiers pas (STATUS_PRIVILEGED_INSTRUCTION dans l'en-tête de `shlwapi.dll`). Sa pile est écrasée par
« Shell_TrayWnd » : NtUserGetAtomName prenait son second argument, un `PUNICODE_STRING`, pour le tampon, et écrivait le
nom par-dessus la structure et la pile de l'appelant. Le correctif est celui de la boîte Enregistrer sous
(`claude/blissful-herschel-4bf0cc`, commit `4226c9c`, à fusionner avant la suite).

Avec ce correctif appliqué, `explorer` crée la fenêtre de sa barre des tâches et va plus loin ; ce qu'il demande
ensuite, dans l'ordre où cela bloque :

1. **Les classes COM de `browseui` et `shell32`** : CLSID_StartMenu (`{4622AD11-FF23-11D0-8D34-00A0C90F2719}`) et
   CLSID_RebarBandSite (`{ECD4FC4D-521C-11D0-B792-00A0C90312E1}`) ne sont pas enregistrées (`REGDB_E_CLASSNOTREG`) :
   l'installation de ReactOS appelle DllRegisterServer des DLL de `syssetup.inf` (`RegistrationPhase2`,
   `OleControlDlls`), que `minoinit.exe` ne fait pas encore.
2. **Les fenêtres « message seul »** (`HWND_MESSAGE`, « not yet ») : la fenêtre d'appartement de COM n'est pas créée
   (`combase` apartment.c : « CreateWindow failed with error 1400 »).
3. **DeferWindowPos** (NtUserCallOneParam 0x1E, BeginDeferWindowPos : « BeginDeferWindowPos failed. lastErr=120 »),
   NtUserSetWindowRgn, SystemParametersInfo (0x2B, 0x2F), NtUserCallOneParam 0x27, NtUserGetSystemMenu.
4. Le bureau du shell échoue (`desktop.cpp:193`, E_FAIL), puis une assertion d'ATL (`atlcomcli.h:208`, `p != 0`).
5. Côté icônes : NtUserGetIconInfo, NtGdiGetDIBitsInternal, NtUserRemoveProp (le travail de la boîte Enregistrer sous).

## Vu en chemin, pas fait

- Le thread de `userinit` n'a pas de bureau de démarrage : « no startup desktop for thread … of userinit.exe
  (STATUS_NOT_IMPLEMENTED) » (`win32k::startup`) ; il prend celui de son processus ensuite. À diagnostiquer avant
  `explorer`, qui doit s'ouvrir sur `WinSta0\Default`.
- NtDeleteKey (le nettoyage de `winlogon` à la fermeture d'une session : `Volatile Environment`), FileStreamInformation
  (classe 22, que CopyFileW demande sans en dépendre), NtUserSetThreadState, NtUserUpdatePerUserSystemParameters
  (rend 0), NtUserSystemParametersInfo (classes 0x0E, 0x14, 0x5A), NtUserCallOneParam (0x31), NtUserCallHwnd.
- La parenté des jetons (`ParentTokenId`, SeIsTokenChild, SeIsTokenSibling) n'est pas suivie : un jeton tiré de celui
  de l'appelant demande donc aussi `SeAssignPrimaryTokenPrivilege` ; `winlogon` l'a actif.
- NtUnloadKey démonte une ruche dont des clés sont ouvertes (NT refuse : `STATUS_CANNOT_DELETE`).
- NtLoadKey refuse un fichier désigné relativement à un répertoire ouvert (`STATUS_NOT_IMPLEMENTED`) : sa réécriture
  demande son nom entier.

## La suite

Fusionner le correctif de NtUserGetAtomName, puis lever les blocages d'`explorer` ci-dessus dans l'ordre : les classes
COM (DllRegisterServer dans `minoinit`), les fenêtres message seul, DeferWindowPos ; ensuite ce qu'il demandera pour
la barre des tâches (crochets, `SetWindowsHookEx`, presse-papiers, notifications), `NtNotifyChangeKey`, puis le bureau
du critère.

## Tests

Hôte : `se` (un jeton créé tel qu'on l'a donné, le propriétaire et le groupe principal refusés, un jeton d'emprunt
d'identité créé, la copie « effective only »), `cm` (une ruche montée sous une clé virtuelle ouverte, refusée sous une
clé de ruche, déchargée puis rechargée), `ex` (les paramètres de l'utilisateur suivent ceux du système jusqu'à être
fixés). Scénario `logon` : les marqueurs du profil chargé (`IncrementRefCount(S-1-5-21-…)`), de la session ouverte
(« We are logged on »), de `userinit` (son thread converti, « Failed to start default shell ») ; chaque échec traversé
est interdit (NtCreateToken, LsaLogonUser, le profil, RegLoadKeyW, ImpersonateLoggedOnUser, l'assignation du jeton,
CreateProcessAsUserW). Neuf mutations (chacun des sept services ou classes retiré, la valeur `Locale` de la couche, les
droits d'une copie à `DesiredAccess` nul) font échouer le scénario.

Les apitests de `ntdll` (scénario `rostests`) restent à 43 sur 84, le plancher, mais pas les mêmes : NtDuplicateToken
(un `NewTokenHandle` nul : `STATUS_ACCESS_VIOLATION`, la poignée écrite d'abord, comme ProbeForWriteHandle) et
NtOpenThreadToken passent ; NtAccessCheck et NtAccessCheckByTypeResultList, qui passaient en se sautant faute de
NtDuplicateToken (GetToken), vont maintenant jusqu'à NtAccessCheck, pas encore là (SeAccessCheck, ADR-011).
NtSetDefaultLocale de l'utilisateur rend `STATUS_OBJECT_NAME_NOT_FOUND` pour un LCID que `Nls\Locale` ne connaît
pas, comme l'apitest l'attend d'XP (ExpValidateNlsLocaleId : la valeur introuvable) ; un groupe de langues absent
reste `STATUS_INVALID_PARAMETER`.
