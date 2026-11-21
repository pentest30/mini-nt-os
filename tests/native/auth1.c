/* Authenticode under Mino, as Notepad++ 7.9.2 checks the signature of its
   own DLLs: WinVerifyTrust, then the signer's certificate through
   CryptQueryObject, CryptMsgGetParam, CertFindCertificateInStore,
   CertNameToStr, CertGetCertificateContextProperty and CertGetNameString;
   on the installer of Notepad++ in C:\APPS, signed by the same certificate.
   Started by userinit as the shell of the logged-on user (a scenario's
   `session`): crypt32 hashes through rsaenh, whose CryptAcquireContext asks
   the user's name (GetUserNameW, LSA); minoinit registered the providers.
   Each step prints its result and last error. */
#include "app_probe.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#define TAG "[auth] "

typedef BOOL(WINAPI *QueryObjectFn)(DWORD, const void *, DWORD, DWORD, DWORD, DWORD *, DWORD *, DWORD *, HCERTSTORE *,
                                    HCRYPTMSG *, const void **);
typedef BOOL(WINAPI *MsgGetParamFn)(HCRYPTMSG, DWORD, DWORD, void *, DWORD *);
typedef PCCERT_CONTEXT(WINAPI *FindCertFn)(HCERTSTORE, DWORD, DWORD, DWORD, const void *, PCCERT_CONTEXT);
typedef DWORD(WINAPI *NameToStrFn)(DWORD, PCERT_NAME_BLOB, DWORD, LPWSTR, DWORD);
typedef BOOL(WINAPI *GetPropertyFn)(PCCERT_CONTEXT, DWORD, void *, DWORD *);
typedef DWORD(WINAPI *GetNameStringFn)(PCCERT_CONTEXT, DWORD, DWORD, void *, LPWSTR, DWORD);
typedef LONG(WINAPI *VerifyTrustFn)(HWND, GUID *, void *);
typedef BOOL(WINAPI *GetUserNameFn)(LPWSTR, DWORD *);
typedef BOOL(WINAPI *AcquireFn)(HCRYPTPROV *, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef BOOL(WINAPI *ReleaseFn)(HCRYPTPROV, DWORD);

static char narrow_buffer[512];
static const char *narrow(const WCHAR *w)
{
    if (!WideCharToMultiByte(CP_ACP, 0, w, -1, narrow_buffer, sizeof(narrow_buffer), 0, 0)) narrow_buffer[0] = 0;
    narrow_buffer[sizeof(narrow_buffer) - 1] = 0;
    return narrow_buffer;
}

static FARPROC entry(HMODULE dll, const char *name)
{
    FARPROC f = dll ? GetProcAddress(dll, name) : 0;
    if (!f) DbgPrint(TAG "FAIL no %s (%lu)\n", name, GetLastError());
    return f;
}

static void stop(const char *what)
{
    DbgPrint(TAG "FAIL %s (last error %lx)\n", what, GetLastError());
    ExitProcess(1);
}

DWORD WINAPI GuiStartup(void)
{
    static const WCHAR path[] = L"C:\\APPS\\npp.7.9.2.Installer.exe";
    static WCHAR text[512];
    HMODULE crypt32 = LoadLibraryW(L"crypt32.dll"), wintrust = LoadLibraryW(L"wintrust.dll");
    HMODULE advapi32 = LoadLibraryW(L"advapi32.dll");
    QueryObjectFn query = (QueryObjectFn)(void *)entry(crypt32, "CryptQueryObject");
    MsgGetParamFn get_param = (MsgGetParamFn)(void *)entry(crypt32, "CryptMsgGetParam");
    FindCertFn find = (FindCertFn)(void *)entry(crypt32, "CertFindCertificateInStore");
    NameToStrFn name_to_str = (NameToStrFn)(void *)entry(crypt32, "CertNameToStrW");
    GetPropertyFn get_property = (GetPropertyFn)(void *)entry(crypt32, "CertGetCertificateContextProperty");
    GetNameStringFn get_name = (GetNameStringFn)(void *)entry(crypt32, "CertGetNameStringW");
    VerifyTrustFn verify = (VerifyTrustFn)(void *)entry(wintrust, "WinVerifyTrust");
    GetUserNameFn get_user = (GetUserNameFn)(void *)entry(advapi32, "GetUserNameW");
    AcquireFn acquire = (AcquireFn)(void *)entry(advapi32, "CryptAcquireContextW");
    ReleaseFn release = (ReleaseFn)(void *)entry(advapi32, "CryptReleaseContext");
    DWORD encoding = 0, content = 0, format = 0, size = 0, n;
    HCERTSTORE store = 0;
    HCRYPTMSG msg = 0;
    HCRYPTPROV prov = 0;
    CMSG_SIGNER_INFO *signer;
    CERT_INFO info = {0};
    PCCERT_CONTEXT cert;
    BYTE key[64];

    DbgPrint(TAG "the probe starts\n");
    if (!query || !get_param || !find || !name_to_str || !get_property || !get_name || !verify || !get_user ||
        !acquire || !release)
        stop("the entry points");

    /* rsaenh names its default key container after the user. */
    n = sizeof(text) / sizeof(text[0]);
    if (!get_user(text, &n)) stop("GetUserNameW");
    DbgPrint(TAG "user: %s\n", narrow(text));
    if (!acquire(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) stop("CryptAcquireContextW");
    release(prov, 0);
    DbgPrint(TAG "CryptAcquireContextW: the default provider\n");

    {
        WINTRUST_FILE_INFO file = {sizeof(file), path, 0, 0};
        WINTRUST_DATA data = {0};
        GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG trust;
        data.cbStruct = sizeof(data);
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.pFile = &file;
        trust = verify(0, &policy, &data);
        DbgPrint(TAG "WinVerifyTrust: %lx\n", (DWORD)trust);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        verify(0, &policy, &data);
        /* Notepad++ refuses a DLL whose signature does not verify. */
        if (trust != 0) {
            SetLastError((DWORD)trust);
            stop("WinVerifyTrust");
        }
    }

    if (!query(CERT_QUERY_OBJECT_FILE, path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
               &encoding, &content, &format, &store, &msg, 0))
        stop("CryptQueryObject");
    DbgPrint(TAG "CryptQueryObject: the embedded signature\n");
    if (!get_param(msg, CMSG_SIGNER_INFO_PARAM, 0, 0, &size)) stop("CryptMsgGetParam (size)");
    signer = (CMSG_SIGNER_INFO *)LocalAlloc(LPTR, size);
    if (!signer || !get_param(msg, CMSG_SIGNER_INFO_PARAM, 0, signer, &size)) stop("CryptMsgGetParam");
    info.Issuer = signer->Issuer;
    info.SerialNumber = signer->SerialNumber;
    cert = find(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &info, 0);
    if (!cert) stop("CertFindCertificateInStore");
    n = name_to_str(X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_X500_NAME_STR, text, 512);
    if (n <= 1) stop("CertNameToStr");
    DbgPrint(TAG "subject: %s\n", narrow(text));
    size = sizeof(key);
    if (!get_property(cert, CERT_KEY_IDENTIFIER_PROP_ID, key, &size) || size == 0)
        stop("CertGetCertificateContextProperty");
    DbgPrint(TAG "key identifier: %lu bytes\n", size);
    n = get_name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0, text, 512);
    if (n <= 1) stop("CertGetNameString");
    DbgPrint(TAG "signer: %s\n", narrow(text));
    DbgPrint(TAG "PASS\n");
    ExitProcess(0);
    return 0;
}
