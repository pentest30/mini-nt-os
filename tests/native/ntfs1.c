/* Original native syscall probe for Mino's read-only NTFS data mount. */
typedef unsigned long ULONG;
typedef unsigned short WCHAR;
typedef long NTSTATUS;
typedef void *HANDLE;
typedef struct { unsigned short length, maximum; WCHAR *buffer; } UNICODE_STRING;
typedef struct { ULONG length; HANDLE root; UNICODE_STRING *name; ULONG attributes; void *security, *qos; } OBJECT_ATTRIBUTES;
typedef struct { NTSTATUS status; ULONG information; } IOSB;
#define IMPORT __declspec(dllimport)
IMPORT ULONG __cdecl DbgPrint(const char *, ...);
IMPORT NTSTATUS __stdcall NtTerminateProcess(HANDLE, NTSTATUS);
IMPORT NTSTATUS __stdcall NtClose(HANDLE);
IMPORT NTSTATUS __stdcall NtOpenFile(HANDLE *, ULONG, OBJECT_ATTRIBUTES *, IOSB *, ULONG, ULONG);
IMPORT NTSTATUS __stdcall NtCreateFile(HANDLE *, ULONG, OBJECT_ATTRIBUTES *, IOSB *, void *, ULONG, ULONG, ULONG, ULONG, void *, ULONG);
IMPORT NTSTATUS __stdcall NtWriteFile(HANDLE, HANDLE, void *, void *, IOSB *, void *, ULONG, void *, void *);
IMPORT NTSTATUS __stdcall NtReadFile(HANDLE, HANDLE, void *, void *, IOSB *, void *, ULONG, void *, void *);
IMPORT NTSTATUS __stdcall NtQueryInformationFile(HANDLE, IOSB *, void *, ULONG, ULONG);
IMPORT NTSTATUS __stdcall NtQueryVolumeInformationFile(HANDLE, IOSB *, void *, ULONG, ULONG);
IMPORT NTSTATUS __stdcall NtQueryDirectoryFile(HANDLE, HANDLE, void *, void *, IOSB *, void *, ULONG, ULONG, unsigned char, void *, unsigned char);
static void check(int ok, const char *where) {
    if (!ok) { DbgPrint("[ntfs] FAIL: %s\n", where); NtTerminateProcess((HANDLE)-1, (NTSTATUS)0xBAD); for (;;) {} }
}
static OBJECT_ATTRIBUTES attributes(WCHAR *path, UNICODE_STRING *name) {
    ULONG n=0; while(path[n]) ++n;
    name->buffer=path; name->length=(unsigned short)(n*2); name->maximum=name->length;
    OBJECT_ATTRIBUTES o={sizeof(o),0,name,0x40,0,0}; return o;
}
static HANDLE open_file(WCHAR *path, int directory) {
    HANDLE h=0; IOSB iosb; UNICODE_STRING name; OBJECT_ATTRIBUTES o=attributes(path,&name);
    NTSTATUS status=NtOpenFile(&h,0x100081,&o,&iosb,7,0x20|(directory?1:0x40));
    if(status) DbgPrint("[ntfs] open status %08lx\n",(ULONG)status);
    check(status==0,"open"); return h;
}
static unsigned char buffer[4096];
static void text(WCHAR *path) {
    static const char expected[]="Mino NTFS read-only\n";
    HANDLE h=open_file(path,0); IOSB iosb; unsigned long long offset=0;
    check(NtReadFile(h,0,0,0,&iosb,buffer,sizeof(buffer),&offset,0)==0,"resident read");
    check(iosb.information==sizeof(expected)-1,"resident length");
    for(ULONG i=0;i<sizeof(expected)-1;++i) check(buffer[i]==(unsigned char)expected[i],"resident contents");
    NtClose(h);
}
void __stdcall NtProcessStartup(void *peb) {
    (void)peb;
    text(L"\\??\\D:\\README.TXT"); text(L"\\??\\D:\\ÉTÉ.TXT");
    DbgPrint("[ntfs] resident and Unicode reads OK\n");
    HANDLE file=open_file(L"\\??\\D:\\large.bin",0); IOSB iosb;
    check(NtQueryInformationFile(file,&iosb,buffer,sizeof(buffer),5)==0,"file info");
    check(((ULONG *)buffer)[2]==131195 && ((ULONG *)buffer)[3]==0,"64-bit EOF size");
    unsigned long long offset=4090;
    check(NtReadFile(file,0,0,0,&iosb,buffer,32,&offset,0)==0 && iosb.information==32,"cross-cluster read");
    for(ULONG i=0;i<32;++i) check(buffer[i]==(4090+i)%251,"nonresident contents");
    offset=131190;
    check(NtReadFile(file,0,0,0,&iosb,buffer,32,&offset,0)==0 && iosb.information==5,"short read");
    offset=131195;
    check(NtReadFile(file,0,0,0,&iosb,buffer,32,&offset,0)==(NTSTATUS)0xC0000011,"EOF");
    NtClose(file); DbgPrint("[ntfs] nonresident reads and EOF OK\n");
    HANDLE root=open_file(L"\\??\\D:\\",1);
    check(NtQueryVolumeInformationFile(root,&iosb,buffer,sizeof(buffer),5)==0,"volume attributes");
    check((((ULONG *)buffer)[0]&0x80000)!=0 && ((ULONG *)buffer)[2]==8,"read-only filesystem");
    WCHAR *fs=(WCHAR *)(buffer+12); check(fs[0]=='N'&&fs[1]=='T'&&fs[2]=='F'&&fs[3]=='S',"NTFS name");
    check(NtQueryVolumeInformationFile(root,&iosb,buffer,sizeof(buffer),3)==0,"volume space");
    check(((ULONG *)buffer)[0]>0,"total clusters");
    check(NtQueryDirectoryFile(root,0,0,0,&iosb,buffer,sizeof(buffer),12,0,0,1)==0,"directory query");
    ULONG count=0, at=0, raw_name=0;
    static const WCHAR unusual[]=L"\xd800-surrogate.txt";
    for(;;) {
        ++count;
        check(at+12<=iosb.information,"directory header bounds");
        ULONG length=*(ULONG *)(buffer+at+8);
        check(at+12+length<=iosb.information,"directory name bounds");
        WCHAR *entry=(WCHAR *)(buffer+at+12);
        if(length==sizeof(unusual)-2 && entry[0]==0xd800) {
            for(ULONG i=0;i<length/2;++i) check(entry[i]==unusual[i],"raw UTF-16 preserved");
            ++raw_name;
        }
        ULONG next=*(ULONG *)(buffer+at); if(!next)break;
        at+=next; check(at<iosb.information,"directory bounds");
    }
    check(count==4 && raw_name==1,"four user files including unpaired surrogate");
    DbgPrint("[ntfs] raw UTF-16 directory names OK\n");
    NtClose(root); DbgPrint("[ntfs] volume and directory information OK\n");
    UNICODE_STRING name; OBJECT_ATTRIBUTES o=attributes(L"\\??\\D:\\readme.txt",&name); HANDLE h=0;
    const ULONG read_access[]={0x80000000,0x02000000,0x82000000};
    for(ULONG i=0;i<3;++i) {
        check(NtOpenFile(&h,read_access[i],&o,&iosb,7,0x60)==0,"generic/maximum read open");
        offset=0;
        check(NtReadFile(h,0,0,0,&iosb,buffer,1,&offset,0)==0 && buffer[0]=='M',"generic/maximum read");
        check(NtWriteFile(h,0,0,0,&iosb,buffer,1,&offset,0)==(NTSTATUS)0xC0000022,"read handle has no write grant");
        NtClose(h);
    }
    check(NtOpenFile(&h,0x02000002,&o,&iosb,7,0x60)==(NTSTATUS)0xC00000A2,"maximum plus explicit write refused");
    DbgPrint("[ntfs] generic and maximum read access OK\n");
    check(NtOpenFile(&h,0x100002,&o,&iosb,7,0x60)==(NTSTATUS)0xC00000A2,"write open refused");
    check(NtCreateFile(&h,0x100002,&o,&iosb,0,0,7,4,0x60,0,0)==(NTSTATUS)0xC00000A2,"overwrite refused");
    o=attributes(L"\\??\\D:\\new.txt",&name);
    check(NtCreateFile(&h,0x100002,&o,&iosb,0,0,7,2,0x60,0,0)==(NTSTATUS)0xC00000A2,"create refused");
    DbgPrint("[ntfs] write opens, create and overwrite refused\n[ntfs] PASS\n");
    NtTerminateProcess((HANDLE)-1,0x600D);
}
