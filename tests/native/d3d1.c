/* M8 spike: Direct3D 9 under Mino, through the pinned ReactOS stack (d3d9,
   Wine's d3d9 over wined3d in d3dwine.dll, over opengl32.dll's Mesa software
   renderer, over GDI). A window, a device, a blue clear, a red triangle,
   Present; each step prints its result. Taking WinSta0\Default, it replaces
   winlogon (initial-command). */
#define COBJMACROS
#include "app_probe.h"
#include <d3d9.h>

#define TAG "[d3d] "

typedef struct {
    float x, y, z, rhw;
    DWORD color;
} Vertex;

static LRESULT CALLBACK proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

static void pump(DWORD ms)
{
    DWORD end = GetTickCount() + ms;
    MSG msg;
    while ((LONG)(GetTickCount() - end) < 0) {
        while (PeekMessageW(&msg, 0, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
}

static void finish(const char *verdict)
{
    DbgPrint(TAG "%s\n", verdict);
    DbgPrint(TAG "the probe ends\n");
    pump(15000);
    ExitProcess(0);
}

DWORD WINAPI GuiStartup(void)
{
    WNDCLASSW wc = {0};
    HWND hwnd;
    IDirect3D9 *d3d;
    IDirect3DDevice9 *device = 0;
    D3DPRESENT_PARAMETERS pp;
    D3DADAPTER_IDENTIFIER9 id;
    D3DCAPS9 caps;
    HRESULT hr;
    static const Vertex triangle[3] = {
        {160.0f, 40.0f, 0.5f, 1.0f, 0xFFFF0000},
        {280.0f, 200.0f, 0.5f, 1.0f, 0xFFFF0000},
        {40.0f, 200.0f, 0.5f, 1.0f, 0xFFFF0000},
    };

    app_desktop();
    DbgPrint(TAG "the probe starts\n");
    wc.lpfnWndProc = proc;
    wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"MinoD3D";
    wc.hCursor = LoadCursorW(0, (LPCWSTR)IDC_ARROW);
    if (!RegisterClassW(&wc)) finish("FAIL RegisterClass");
    hwnd = CreateWindowExW(0, L"MinoD3D", L"Mino D3D9", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 336, 278, 0, 0,
                           wc.hInstance, 0);
    if (!hwnd) finish("FAIL CreateWindow");
    pump(500);

    /* The pixel formats the window's DC offers (opengl32's Mesa): wined3d
       keeps none that is PFD_GENERIC_FORMAT when it has no
       WGL_ARB_pixel_format. */
    {
        HDC dc = GetDC(hwnd);
        PIXELFORMATDESCRIPTOR pfd;
        int count = DescribePixelFormat(dc, 1, sizeof(pfd), &pfd), i, generic = 0;
        DbgPrint(TAG "DescribePixelFormat: %d formats\n", count);
        for (i = 1; i <= count; ++i) {
            if (!DescribePixelFormat(dc, i, sizeof(pfd), &pfd)) continue;
            if (pfd.dwFlags & PFD_GENERIC_FORMAT) ++generic;
            if (i <= 4)
                DbgPrint(TAG "format %d: flags %lx type %d color %d depth %d\n", i, pfd.dwFlags, pfd.iPixelType,
                         pfd.cColorBits, pfd.cDepthBits);
        }
        DbgPrint(TAG "generic formats: %d of %d\n", generic, count);

        /* What win32k says of pixel formats (gdi32's direct exports, which
           opengl32 calls after loading an ICD): the display driver describes
           none, so neither sets nor swaps. */
        {
            typedef INT(WINAPI * DescribeFn)(HDC, INT, UINT, PIXELFORMATDESCRIPTOR *);
            typedef BOOL(WINAPI * SetFn)(HDC, INT);
            typedef BOOL(WINAPI * SwapFn)(HDC);
            HMODULE gdi = GetModuleHandleW(L"gdi32.dll");
            DescribeFn describe = (DescribeFn)(void *)GetProcAddress(gdi, "GdiDescribePixelFormat");
            SetFn set = (SetFn)(void *)GetProcAddress(gdi, "GdiSetPixelFormat");
            SwapFn swap = (SwapFn)(void *)GetProcAddress(gdi, "GdiSwapBuffers");
            int described;
            BOOL done;
            SetLastError(0);
            described = describe(dc, 0, 0, 0);
            DbgPrint(TAG "GdiDescribePixelFormat: %d, error %lu\n", described, GetLastError());
            SetLastError(0);
            done = set(dc, 1);
            DbgPrint(TAG "GdiSetPixelFormat: %d, error %lu\n", done, GetLastError());
            SetLastError(0);
            done = swap(dc);
            DbgPrint(TAG "GdiSwapBuffers: %d, error %lu\n", done, GetLastError());
            {
                HDC memory = CreateCompatibleDC(dc);
                SetLastError(0);
                done = swap(memory);
                DbgPrint(TAG "GdiSwapBuffers of a memory DC: %d, error %lu\n", done, GetLastError());
                DeleteDC(memory);
            }
            SetLastError(0);
            described = describe((HDC)0x01010101, 0, 0, 0);
            DbgPrint(TAG "GdiDescribePixelFormat of no DC: %d, error %lu\n", described, GetLastError());
        }
        ReleaseDC(hwnd, dc);
    }

    d3d = Direct3DCreate9(D3D_SDK_VERSION);
    DbgPrint(TAG "Direct3DCreate9: %p\n", (void *)d3d);
    if (!d3d) finish("FAIL Direct3DCreate9");
    DbgPrint(TAG "adapters: %u\n", IDirect3D9_GetAdapterCount(d3d));
    memset(&id, 0, sizeof(id));
    hr = IDirect3D9_GetAdapterIdentifier(d3d, D3DADAPTER_DEFAULT, 0, &id);
    DbgPrint(TAG "GetAdapterIdentifier: %lx %s / %s\n", (DWORD)hr, id.Description, id.Driver);
    hr = IDirect3D9_GetDeviceCaps(d3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, &caps);
    DbgPrint(TAG "GetDeviceCaps(HAL): %lx, vertex shader %lx, pixel shader %lx\n", (DWORD)hr,
             (DWORD)caps.VertexShaderVersion, (DWORD)caps.PixelShaderVersion);

    memset(&pp, 0, sizeof(pp));
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_UNKNOWN;
    pp.hDeviceWindow = hwnd;
    hr = IDirect3D9_CreateDevice(d3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp,
                                 &device);
    DbgPrint(TAG "CreateDevice(HAL): %lx\n", (DWORD)hr);
    if (FAILED(hr) || !device) finish("FAIL CreateDevice");

    hr = IDirect3DDevice9_Clear(device, 0, 0, D3DCLEAR_TARGET, D3DCOLOR_XRGB(0, 0, 255), 1.0f, 0);
    DbgPrint(TAG "Clear: %lx\n", (DWORD)hr);
    hr = IDirect3DDevice9_BeginScene(device);
    DbgPrint(TAG "BeginScene: %lx\n", (DWORD)hr);
    hr = IDirect3DDevice9_SetFVF(device, D3DFVF_XYZRHW | D3DFVF_DIFFUSE);
    DbgPrint(TAG "SetFVF: %lx\n", (DWORD)hr);
    hr = IDirect3DDevice9_DrawPrimitiveUP(device, D3DPT_TRIANGLELIST, 1, triangle, sizeof(Vertex));
    DbgPrint(TAG "DrawPrimitiveUP: %lx\n", (DWORD)hr);
    hr = IDirect3DDevice9_EndScene(device);
    DbgPrint(TAG "EndScene: %lx\n", (DWORD)hr);
    hr = IDirect3DDevice9_Present(device, 0, 0, 0, 0);
    DbgPrint(TAG "Present: %lx\n", (DWORD)hr);
    if (FAILED(hr)) finish("FAIL Present");
    finish("PASS");
    return 0;
}
