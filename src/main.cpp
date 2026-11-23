// main.cpp — Win32 window + DirectX 11 + ImGui bootstrap for TPMViewer.
#include <windows.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <shellapi.h>

#include <d3d11.h>
#include <dxgi1_3.h>
#include <tchar.h>

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <vector>

#include "app.hpp"

#include <imgui.h>
#include <backends/imgui_impl_dx11.h>
#include <backends/imgui_impl_win32.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam,
                                                             LPARAM lParam);

namespace tcg {
extern ImFont* gMonoFont; // defined in app.cpp
}

static tcg::App* g_app = nullptr;
static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static UINT g_resizeWidth = 0, g_resizeHeight = 0;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static std::string ToUtf8(const std::wstring& w);

static const wchar_t* kWndClass = L"TPMViewerWndClass";

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    // Per-monitor DPI awareness MUST be set before the window is created.
    // If set afterwards, the window stays DPI-virtualized: GetCursorPos reports
    // physical pixels while GetClientRect reports logical ones, so on scaled
    // displays (125%/150%) ImGui hit-testing drifts below the real cursor after
    // a maximize and clicks select the wrong table row.
    if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
        using SetCtxFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto setCtx = reinterpret_cast<SetCtxFn>(GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (setCtx) setCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    // 图标来自 app.rc 资源 ID 1（assets 生成，见 src/app.ico）。
    WNDCLASSEXW wc = {sizeof(wc), CS_HREDRAW | CS_VREDRAW, WndProc, 0, 0, hInstance,
                      LoadIconW(hInstance, MAKEINTRESOURCEW(1)),      // 应用图标
                      LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)),  // IDC_ARROW
                      nullptr, nullptr, kWndClass,
                      LoadIconW(hInstance, MAKEINTRESOURCEW(1))};     // 标题栏小图标
    RegisterClassExW(&wc);

    // Size to ~82% of the primary monitor (mirrors the reference tool).
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    int w = int((work.right - work.left) * 0.82f);
    int h = int((work.bottom - work.top) * 0.84f);
    if (w < 1024) w = 1024;
    if (h < 640) h = 640;
    int x = work.left + ((work.right - work.left) - w) / 2;
    int y = work.top + ((work.bottom - work.top) - h) / 2;

    HWND hwnd = CreateWindowExW(0, kWndClass, L"TPMViewer - TPM Measured Boot Log",
                                WS_OVERLAPPEDWINDOW, x, y, w, h, nullptr, nullptr, hInstance,
                                nullptr);
    if (!hwnd) return 1;

    // Font scale from the monitor DPI (awareness is already active).
    float fontScale = 1.0f;
    if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
        using GetDpiFn = UINT(WINAPI*)(HWND);
        auto getDpi = reinterpret_cast<GetDpiFn>(GetProcAddress(user32, "GetDpiForWindow"));
        if (getDpi) fontScale = float(getDpi(hwnd)) / 96.0f;
        if (fontScale < 0.5f) fontScale = 1.0f;
    }

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    // Accept drag & drop of log files.
    DragAcceptFiles(hwnd, TRUE);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGui::GetStyle().WindowRounding = 0.0f;
    ImGui::GetStyle().FrameRounding = 3.0f;
    ImGui::GetStyle().GrabRounding = 3.0f;
    ImGui::GetStyle().ScrollbarRounding = 6.0f;
    ImGui::GetStyle().ChildRounding = 3.0f;
    ImGui::GetStyle().PopupRounding = 3.0f;

    // Fonts: CJK-capable UI font + Consolas (mono) with CJK glyphs merged in.
    {
        wchar_t win[MAX_PATH] = L"";
        GetWindowsDirectoryW(win, MAX_PATH);
        auto fontFile = [&](const wchar_t* name) {
            return ToUtf8(std::wstring(win) + L"\\Fonts\\" + name);
        };
        static const ImWchar ranges[] = {
            0x0020, 0x00FF, // Basic Latin + Latin-1
            0x2010, 0x2027, // dashes / bullets
            0x25A0, 0x25CF, // geometric shapes
            0x2713, 0x2718, // check / cross marks
            0x3000, 0x9FFF, // CJK
            0xFF00, 0xFFEF, // fullwidth punctuation
            0,
        };
        ImFontAtlas* fa = ImGui::GetIO().Fonts;
        // Read the CJK font once; the UI font and the mono merge share the same
        // data (FontDataOwnedByAtlas=false). It must outlive the first atlas build.
        static std::vector<uint8_t> cjkData;
        auto readFont = [](const std::string& p, std::vector<uint8_t>& out) {
            std::ifstream f(p.c_str(), std::ios::binary);
            if (!f) return false;
            f.seekg(0, std::ios::end);
            std::streamoff n = f.tellg();
            f.seekg(0);
            if (n <= 0) return false;
            out.resize(size_t(n));
            return bool(f.read(reinterpret_cast<char*>(out.data()), n));
        };
        // UI font: Segoe UI has no CJK glyphs, so prefer a Chinese font.
        const wchar_t* cjkFonts[] = {L"msyh.ttc", L"simhei.ttf", L"simsun.ttc", L"Deng.ttf"};
        for (const wchar_t* f : cjkFonts) {
            if (readFont(fontFile(f), cjkData)) break;
        }
        ImFontConfig cfg;
        cfg.OversampleH = 2;
        cfg.OversampleV = 1;
        ImFont* ui = nullptr;
        if (!cjkData.empty()) {
            cfg.FontDataOwnedByAtlas = false;
            ui = fa->AddFontFromMemoryTTF(cjkData.data(), int(cjkData.size()),
                                          17.0f * fontScale, &cfg, ranges);
        }
        if (!ui) {
            std::string p = fontFile(L"segoeui.ttf");
            fa->AddFontFromFileTTF(p.c_str(), 17.0f * fontScale, &cfg, ranges);
        }
        // Mono font for hex; merge CJK glyphs so Chinese text still renders.
        std::string cons = fontFile(L"consola.ttf");
        tcg::gMonoFont = fa->AddFontFromFileTTF(cons.c_str(), 16.0f * fontScale, nullptr,
                                                fa->GetGlyphRangesDefault());
        if (tcg::gMonoFont && !cjkData.empty()) {
            ImFontConfig merge;
            merge.MergeMode = true;
            merge.OversampleH = 2;
            merge.OversampleV = 1;
            merge.FontDataOwnedByAtlas = false;
            fa->AddFontFromMemoryTTF(cjkData.data(), int(cjkData.size()),
                                     16.0f * fontScale, &merge, ranges);
        }
    }

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    static tcg::App app;
    g_app = &app;

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;
        if (g_resizeWidth != 0 && g_resizeHeight != 0) {
            // Do NOT call ImGui_ImplDX11_InvalidateDeviceObjects() here: it would
            // delete the font texture and force a full CJK atlas rasterization on
            // every WM_SIZE during a drag. But the RTV referencing the back buffer
            // MUST be released, or ResizeBuffers fails with DXGI_ERROR_INVALID_CALL,
            // buffers keep their old size and DXGI stretches them over the new
            // window size -> rendered content no longer matches mouse coordinates
            // (highlight drifts below the cursor, worse toward the bottom).
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_resizeWidth, g_resizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_resizeWidth = g_resizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        g_app->Draw();

        ImGui::Render();
        const float clear[4] = {0.08f, 0.09f, 0.11f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // vsync
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    return 0;
}

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.OutputWindow = hWnd;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    sd.Flags = 0;

    UINT flags = D3D11_CREATE_DEVICE_DEBUG;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                                               nullptr, 0, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
                                               &g_pd3dDevice, nullptr, &g_pd3dDeviceContext);
    if (FAILED(hr)) {
        // Retry without the debug layer (not present on all systems).
        flags = 0;
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                                           nullptr, 0, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
                                           &g_pd3dDevice, nullptr, &g_pd3dDeviceContext);
    }
    if (FAILED(hr)) return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) {
        g_pSwapChain->Release();
        g_pSwapChain = nullptr;
    }
    if (g_pd3dDeviceContext) {
        g_pd3dDeviceContext->Release();
        g_pd3dDeviceContext = nullptr;
    }
    if (g_pd3dDevice) {
        g_pd3dDevice->Release();
        g_pd3dDevice = nullptr;
    }
}

static void CreateRenderTarget() {
    ID3D11Texture2D* backBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    if (backBuffer) {
        g_pd3dDevice->CreateRenderTargetView(backBuffer, nullptr, &g_mainRenderTargetView);
        backBuffer->Release();
    }
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

static void HandleDrop(HDROP drop) {
    wchar_t path[MAX_PATH] = L"";
    if (DragQueryFileW(drop, 0, path, MAX_PATH) > 0) {
        std::string err;
        if (!g_app->LoadFile(path, &err))
            MessageBoxW(nullptr, L"Could not load the dropped file.", L"TPMViewer", MB_ICONERROR);
    }
    DragFinish(drop);
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
        case WM_SIZE:
            if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
                g_resizeWidth = LOWORD(lParam);
                g_resizeHeight = HIWORD(lParam);
            }
            return 0;
        case WM_DROPFILES:
            HandleDrop(reinterpret_cast<HDROP>(wParam));
            return 0;
        case WM_DPICHANGED:
            // Maximize / move to another monitor: apply the suggested rect so the
            // client area matches the new DPI before the swap chain resizes.
            if (lParam) {
                const RECT* r = reinterpret_cast<const RECT*>(lParam);
                SetWindowPos(hWnd, nullptr, r->left, r->top, r->right - r->left,
                             r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0; // disable Alt menu
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}
