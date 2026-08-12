// vd-bitrate-autoset GUI v3
// - 自绘暗色现代 UI（无边框圆角窗口、自定义标题栏、悬停反馈按钮）
// - 三步差分定位 + 指针路径生成 + 常驻托盘
// - 监控按钮三态：待机 / 监控中 / 休眠；修改完成后自动休眠，
//   再次点击按钮才恢复监控 SteamVR。

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef _WIN32_IE
#define _WIN32_IE 0x0A00
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <uxtheme.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "scanner.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

constexpr DWORD kDefaultFrom = 500000000;
constexpr DWORD kDefaultTo   = 800000000;

// ---------- 主题色 ----------
constexpr COLORREF kBg          = RGB(20, 22, 26);
constexpr COLORREF kCard        = RGB(28, 31, 38);
constexpr COLORREF kCardBorder  = RGB(44, 49, 58);
constexpr COLORREF kInput       = RGB(35, 39, 47);
constexpr COLORREF kText        = RGB(230, 232, 236);
constexpr COLORREF kTextDim     = RGB(154, 160, 170);
constexpr COLORREF kAccent      = RGB(79, 124, 243);
constexpr COLORREF kAccentHover = RGB(106, 145, 245);
constexpr COLORREF kAccentDown  = RGB(64, 102, 205);
constexpr COLORREF kGreen       = RGB(60, 196, 124);
constexpr COLORREF kGreenDown   = RGB(46, 158, 98);
constexpr COLORREF kYellow      = RGB(245, 196, 83);
constexpr COLORREF kYellowDown  = RGB(198, 157, 63);
constexpr COLORREF kBtnBg       = RGB(38, 43, 52);
constexpr COLORREF kBtnHover    = RGB(47, 54, 66);
constexpr COLORREF kBtnDown     = RGB(30, 34, 42);
constexpr COLORREF kHoverCell   = RGB(40, 46, 56);
constexpr COLORREF kCloseHover  = RGB(214, 69, 69);

constexpr int kW = 880;
constexpr int kH = 630;
constexpr int kTitleH = 44;

// ---------- 控件 ID ----------
enum {
    IDC_EDIT_FROM = 1001,
    IDC_EDIT_TO,
    IDC_BTN_MONITOR,
    IDC_BTN_SAVE,
    IDC_BTN_PATCHALL,
    IDC_BTN_SCAN,
    IDC_BTN_CHANGED,
    IDC_BTN_RESTORED,
    IDC_BTN_FINDPTR,
    IDC_BTN_TEST,
    IDC_LV_ADDR,
    IDC_LV_PATH,
    IDC_LOG,
    IDC_CHK_NOSLEEP,
    IDC_CHK_POPUP,
};

constexpr UINT WM_TRAY   = WM_APP + 10;
constexpr UINT WM_LOGMSG = WM_APP + 1;
constexpr UINT WM_STATUS = WM_APP + 2;
constexpr UINT WM_SLEEP  = WM_APP + 3;
constexpr UINT WM_JOB    = WM_APP + 4;
constexpr UINT WM_SHOW   = WM_APP + 5;
constexpr UINT kTrayId   = 1;

// ---------- 状态机 ----------
enum class MonState { Standby, Armed, Sleeping };

struct AppState {
    HWND hwnd = nullptr;
    HINSTANCE hInst = nullptr;
    HFONT font = nullptr;
    HFONT titleFont = nullptr;
    HFONT statusFont = nullptr;
    HICON appIcon = nullptr;
    HBRUSH bgBrush = nullptr;
    HBRUSH cardBrush = nullptr;
    HBRUSH inputBrush = nullptr;
    HBRUSH accentBrush = nullptr;

    double scale = 1.0;   // DPI 缩放因子 (dpi/96)
    int ww = kW;          // 实际窗口宽(像素)
    int wh = kH;          // 实际窗口高(像素)

    bool hovMin = false;
    bool hovClose = false;
    bool mouseTracked = false;

    std::unique_ptr<VdScanner> scanner;
    std::vector<ScanMatch> s1, s2, s3;
    std::vector<PtrPath> paths;
    DWORD from = kDefaultFrom;
    DWORD to   = kDefaultTo;

    HANDLE monitorThread = nullptr;
    HANDLE stopEvent     = nullptr;
    MonState monState     = MonState::Standby;
    bool realExit         = false;
    bool jobBusy          = false;
    bool noSleepAfter     = true;   // 修改后自动休眠(关掉则继续监控, 有被EAC检测风险)
    bool popupAfter       = true;   // 修改后自动弹出主窗口
    HFONT smallFont       = nullptr;
};

AppState g;

// 按 DPI 缩放设计坐标
#define S(v) static_cast<int>((v) * g.scale)

const wchar_t* kVdStreamer     = L"virtualdesktop.streamer.exe";
const wchar_t* kSteamVRNames[] = { L"vrserver.exe", L"vrmonitor.exe" };
const wchar_t* kCfgFile        = L"vd-bitrate-autoset.cfg";

// ---------- 工具 ----------

DWORD FindPidByName(const wchar_t* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    DWORD pid = 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

bool IsSteamVrRunning()
{
    for (const wchar_t* n : kSteamVRNames)
        if (FindPidByName(n) != 0)
            return true;
    return false;
}

void Log(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    HWND log = GetDlgItem(g.hwnd, IDC_LOG);
    const int len = GetWindowTextLengthW(log);
    SendMessageW(log, EM_SETSEL, len, len);
    SendMessageW(log, EM_REPLACESEL, FALSE,
                 reinterpret_cast<LPARAM>(L"\r\n[VD] "));
    SendMessageW(log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(buf));
    SendMessageW(log, EM_SCROLLCARET, 0, 0);
}

void ThreadLog(HWND hwnd, const wchar_t* text)
{
    wchar_t* copy = _wcsdup(text);
    if (copy)
        PostMessageW(hwnd, WM_LOGMSG, 0, reinterpret_cast<LPARAM>(copy));
}

void InvalidatePill()
{
    RECT r{ S(14), S(52), S(kW - 14), S(104) };
    InvalidateRect(g.hwnd, &r, FALSE);
}

// ---------- 暗色模式 ----------

bool g_dark = false;

void InitDarkMode()
{
    HMODULE ux = LoadLibraryW(L"uxtheme.dll");
    if (!ux)
        return;
    using SetPref = int(WINAPI*)(int);
    using AllowApp = BOOL(WINAPI*)(BOOL);
    auto pref  = reinterpret_cast<SetPref>(GetProcAddress(ux, "SetPreferredAppMode"));
    auto allow = reinterpret_cast<AllowApp>(GetProcAddress(ux, "AllowDarkModeForApp"));
    if (pref) {
        pref(2);
        g_dark = true;
    } else if (allow) {
        allow(TRUE);
        g_dark = true;
    }
}

// ---------- 图标 ----------

HICON CreateAppIcon(const wchar_t* text)
{
    constexpr int size = 32;
    BITMAPINFO bi{};
    bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth       = size;
    bi.bmiHeader.biHeight      = -size;
    bi.bmiHeader.biPlanes      = 1;
    bi.bmiHeader.biBitCount    = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HDC dc = GetDC(nullptr);
    HBITMAP hbm = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    HDC mem = CreateCompatibleDC(dc);
    HGDIOBJ oldBmp = SelectObject(mem, hbm);

    HBRUSH bg = CreateSolidBrush(kAccent);
    RECT rc{ 0, 0, size, size };
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, RGB(255, 255, 255));
    HFONT f = CreateFontW(-size / 2, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                          DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
    HGDIOBJ oldFont = SelectObject(mem, f);
    DrawTextW(mem, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(mem, oldFont);
    DeleteObject(f);

    ICONINFO ii{};
    ii.fIcon    = TRUE;
    ii.hbmColor = hbm;
    ii.hbmMask  = CreateBitmap(size, size, 1, 1, nullptr);
    HICON icon  = CreateIconIndirect(&ii);

    DeleteObject(ii.hbmMask);
    SelectObject(mem, oldBmp);
    DeleteObject(hbm);
    DeleteDC(mem);
    ReleaseDC(nullptr, dc);
    return icon;
}

void AddTrayIcon()
{
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = g.hwnd;
    nid.uID    = kTrayId;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = g.appIcon;
    wcsncpy_s(nid.szTip, L"VD码率修改器 - 双击显示窗口", _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &nid);
}

void TrayBalloon(const wchar_t* info)
{
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = g.hwnd;
    nid.uID    = kTrayId;
    nid.uFlags = NIF_INFO;
    wcsncpy_s(nid.szInfoTitle, L"VD码率修改器", _TRUNCATE);
    wcsncpy_s(nid.szInfo, info, _TRUNCATE);
    nid.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// ---------- 自绘按钮 ----------

struct ButtonData {
    COLORREF bg, hover, down, text;
};

LRESULT CALLBACK ButtonSubclass(HWND h, UINT m, WPARAM w, LPARAM l,
                                UINT_PTR, DWORD_PTR ref)
{
    auto* bd = reinterpret_cast<ButtonData*>(ref);
    switch (m) {
        case WM_MOUSEMOVE: {
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            InvalidateRect(h, nullptr, FALSE);
            break;
        }
        case WM_MOUSELEAVE:
            InvalidateRect(h, nullptr, FALSE);
            break;
        case WM_NCDESTROY:
            delete bd;
            break;
    }
    return DefSubclassProc(h, m, w, l);
}

HWND MakeButton(HWND parent, int id, const wchar_t* text, int x, int y,
                int w, int h, COLORREF bg = kBtnBg, COLORREF hover = kBtnHover,
                COLORREF down = kBtnDown)
{
    HWND b = CreateWindowExW(0, L"BUTTON", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                 BS_OWNERDRAW,
                             x, y, w, h, parent,
                             reinterpret_cast<HMENU>(id), g.hInst, nullptr);
    auto* bd = new ButtonData{ bg, hover, down, kText };
    SetWindowSubclass(b, ButtonSubclass, 0,
                      reinterpret_cast<DWORD_PTR>(bd));
    SetWindowLongPtrW(b, GWLP_USERDATA,
                      reinterpret_cast<LONG_PTR>(bd));
    SendMessageW(b, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
    return b;
}

void FillRoundRect(HDC dc, int l, int t, int r, int b, COLORREF color,
                   int radius = 8);

LRESULT CALLBACK CheckboxSubclass(HWND h, UINT m, WPARAM w, LPARAM l,
                                  UINT_PTR, DWORD_PTR)
{
    switch (m) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(h, &ps);
            RECT rc{};
            GetClientRect(h, &rc);
            FillRect(dc, &rc, g.bgBrush);
            const bool checked =
                SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED;
            POINT pt{};
            GetCursorPos(&pt);
            ScreenToClient(h, &pt);
            const bool hover = PtInRect(&rc, pt);
            const int box = S(14);
            const int by  = rc.top + (rc.bottom - rc.top - box) / 2;
            RECT bx{ S(4), by, S(4) + box, by + box };
            FillRoundRect(dc, bx.left, bx.top, bx.right, bx.bottom,
                          checked ? kAccent : (hover ? kBtnHover : kInput),
                          S(3));
            HPEN pen = CreatePen(PS_SOLID, 1, checked ? kAccent : kCardBorder);
            HGDIOBJ old = SelectObject(dc, pen);
            SelectObject(dc, GetStockObject(NULL_BRUSH));
            RoundRect(dc, bx.left, bx.top, bx.right, bx.bottom, S(3) * 2,
                      S(3) * 2);
            SelectObject(dc, old);
            DeleteObject(pen);
            if (checked) {
                SetTextColor(dc, RGB(255, 255, 255));
                SelectObject(dc, g.font);
                DrawTextW(dc, L"✓", -1, &bx,
                          DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            }
            wchar_t text[128];
            GetWindowTextW(h, text, _countof(text));
            RECT tr{ bx.right + S(8), rc.top, rc.right, rc.bottom };
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, hover ? kAccentHover : kText);
            SelectObject(dc, g.font);
            DrawTextW(dc, text, -1, &tr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            EndPaint(h, &ps);
            return 0;
        }
        case WM_MOUSEMOVE: {
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            InvalidateRect(h, nullptr, FALSE);
            break;
        }
        case WM_MOUSELEAVE:
            InvalidateRect(h, nullptr, FALSE);
            break;
    }
    return DefSubclassProc(h, m, w, l);
}

HWND MakeCheckbox(HWND parent, int id, const wchar_t* text, int x, int y,
                  int w, int h)
{
    HWND b = CreateWindowExW(0, L"BUTTON", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                 BS_AUTOCHECKBOX,
                             x, y, w, h, parent,
                             reinterpret_cast<HMENU>(id), g.hInst, nullptr);
    SetWindowSubclass(b, CheckboxSubclass, 0, 0);
    SendMessageW(b, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
    return b;
}

void FillRoundRect(HDC dc, int l, int t, int r, int b, COLORREF color,
                   int radius)
{
    HBRUSH br = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ oBr = SelectObject(dc, br);
    HGDIOBJ oPn = SelectObject(dc, pen);
    RoundRect(dc, l, t, r, b, radius * 2, radius * 2);
    SelectObject(dc, oBr);
    SelectObject(dc, oPn);
    DeleteObject(pen);
    DeleteObject(br);
}

// ---------- 自绘输入框 ----------

struct EditData {
    bool focused = false;
};

LRESULT CALLBACK EditSubclass(HWND h, UINT m, WPARAM w, LPARAM l,
                              UINT_PTR, DWORD_PTR ref)
{
    auto* ed = reinterpret_cast<EditData*>(ref);
    switch (m) {
        case WM_SETFOCUS:
            ed->focused = true;
            InvalidateRect(h, nullptr, FALSE);
            break;
        case WM_KILLFOCUS:
            ed->focused = false;
            InvalidateRect(h, nullptr, FALSE);
            break;
        case WM_PAINT: {
            LRESULT r = DefSubclassProc(h, WM_PAINT, w, l);
            HDC dc = GetDC(h);
            RECT rc;
            GetClientRect(h, &rc);
            HPEN pen = CreatePen(PS_SOLID, 1,
                                 ed->focused ? kAccent : kCardBorder);
            HGDIOBJ old = SelectObject(dc, pen);
            SelectObject(dc, GetStockObject(NULL_BRUSH));
            Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
            SelectObject(dc, old);
            DeleteObject(pen);
            ReleaseDC(h, dc);
            return r;
        }
        case WM_NCDESTROY:
            delete ed;
            break;
    }
    return DefSubclassProc(h, m, w, l);
}

HWND MakeEdit(HWND parent, int id, int x, int y, int w, int h,
              const wchar_t* text)
{
    HWND e = CreateWindowExW(0, L"EDIT", text,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                 ES_AUTOHSCROLL,
                             x, y, w, h, parent,
                             reinterpret_cast<HMENU>(id), g.hInst, nullptr);
    SetWindowSubclass(e, EditSubclass, 0,
                      reinterpret_cast<DWORD_PTR>(new EditData));
    SendMessageW(e, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
    return e;
}

std::wstring GetEditText(int id)
{
    HWND e = GetDlgItem(g.hwnd, id);
    const int len = GetWindowTextLengthW(e);
    std::wstring s(len, L'\0');
    if (len > 0)
        GetWindowTextW(e, &s[0], len + 1);
    return s;
}

void SetEditText(int id, const std::wstring& s)
{
    SetWindowTextW(GetDlgItem(g.hwnd, id), s.c_str());
}

HWND MakeCaption(HWND parent, const wchar_t* text, int x, int y, int w, int h)
{
    HWND c = CreateWindowExW(0, L"STATIC", text,
                             WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
                             x, y, w, h, parent, nullptr, g.hInst, nullptr);
    SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
    return c;
}

LRESULT CALLBACK HeaderSubclass(HWND h, UINT m, WPARAM w, LPARAM l,
                                UINT_PTR, DWORD_PTR)
{
    if (m == WM_PAINT) {
        LRESULT r = DefSubclassProc(h, m, w, l);
        HDC dc = GetDC(h);
        RECT rc;
        GetClientRect(h, &rc);
        HBRUSH b = CreateSolidBrush(kCard);
        FillRect(dc, &rc, b);
        DeleteObject(b);
        const int n = Header_GetItemCount(h);
        for (int i = 0; i < n; i++) {
            RECT ir;
            Header_GetItemRect(h, i, &ir);
            wchar_t buf[128];
            HDITEM hi{};
            hi.mask        = HDI_TEXT;
            hi.pszText     = buf;
            hi.cchTextMax  = _countof(buf);
            if (Header_GetItem(h, i, &hi)) {
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, kTextDim);
                SelectObject(dc, g.font);
                RECT tr = ir;
                tr.left += S(8);
                DrawTextW(dc, hi.pszText, -1, &tr,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            }
        }
        ReleaseDC(h, dc);
        return r;
    }
    return DefSubclassProc(h, m, w, l);
}

HWND MakeList(HWND parent, int id, int x, int y, int w, int h)
{
    HWND lv = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT |
                                  LVS_SINGLESEL,
                              x, y, w, h, parent,
                              reinterpret_cast<HMENU>(id), g.hInst, nullptr);
    ListView_SetExtendedListViewStyle(lv,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                          LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(lv, kCard);
    ListView_SetTextColor(lv, kText);
    ListView_SetTextBkColor(lv, kCard);
    SetWindowSubclass(ListView_GetHeader(lv), HeaderSubclass, 0, 0);
    return lv;
}

void AddColumn(HWND lv, int idx, const wchar_t* title, int width)
{
    LVCOLUMNW c{};
    c.mask    = LVCF_TEXT | LVCF_WIDTH;
    c.pszText = const_cast<LPWSTR>(title);
    c.cx      = width;
    ListView_InsertColumn(lv, idx, &c);
}

void AddRow(HWND lv, const std::wstring& col0, const std::wstring& col1)
{
    const int idx = ListView_GetItemCount(lv);
    LVITEMW it{};
    it.mask    = LVIF_TEXT;
    it.iItem   = idx;
    it.pszText = const_cast<LPWSTR>(col0.c_str());
    ListView_InsertItem(lv, &it);
    if (!col1.empty())
        ListView_SetItemText(lv, idx, 1, const_cast<LPWSTR>(col1.c_str()));
}

std::wstring HexAddr(uintptr_t a)
{
    wchar_t buf[32];
    swprintf_s(buf, _countof(buf), L"0x%llX",
               static_cast<unsigned long long>(a));
    return buf;
}

// ---------- 监控状态按钮 ----------

void UpdateMonitorButton()
{
    HWND btn = GetDlgItem(g.hwnd, IDC_BTN_MONITOR);
    if (!btn)
        return;
    auto* bd = reinterpret_cast<ButtonData*>(
        GetWindowLongPtrW(btn, GWLP_USERDATA));
    if (!bd)
        return;
    switch (g.monState) {
        case MonState::Standby:
            SetWindowTextW(btn, L"▶ 开始监控");
            bd->bg = kAccent; bd->hover = kAccentHover; bd->down = kAccentDown;
            bd->text = RGB(255, 255, 255);
            break;
        case MonState::Armed:
            SetWindowTextW(btn, L"● 监控中 · 点击停止");
            bd->bg = kGreen; bd->hover = kGreen; bd->down = kGreenDown;
            bd->text = RGB(20, 28, 22);
            break;
        case MonState::Sleeping:
            SetWindowTextW(btn, L"◐ 休眠中 · 点击唤醒");
            bd->bg = kYellow; bd->hover = kYellow; bd->down = kYellowDown;
            bd->text = RGB(30, 26, 12);
            break;
    }
    InvalidateRect(btn, nullptr, TRUE);
}

COLORREF PillColor()
{
    switch (g.monState) {
        case MonState::Armed:    return kGreen;
        case MonState::Sleeping: return kYellow;
        default:                 return kTextDim;
    }
}

const wchar_t* PillText()
{
    switch (g.monState) {
        case MonState::Armed:    return L"监控中 · 等待 SteamVR 启动...";
        case MonState::Sleeping: return L"休眠中 · 点击「开始监控」后继续监听 SteamVR";
        default:                 return L"待机 · 完成 ④ 生成指针路径后点击「开始监控」";
    }
}

// ---------- 差分三步 ----------

// ---------- 后台任务 ----------
// 扫描类操作(①~④/全量)都较慢，统一放到工作线程执行，避免 UI 假死白屏。
// 结果通过 WM_JOB 投递回 UI 线程统一应用；任务期间禁用相关按钮。

enum JobKind { JOB_SCAN = 1, JOB_CHANGED, JOB_RESTORED, JOB_FINDPTR, JOB_PATCHALL };

struct ScanJob {
    int kind = 0;
    DWORD from = 0, to = 0;
    std::vector<ScanMatch> inMatches;
    std::vector<ScanMatch> outMatches;
    std::vector<PtrPath> outPaths;
    std::wstring outErr;
    int patched = 0;
    std::unique_ptr<VdScanner> scanner;
};

DWORD WINAPI JobProc(LPVOID lp);

void SetJobUi(bool enabled)
{
    for (int id : { IDC_BTN_SCAN, IDC_BTN_CHANGED, IDC_BTN_RESTORED,
                    IDC_BTN_FINDPTR, IDC_BTN_TEST, IDC_BTN_PATCHALL,
                    IDC_BTN_SAVE })
        EnableWindow(GetDlgItem(g.hwnd, id), enabled);
}

void RunJob(int kind, std::vector<ScanMatch> in = {})
{
    if (g.jobBusy)
        return;
    g.jobBusy = true;
    SetJobUi(false);

    auto* job = new ScanJob;
    job->kind = kind;
    job->from = static_cast<DWORD>(
        wcstoull(GetEditText(IDC_EDIT_FROM).c_str(), nullptr, 10));
    job->to = static_cast<DWORD>(
        wcstoull(GetEditText(IDC_EDIT_TO).c_str(), nullptr, 10));
    job->inMatches = std::move(in);
    if (g.scanner)
        job->scanner = std::move(g.scanner);

    HANDLE t = CreateThread(nullptr, 0, JobProc, job, 0, nullptr);
    if (!t) {
        g.jobBusy = false;
        SetJobUi(true);
        delete job;
    }
}

void PtrScanProgressCb(void* ctx, int depth, size_t candidates, DWORD elapsedMs)
{
    wchar_t buf[256];
    swprintf_s(buf, _countof(buf),
               L"  第 %d 层: %zu 个候选指针, 已用时 %lu 秒...",
               depth, candidates, elapsedMs / 1000);
    ThreadLog(reinterpret_cast<HWND>(ctx), buf);
}

DWORD WINAPI JobProc(LPVOID lp)
{
    auto* job = static_cast<ScanJob*>(lp);
    switch (job->kind) {
        case JOB_SCAN: {
            const DWORD pid = FindPidByName(kVdStreamer);
            if (pid == 0) {
                job->outErr =
                    L"未找到 virtualdesktop.streamer.exe，请先启动 Virtual Desktop Streamer。";
                break;
            }
            auto sc = std::make_unique<VdScanner>(pid);
            if (!sc->Attach()) {
                job->outErr = L"无法打开进程句柄（可能权限不足）。";
                break;
            }
            job->scanner = std::move(sc);
            ThreadLog(g.hwnd, L"已附加 virtualdesktop.streamer.exe，正在全内存扫描...");
            job->outMatches = job->scanner->ScanValue(job->from);
            break;
        }
        case JOB_CHANGED:
            for (const ScanMatch& m : job->inMatches) {
                uint32_t v = 0;
                if (job->scanner->Read32(m.addr, &v) && v != job->from)
                    job->outMatches.push_back({ m.addr, v });
            }
            break;
        case JOB_RESTORED:
            for (const ScanMatch& m : job->inMatches) {
                uint32_t v = 0;
                if (job->scanner->Read32(m.addr, &v) && v == job->from)
                    job->outMatches.push_back({ m.addr, v });
            }
            break;
        case JOB_FINDPTR: {
            const size_t maxLeaves = (std::min)(job->inMatches.size(), size_t(8));
            for (size_t i = 0; i < maxLeaves; ++i) {
                wchar_t buf[256];
                swprintf_s(buf, _countof(buf),
                           L"  叶地址 %s: 反向扫描指针链(最多4层,每叶限时180秒)...",
                           HexAddr(job->inMatches[i].addr).c_str());
                ThreadLog(g.hwnd, buf);
                const DWORD t0 = GetTickCount();
                const std::vector<PtrPath> found =
                    job->scanner->FindPointerPaths(job->inMatches[i].addr, 4,
                                                   8, 180000,
                                                   PtrScanProgressCb,
                                                   g.hwnd);
                const DWORD secs = (GetTickCount() - t0) / 1000;
                swprintf_s(buf, _countof(buf),
                           L"  叶地址 %s: 用时 %lu 秒, 找到 %zu 条候选路径",
                           HexAddr(job->inMatches[i].addr).c_str(), secs,
                           found.size());
                ThreadLog(g.hwnd, buf);
                for (const PtrPath& p : found)
                    job->outPaths.push_back(p);
            }
            std::sort(job->outPaths.begin(), job->outPaths.end(),
                      [](const PtrPath& a, const PtrPath& b) {
                          return a.ToString() < b.ToString();
                      });
            job->outPaths.erase(
                std::unique(job->outPaths.begin(), job->outPaths.end(),
                            [](const PtrPath& a, const PtrPath& b) {
                                return a.ToString() == b.ToString();
                            }),
                job->outPaths.end());
            break;
        }
        case JOB_PATCHALL: {
            if (!job->scanner) {
                const DWORD pid = FindPidByName(kVdStreamer);
                if (pid == 0) {
                    job->outErr = L"未找到 virtualdesktop.streamer.exe。";
                    break;
                }
                auto sc = std::make_unique<VdScanner>(pid);
                if (!sc->Attach()) {
                    job->outErr = L"无法打开进程句柄。";
                    break;
                }
                job->scanner = std::move(sc);
            }
            for (const ScanMatch& m : job->scanner->ScanValue(job->from))
                if (job->scanner->Write32(m.addr, job->to))
                    ++job->patched;
            break;
        }
    }
    PostMessageW(g.hwnd, WM_JOB, 0, reinterpret_cast<LPARAM>(job));
    return 0;
}

void DoScan()
{
    RunJob(JOB_SCAN);
}

void DoChanged()
{
    if (!g.scanner || g.s1.empty()) {
        MessageBoxW(g.hwnd, L"请先执行 ① 扫描。", L"提示", MB_ICONINFORMATION);
        return;
    }
    RunJob(JOB_CHANGED, g.s1);
}

void DoRestored()
{
    if (!g.scanner || g.s2.empty()) {
        MessageBoxW(g.hwnd, L"请先执行 ②。", L"提示", MB_ICONINFORMATION);
        return;
    }
    RunJob(JOB_RESTORED, g.s2);
}

void DoFindPtr()
{
    if (g.s3.empty()) {
        MessageBoxW(g.hwnd, L"请先完成三步差分定位(①→②→③)。",
                    L"提示", MB_ICONINFORMATION);
        return;
    }
    RunJob(JOB_FINDPTR, g.s3);
}

void DoTestPtr()
{
    if (g.paths.empty()) {
        MessageBoxW(g.hwnd, L"请先执行 ④ 查找指针路径。", L"提示",
                    MB_ICONINFORMATION);
        return;
    }
    HWND lv = GetDlgItem(g.hwnd, IDC_LV_PATH);
    const int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (sel < 0 || static_cast<size_t>(sel) >= g.paths.size()) {
        MessageBoxW(g.hwnd, L"请先在列表中选中一条路径。", L"提示",
                    MB_ICONINFORMATION);
        return;
    }
    if (!g.scanner) {
        const DWORD pid = FindPidByName(kVdStreamer);
        if (pid == 0) {
            MessageBoxW(g.hwnd, L"未找到 virtualdesktop.streamer.exe，"
                                L"请先启动 Virtual Desktop 串流。",
                        L"提示", MB_ICONINFORMATION);
            return;
        }
        auto sc = std::make_unique<VdScanner>(pid);
        if (!sc->Attach()) {
            MessageBoxW(g.hwnd, L"无法打开进程句柄。", L"错误", MB_ICONERROR);
            return;
        }
        g.scanner = std::move(sc);
    }
    const PtrPath& p = g.paths[static_cast<size_t>(sel)];
    uintptr_t addr = 0;
    if (!g.scanner->Resolve(p, &addr)) {
        MessageBoxW(g.hwnd, L"解析失败，可能模块基址已变。", L"错误",
                    MB_ICONERROR);
        return;
    }
    uint32_t v = 0;
    g.scanner->Read32(addr, &v);
    wchar_t msg[512];
    swprintf_s(msg, _countof(msg),
               L"路径: %s\n解析地址: %s\n当前数值: %lu\n\n"
               L"如果当前数值 = VD 界面显示的码率，则该路径正确。",
               p.ToString().c_str(), HexAddr(addr).c_str(), v);
    MessageBoxW(g.hwnd, msg, L"路径测试", MB_OK | MB_ICONINFORMATION);
}

// ---------- 配置 ----------

std::wstring CfgPath()
{
    wchar_t dir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash)
        *slash = L'\0';
    return std::wstring(dir) + L"\\" + kCfgFile;
}

void SaveConfig()
{
    std::wofstream f(CfgPath(), std::ios::out);
    f << L"from=" << g.from << L"\n";
    f << L"to=" << g.to << L"\n";
    f << L"nosleep=" << (g.noSleepAfter ? 1 : 0) << L"\n";
    f << L"popup_after=" << (g.popupAfter ? 1 : 0) << L"\n";
    for (const PtrPath& p : g.paths)
        f << L"path=" << p.ToString() << L"\n";
}

void LoadConfig()
{
    std::wifstream f(CfgPath());
    if (f) {
        std::wstring line;
        while (std::getline(f, line)) {
        if (line.rfind(L"from=", 0) == 0)
            g.from = static_cast<DWORD>(wcstoull(line.c_str() + 5, nullptr, 10));
        else if (line.rfind(L"to=", 0) == 0)
            g.to = static_cast<DWORD>(wcstoull(line.c_str() + 3, nullptr, 10));
        else if (line.rfind(L"nosleep=", 0) == 0)
            g.noSleepAfter = _wtoi(line.c_str() + 8) != 0;
        else if (line.rfind(L"popup_after=", 0) == 0)
            g.popupAfter = _wtoi(line.c_str() + 12) != 0;
        else if (line.rfind(L"path=", 0) == 0) {
            PtrPath p;
            if (PtrPath::Parse(line.substr(5), p))
                g.paths.push_back(p);
        }
    }
    }
    SetEditText(IDC_EDIT_FROM, std::to_wstring(g.from));
    SetEditText(IDC_EDIT_TO, std::to_wstring(g.to));
    SendMessageW(GetDlgItem(g.hwnd, IDC_CHK_NOSLEEP), BM_SETCHECK,
                 g.noSleepAfter ? BST_CHECKED : BST_UNCHECKED, 0);
    InvalidateRect(GetDlgItem(g.hwnd, IDC_CHK_NOSLEEP), nullptr, TRUE);
    SendMessageW(GetDlgItem(g.hwnd, IDC_CHK_POPUP), BM_SETCHECK,
                 g.popupAfter ? BST_CHECKED : BST_UNCHECKED, 0);
    InvalidateRect(GetDlgItem(g.hwnd, IDC_CHK_POPUP), nullptr, TRUE);
    HWND lv = GetDlgItem(g.hwnd, IDC_LV_PATH);
    for (const PtrPath& p : g.paths)
        AddRow(lv, p.ToString(), L"");
}

// ---------- 自动监视 ----------

struct MonitorCtx {
    DWORD from, to;
    HWND hwnd;
    HANDLE stop;
    std::vector<PtrPath> paths;
    bool noSleep = false;
    bool popup   = false;
};

DWORD WINAPI MonitorProc(LPVOID lp)
{
    auto* ctx = static_cast<MonitorCtx*>(lp);
    bool patched = false;
    while (WaitForSingleObject(ctx->stop, 2000) == WAIT_TIMEOUT) {
        const bool vr = IsSteamVrRunning();
        if (vr && !patched) {
            const DWORD pid = FindPidByName(kVdStreamer);
            if (pid) {
                VdScanner sc(pid);
                if (sc.Attach()) {
                    int done = 0;
                    for (const PtrPath& p : ctx->paths) {
                        uintptr_t addr = 0;
                        if (!sc.Resolve(p, &addr))
                            continue;
                        uint32_t v = 0;
                        if (sc.Read32(addr, &v) && v == ctx->from) {
                            if (sc.Write32(addr, ctx->to))
                                ++done;
                        }
                    }
                    wchar_t msg[256];
                    swprintf_s(msg, _countof(msg),
                               L"SteamVR 启动，已修改 %d 处码率 %lu -> %lu",
                               done, ctx->from, ctx->to);
                    ThreadLog(ctx->hwnd, msg);
                    if (ctx->popup)
                        PostMessageW(ctx->hwnd, WM_SHOW, 0, 0);
                    if (ctx->noSleep) {
                        ThreadLog(ctx->hwnd, L"[监控] 已开启「修改后不休眠」: "
                                    L"继续监听, 下次 SteamVR 启动会再次修改");
                    } else {
                        // 修改完成 → 自动休眠
                        wchar_t* sleepMsg = _wcsdup(msg);
                        if (sleepMsg)
                            PostMessageW(ctx->hwnd, WM_SLEEP, 0,
                                         reinterpret_cast<LPARAM>(sleepMsg));
                    }
                }
            }
            patched = true;
        } else if (!vr) {
            patched = false;
        }
    }
    delete ctx;
    return 0;
}

void StopMonitor()
{
    if (!g.monitorThread)
        return;
    SetEvent(g.stopEvent);
    WaitForSingleObject(g.monitorThread, 5000);
    CloseHandle(g.monitorThread);
    g.monitorThread = nullptr;
    CloseHandle(g.stopEvent);
    g.stopEvent = nullptr;
}

void ArmMonitor()
{
    if (g.monitorThread)
        return;
    if (g.paths.empty()) {
        MessageBoxW(g.hwnd,
                    L"当前没有已保存的指针路径，请先完成 ④ 查找指针路径。",
                    L"提示", MB_ICONINFORMATION);
        return;
    }
    g.from = static_cast<DWORD>(
        wcstoull(GetEditText(IDC_EDIT_FROM).c_str(), nullptr, 10));
    g.to = static_cast<DWORD>(
        wcstoull(GetEditText(IDC_EDIT_TO).c_str(), nullptr, 10));

    auto* ctx = new MonitorCtx{ g.from, g.to, g.hwnd, nullptr, g.paths,
                                g.noSleepAfter, g.popupAfter };
    g.stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ctx->stop = g.stopEvent;
    g.monitorThread = CreateThread(nullptr, 0, MonitorProc, ctx, 0, nullptr);
    g.monState = MonState::Armed;
    UpdateMonitorButton();
    InvalidatePill();
    SaveConfig();
    Log(L"[监控] 已开始: SteamVR 启动时自动把 %lu -> %lu，%s",
        g.from, g.to,
        g.noSleepAfter ? L"修改完成后自动休眠" : L"修改后不休眠(继续监控)");
}

void ToggleMonitor()
{
    if (g.monitorThread) {
        StopMonitor();
        g.monState = MonState::Standby;
        UpdateMonitorButton();
        InvalidatePill();
        Log(L"[监控] 已停止");
    } else {
        ArmMonitor();
    }
}

void OnAutoSleep(HWND hwnd, wchar_t* text)
{
    if (text) {
        Log(L"%s", text);
        TrayBalloon(text);
        free(text);
    }
    StopMonitor();
    g.monState = MonState::Sleeping;
    UpdateMonitorButton();
    InvalidatePill();
    Log(L"[监控] 修改完成，已自动休眠。需要再次监控时点击「开始监控」按钮");
}

void DoPatchAll()
{
    RunJob(JOB_PATCHALL);
}

// ---------- 窗口绘制 ----------

void DrawTitleBar(HDC dc)
{
    SetBkMode(dc, TRANSPARENT);

    DrawIconEx(dc, S(16), S(12), g.appIcon, S(20), S(20), 0, nullptr,
               DI_NORMAL);
    SelectObject(dc, g.titleFont);
    SetTextColor(dc, kText);
    RECT rt{ S(44), 0, S(kW - 96), S(kTitleH) };
    DrawTextW(dc, L"VD码率修改器", -1, &rt,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    // 最小化按钮
    RECT mr{ S(kW - 92), 0, S(kW - 52), S(kTitleH) };
    if (g.hovMin)
        FillRoundRect(dc, mr.left, mr.top, mr.right, mr.bottom, kHoverCell);
    SetTextColor(dc, kTextDim);
    SelectObject(dc, g.font);
    RECT mt{ mr.left, mr.top, mr.right, mr.bottom };
    DrawTextW(dc, L"—", -1, &mt,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    // 关闭按钮
    RECT cr{ S(kW - 46), 0, S(kW - 6), S(kTitleH) };
    if (g.hovClose)
        FillRoundRect(dc, cr.left, cr.top, cr.right, cr.bottom, kCloseHover);
    SetTextColor(dc, g.hovClose ? RGB(255, 255, 255) : kTextDim);
    DrawTextW(dc, L"✕", -1, &cr,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}

void DrawStatusPill(HDC dc)
{
    const RECT pill{ S(14), S(52), S(kW - 14), S(104) };
    FillRoundRect(dc, pill.left, pill.top, pill.right, pill.bottom, kCard);

    HPEN pen = CreatePen(PS_SOLID, 1, kCardBorder);
    HGDIOBJ old = SelectObject(dc, pen);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, pill.left, pill.top, pill.right, pill.bottom, S(12), S(12));
    SelectObject(dc, old);
    DeleteObject(pen);

    // 状态圆点
    HBRUSH dot = CreateSolidBrush(PillColor());
    HGDIOBJ oBr = SelectObject(dc, dot);
    Ellipse(dc, S(30), S(70), S(42), S(82));
    SelectObject(dc, oBr);
    DeleteObject(dot);

    // 状态文字
    SelectObject(dc, g.statusFont);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, PillColor());
    RECT tr{ S(52), S(62), S(400), S(94) };
    DrawTextW(dc, PillText(), -1, &tr,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
}

// ---------- 界面构建 ----------

void BuildUi()
{
    HWND h = g.hwnd;

    // 状态胶囊右侧的数值输入
    MakeCaption(h, L"from(bit)", S(412), S(69), S(76), S(20));
    MakeEdit(h, IDC_EDIT_FROM, S(492), S(65), S(120), S(26), L"500000000");
    MakeCaption(h, L"to(bit)", S(624), S(69), S(56), S(20));
    MakeEdit(h, IDC_EDIT_TO, S(680), S(65), S(120), S(26), L"800000000");

    // 主操作
    MakeButton(h, IDC_BTN_MONITOR, L"▶ 开始监控", S(14), S(114), S(176), S(38),
               kAccent, kAccentHover, kAccentDown);
    MakeButton(h, IDC_BTN_SAVE, L"保存路径", S(198), S(114), S(110), S(38));
    MakeButton(h, IDC_BTN_PATCHALL, L"全量修改", S(316), S(114), S(130), S(38));

    // 修改后行为开关
    MakeCheckbox(h, IDC_CHK_POPUP, L"修改后弹出窗口", S(460), S(116), S(135),
                 S(34));
    MakeCheckbox(h, IDC_CHK_NOSLEEP, L"修改后自动休眠", S(605), S(116), S(135),
                 S(34));
    HWND warn = MakeCaption(h, L"⚠ 可能被小蓝熊检测", S(750), S(121), S(130),
                            S(22));
    SendMessageW(warn, WM_SETFONT, reinterpret_cast<WPARAM>(g.smallFont), TRUE);

    // 差分定位 + 指针
    MakeButton(h, IDC_BTN_SCAN, L"① 扫描码率", S(14), S(162), S(120), S(32));
    MakeButton(h, IDC_BTN_CHANGED, L"② 已改码率", S(142), S(162), S(120), S(32));
    MakeButton(h, IDC_BTN_RESTORED, L"③ 已改回", S(270), S(162), S(120), S(32));
    MakeButton(h, IDC_BTN_FINDPTR, L"④ 查找指针", S(398), S(162), S(120), S(32));
    MakeButton(h, IDC_BTN_TEST, L"⑤ 测试路径", S(526), S(162), S(120), S(32));

    // 列表
    MakeCaption(h, L"①-③ 差分定位结果", S(14), S(202), S(200), S(18));
    HWND lvAddr = MakeList(h, IDC_LV_ADDR, S(14), S(220), S(420), S(186));
    AddColumn(lvAddr, 0, L"地址", S(190));
    AddColumn(lvAddr, 1, L"数值", S(100));
    MakeCaption(h, L"④ 指针路径候选", S(444), S(202), S(220), S(18));
    HWND lvPath = MakeList(h, IDC_LV_PATH, S(444), S(220), S(422), S(186));
    AddColumn(lvPath, 0, L"指针路径", S(300));
    AddColumn(lvPath, 1, L"当前值", S(100));

    // 日志
    MakeCaption(h, L"日志", S(14), S(414), S(80), S(18));
    HWND log = CreateWindowExW(0, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE |
                                   ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                               S(14), S(432), S(kW - 28), S(168), h,
                               reinterpret_cast<HMENU>(IDC_LOG), g.hInst,
                               nullptr);
    SetWindowSubclass(log, EditSubclass, 0,
                      reinterpret_cast<DWORD_PTR>(new EditData));
    SendMessageW(log, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
}

LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg) {
        case WM_CREATE: {
            g.hwnd = h;
            g.scale = static_cast<double>(GetDpiForWindow(h)) / 96.0;
            if (g.scale <= 0)
                g.scale = 1.0;
            g.ww = S(kW);
            g.wh = S(kH);
            g.font = CreateFontW(S(-15), 0, 0, 0, FW_NORMAL, FALSE, FALSE,
                                 FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                 CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                 DEFAULT_PITCH, L"Microsoft YaHei UI");
            g.titleFont = CreateFontW(S(-19), 0, 0, 0, FW_BOLD, FALSE, FALSE,
                                      FALSE, DEFAULT_CHARSET,
                                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                      DEFAULT_QUALITY, DEFAULT_PITCH,
                                      L"Microsoft YaHei UI");
            g.statusFont = CreateFontW(S(-17), 0, 0, 0, FW_SEMIBOLD, FALSE,
                                       FALSE, FALSE, DEFAULT_CHARSET,
                                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                       DEFAULT_QUALITY, DEFAULT_PITCH,
                                       L"Microsoft YaHei UI");
            g.smallFont = CreateFontW(S(-12), 0, 0, 0, FW_NORMAL, FALSE, FALSE,
                                      FALSE, DEFAULT_CHARSET,
                                      OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                      DEFAULT_QUALITY, DEFAULT_PITCH,
                                      L"Microsoft YaHei UI");
            BuildUi();
            UpdateMonitorButton();
            AddTrayIcon();
            LoadConfig();
            UpdateMonitorButton();
            Log(L"欢迎使用 VD码率修改器");
            Log(L"流程: ① 扫描 → 改滑块后② → 改回后③ → ④ 生成指针 → 开始监控");
            Log(L"监控时每次 SteamVR 启动自动改码率，改完自动休眠；关闭窗口=隐藏到托盘");
            if (!g.paths.empty()) {
                ArmMonitor();
                Log(L"已读取保存的 %zu 条指针路径，监控已自动开始", g.paths.size());
            }
            return 0;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(h, &ps);
            RECT rc;
            GetClientRect(h, &rc);
            FillRect(dc, &rc, g.bgBrush);
            DrawTitleBar(dc);
            DrawStatusPill(dc);
            EndPaint(h, &ps);
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_NCHITTEST: {
            POINT pt{ GET_X_LPARAM(l), GET_Y_LPARAM(l) };
            ScreenToClient(h, &pt);
            if (pt.y < S(kTitleH) && pt.x < S(kW - 96))
                return HTCAPTION;
            return DefWindowProcW(h, msg, w, l);
        }
        case WM_MOUSEMOVE: {
            if (!g.mouseTracked) {
                TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
                TrackMouseEvent(&tme);
                g.mouseTracked = true;
            }
            const int x = GET_X_LPARAM(l);
            const bool overMin = x >= S(kW - 92) && x < S(kW - 52);
            const bool overClose = x >= S(kW - 46) && x < S(kW - 6);
            if (overMin != g.hovMin || overClose != g.hovClose) {
                g.hovMin = overMin;
                g.hovClose = overClose;
                InvalidateRect(h, nullptr, FALSE);
            }
            return 0;
        }
        case WM_MOUSELEAVE:
            g.mouseTracked = false;
            if (g.hovMin || g.hovClose) {
                g.hovMin = false;
                g.hovClose = false;
                InvalidateRect(h, nullptr, FALSE);
            }
            return 0;
        case WM_LBUTTONUP: {
            const int x = GET_X_LPARAM(l);
            const int y = GET_Y_LPARAM(l);
            if (y < S(kTitleH) && x >= S(kW - 92) && x < S(kW - 52))
                ShowWindow(h, SW_MINIMIZE);
            else if (y < S(kTitleH) && x >= S(kW - 46) && x < S(kW - 6))
                PostMessageW(h, WM_CLOSE, 0, 0);
            return 0;
        }
        case WM_DRAWITEM: {
            auto* ds = reinterpret_cast<DRAWITEMSTRUCT*>(l);
            const auto* bd = reinterpret_cast<ButtonData*>(
                GetWindowLongPtrW(ds->hwndItem, GWLP_USERDATA));
            if (!bd)
                return 0;
            const bool pressed = (ds->itemState & ODS_SELECTED) != 0;
            RECT rc{};
            GetClientRect(ds->hwndItem, &rc);
            POINT pt{};
            GetCursorPos(&pt);
            ScreenToClient(ds->hwndItem, &pt);
            const bool hover = PtInRect(&rc, pt);
            COLORREF bg = pressed ? bd->down
                                  : (hover ? bd->hover : bd->bg);
            FillRoundRect(ds->hDC, 1, 1, rc.right - 1, rc.bottom - 1, bg);
            wchar_t text[128];
            GetWindowTextW(ds->hwndItem, text, _countof(text));
            SetBkMode(ds->hDC, TRANSPARENT);
            SetTextColor(ds->hDC, bd->text);
            SelectObject(ds->hDC, g.font);
            DrawTextW(ds->hDC, text, -1, &rc,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            return 0;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(w);
            if (GetDlgCtrlID(reinterpret_cast<HWND>(l)) == IDC_LOG) {
                SetTextColor(dc, kText);
                SetBkColor(dc, kInput);
                return reinterpret_cast<LRESULT>(g.inputBrush);
            }
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, kTextDim);
            return reinterpret_cast<LRESULT>(g.bgBrush);
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(w);
            SetTextColor(dc, kText);
            SetBkColor(dc, kInput);
            return reinterpret_cast<LRESULT>(g.inputBrush);
        }
        case WM_COMMAND: {
            switch (LOWORD(w)) {
                case IDC_BTN_MONITOR:  ToggleMonitor(); break;
                case IDC_BTN_SAVE:     SaveConfig();
                                       Log(L"配置已保存到 %s", CfgPath().c_str());
                                       break;
                case IDC_BTN_PATCHALL: DoPatchAll();    break;
                case IDC_BTN_SCAN:     DoScan();        break;
                case IDC_BTN_CHANGED:  DoChanged();     break;
                case IDC_BTN_RESTORED: DoRestored();    break;
                case IDC_BTN_FINDPTR:  DoFindPtr();     break;
                case IDC_BTN_TEST:     DoTestPtr();     break;
                case IDC_CHK_NOSLEEP:
                    g.noSleepAfter = SendMessageW(
                        GetDlgItem(g.hwnd, IDC_CHK_NOSLEEP), BM_GETCHECK, 0,
                        0) == BST_CHECKED;
                    SaveConfig();
                    if (!g.noSleepAfter)
                        Log(L"[配置] 修改后不休眠: 监控线程持续读写内存, "
                            L"长时间运行可能被小蓝熊(EAC)检测");
                    break;
                case IDC_CHK_POPUP:
                    g.popupAfter = SendMessageW(
                        GetDlgItem(g.hwnd, IDC_CHK_POPUP), BM_GETCHECK, 0,
                        0) == BST_CHECKED;
                    SaveConfig();
                    break;
            }
            return 0;
        }
        case WM_LOGMSG: {
            auto* text = reinterpret_cast<wchar_t*>(l);
            if (text) {
                Log(L"%s", text);
                free(text);
            }
            return 0;
        }
        case WM_JOB: {
            auto* job = reinterpret_cast<ScanJob*>(l);
            g.jobBusy = false;
            SetJobUi(true);
            if (!job->outErr.empty()) {
                MessageBoxW(h, job->outErr.c_str(), L"提示",
                            MB_ICONINFORMATION);
                delete job;
                return 0;
            }
            switch (job->kind) {
                case JOB_SCAN: {
                    g.scanner = std::move(job->scanner);
                    g.s1 = std::move(job->outMatches);
                    g.s2.clear();
                    g.s3.clear();
                    HWND lv = GetDlgItem(h, IDC_LV_ADDR);
                    ListView_DeleteAllItems(lv);
                    for (const ScanMatch& m : g.s1)
                        AddRow(lv, HexAddr(m.addr), std::to_wstring(m.value));
                    Log(L"步骤① 完成: 找到 %zu 处数值 = %lu", g.s1.size(),
                        g.from);
                    Log(L"接下来: 去 VD Streamer 把码率滑块改为其他值(如600)，然后点按钮②");
                    break;
                }
                case JOB_CHANGED: {
                    g.scanner = std::move(job->scanner);
                    g.s2 = std::move(job->outMatches);
                    HWND lv = GetDlgItem(h, IDC_LV_ADDR);
                    ListView_DeleteAllItems(lv);
                    for (const ScanMatch& m : g.s2)
                        AddRow(lv, HexAddr(m.addr), std::to_wstring(m.value));
                    Log(L"步骤② 完成: 数值已改变的地址 %zu 处", g.s2.size());
                    Log(L"接下来: 去 VD Streamer 把码率滑块改回 %lu，然后点按钮③",
                        g.from);
                    break;
                }
                case JOB_RESTORED: {
                    g.scanner = std::move(job->scanner);
                    g.s3 = std::move(job->outMatches);
                    HWND lv = GetDlgItem(h, IDC_LV_ADDR);
                    ListView_DeleteAllItems(lv);
                    for (const ScanMatch& m : g.s3)
                        AddRow(lv, HexAddr(m.addr), std::to_wstring(m.value));
                    Log(L"步骤③ 完成: 改回后仍保持 %lu 的地址 %zu 处 (即跟随滑块的活地址)",
                        g.from, g.s3.size());
                    if (g.s3.empty())
                        Log(L"结果为空: 请确认滑块确实改回了 %lu 的精确值，并重试②③",
                            g.from);
                    else
                        Log(L"可以继续执行 ④ 查找指针路径");
                    break;
                }
                case JOB_FINDPTR: {
                    g.scanner = std::move(job->scanner);
                    g.paths = std::move(job->outPaths);
                    HWND lv = GetDlgItem(h, IDC_LV_PATH);
                    ListView_DeleteAllItems(lv);
                    for (const PtrPath& p : g.paths) {
                        uintptr_t addr = 0;
                        std::wstring val = L"解析失败";
                        if (g.scanner && g.scanner->Resolve(p, &addr)) {
                            uint32_t v = 0;
                            if (g.scanner->Read32(addr, &v))
                                val = std::to_wstring(v);
                        }
                        AddRow(lv, p.ToString(), val);
                    }
                    Log(L"④ 完成: 共 %zu 条静态指针路径。选中一条点⑤测试，然后点「开始监控」",
                        g.paths.size());
                    break;
                }
                case JOB_PATCHALL: {
                    g.scanner = std::move(job->scanner);
                    Log(L"[全量] 已修改 %d 处内存 (%lu -> %lu)", job->patched,
                        g.from, g.to);
                    if (job->patched == 0)
                        Log(L"[全量] 未找到数值 %lu (请先确认 VD 码率滑块停在 %lu)",
                            g.from, g.from);
                    break;
                }
            }
            delete job;
            return 0;
        }
        case WM_SLEEP:
            OnAutoSleep(h, reinterpret_cast<wchar_t*>(l));
            return 0;
        case WM_SHOW:
            ShowWindow(h, SW_SHOW);
            SetForegroundWindow(h);
            return 0;
        case WM_TRAY:
            if (LOWORD(l) == WM_RBUTTONUP || LOWORD(l) == WM_CONTEXTMENU) {
                POINT pt{};
                GetCursorPos(&pt);
                HMENU m = CreatePopupMenu();
                AppendMenuW(m, MF_STRING, 1, L"显示窗口");
                AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
                AppendMenuW(m, MF_STRING, 2, L"退出");
                SetForegroundWindow(h);
                const int cmd = TrackPopupMenu(m, TPM_RETURNCMD |
                                                     TPM_RIGHTBUTTON |
                                                     TPM_NONOTIFY,
                                               pt.x, pt.y, 0, h, nullptr);
                DestroyMenu(m);
                if (cmd == 1) {
                    ShowWindow(h, SW_SHOW);
                    SetForegroundWindow(h);
                } else if (cmd == 2) {
                    g.realExit = true;
                    PostMessageW(h, WM_CLOSE, 0, 0);
                }
            } else if (LOWORD(l) == WM_LBUTTONDBLCLK) {
                ShowWindow(h, SW_SHOW);
                SetForegroundWindow(h);
            }
            return 0;
        case WM_CLOSE:
            if (g.realExit) {
                DestroyWindow(h);
            } else {
                ShowWindow(h, SW_HIDE);
                Log(L"窗口已隐藏到系统托盘，监控继续运行。双击托盘图标恢复。");
                TrayBalloon(L"已最小化到托盘，监控继续运行");
            }
            return 0;
        case WM_DESTROY: {
            NOTIFYICONDATAW nid{};
            nid.cbSize = sizeof(nid);
            nid.hWnd   = h;
            nid.uID    = kTrayId;
            Shell_NotifyIconW(NIM_DELETE, &nid);
            StopMonitor();
            g.scanner.reset();
            if (g.font) DeleteObject(g.font);
            if (g.titleFont) DeleteObject(g.titleFont);
            if (g.statusFont) DeleteObject(g.statusFont);
            if (g.smallFont) DeleteObject(g.smallFont);
            if (g.appIcon) DestroyIcon(g.appIcon);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(h, msg, w, l);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow)
{
    // PerMonitorV2 DPI 感知，保证自绘 UI 在任意缩放比下像素级正确
    {
        using Fn = BOOL(WINAPI*)(void*);
        HMODULE u32 = GetModuleHandleW(L"user32.dll");
        auto setCtx = reinterpret_cast<Fn>(
            GetProcAddress(u32, "SetProcessDpiAwarenessContext"));
        if (setCtx)
            setCtx(reinterpret_cast<void*>(-4));  // PER_MONITOR_AWARE_V2
    }

    g.hInst = hInstance;
    g.bgBrush     = CreateSolidBrush(kBg);
    g.cardBrush   = CreateSolidBrush(kCard);
    g.inputBrush  = CreateSolidBrush(kInput);
    g.accentBrush = CreateSolidBrush(kAccent);
    g.appIcon     = CreateAppIcon(L"VD");

    InitDarkMode();
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon         = g.appIcon;
    wc.hbrBackground = g.bgBrush;
    wc.lpszClassName = L"VdBitrateAutosetWnd";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, L"VdBitrateAutosetWnd", L"VD码率修改器",
                                WS_POPUP | WS_MINIMIZEBOX, CW_USEDEFAULT,
                                CW_USEDEFAULT, kW, kH, nullptr, nullptr,
                                hInstance, nullptr);
    if (!hwnd)
        return 1;

    // 按窗口所在监视器 DPI 缩放窗口与布局
    {
        const int dpi = GetDpiForWindow(hwnd);
        const double s = (dpi > 0) ? static_cast<double>(dpi) / 96.0 : 1.0;
        if (s != 1.0)
            SetWindowPos(hwnd, nullptr, 0, 0, S(kW), S(kH),
                         SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }

    // Win11 圆角窗口
    {
        const DWORD corner = 2;  // DWMWCP_ROUND
        DwmSetWindowAttribute(hwnd, 33, &corner, sizeof(corner));
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    SetFocus(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    DeleteObject(g.bgBrush);
    DeleteObject(g.cardBrush);
    DeleteObject(g.inputBrush);
    DeleteObject(g.accentBrush);
    return static_cast<int>(msg.wParam);
}
