#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <uxtheme.h>
#include <string>
#include <vector>
#include <thread>
#include "scanner.h"
#include "../res/resource.h"

static HWND hWnd, hPath, hBrowse, hRecursive, hScan, hHeal, hList, hStatus;
static bool scanning = false;
static std::vector<ScanResult> g_results;

static COLORREF clrSafe = RGB(34, 139, 34);
static COLORREF clrDanger = RGB(200, 40, 40);
static COLORREF clrBg = RGB(245, 245, 248);
static COLORREF clrListBg = RGB(255, 255, 255);
static COLORREF clrText = RGB(30, 30, 30);

static HBRUSH hBrBg;
static HFONT hFontUI, hFontTitle;

static bool langRu = true;

static const wchar_t* T(const wchar_t* ru, const wchar_t* en) { return langRu ? ru : en; }

static void InitFonts() {
    NONCLIENTMETRICSW ncm = { sizeof(ncm) };
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    ncm.lfMessageFont.lfHeight = -14;
    wcscpy_s(ncm.lfMessageFont.lfFaceName, L"Segoe UI");
    hFontUI = CreateFontIndirectW(&ncm.lfMessageFont);
    ncm.lfMessageFont.lfHeight = -18;
    ncm.lfMessageFont.lfWeight = FW_BOLD;
    hFontTitle = CreateFontIndirectW(&ncm.lfMessageFont);
}

static void SetupListView() {
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    col.pszText = (LPWSTR)T(L"Файл", L"File");
    col.cx = 520;
    col.iSubItem = 0;
    ListView_InsertColumn(hList, 0, &col);

    col.pszText = (LPWSTR)T(L"Статус", L"Status");
    col.cx = 100;
    col.iSubItem = 1;
    ListView_InsertColumn(hList, 1, &col);

    col.pszText = (LPWSTR)T(L"Подробности", L"Details");
    col.cx = 340;
    col.iSubItem = 2;
    ListView_InsertColumn(hList, 2, &col);
}

static void RefreshList() {
    ListView_DeleteAllItems(hList);
    for (int i = 0; i < (int)g_results.size(); i++) {
        auto& r = g_results[i];
        LVITEMW item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = i;
        item.pszText = (LPWSTR)r.path.c_str();
        item.lParam = (LPARAM)r.verdict;
        ListView_InsertItem(hList, &item);

        const wchar_t* status = r.verdict == Verdict::Malicious ?
            T(L"УГРОЗА", L"MALICIOUS") : T(L"ЧИСТО", L"SAFE");
        ListView_SetItemText(hList, i, 1, (LPWSTR)status);
        ListView_SetItemText(hList, i, 2, (LPWSTR)r.threat.c_str());
    }
}

static void DoScan() {
    wchar_t path[MAX_PATH] = {};
    GetWindowTextW(hPath, path, MAX_PATH);
    bool recursive = SendMessageW(hRecursive, BM_GETCHECK, 0, 0) == BST_CHECKED;

    g_results.clear();
    ListView_DeleteAllItems(hList);
    SetWindowTextW(hStatus, T(L"Сканирование...", L"Scanning..."));
    EnableWindow(hScan, FALSE);
    EnableWindow(hHeal, FALSE);
    scanning = true;

    std::wstring dir = path;
    std::thread([dir, recursive]() {
        ScanStats stats{};
        auto results = ScanDirectory(dir, recursive, stats);

        for (auto& r : results) {
            auto* copy = new ScanResult(r);
            PostMessage(hWnd, WM_APP + 2, 0, reinterpret_cast<LPARAM>(copy));
        }

        PostMessage(hWnd, WM_APP + 3, (WPARAM)stats.files,
            MAKELPARAM(stats.threats, stats.folders));
    }).detach();
}

static void DoHeal() {
    int res = MessageBoxW(hWnd,
        T(L"Лечение обрежет вредоносные данные из файлов.\n"
          L"Это может не помочь до конца если файл сильно поврежден.\n\n"
          L"Продолжить?",
          L"Healing will truncate malicious data from files.\n"
          L"This may not fully repair severely corrupted files.\n\n"
          L"Continue?"),
        T(L"Подтверждение", L"Confirm"),
        MB_OKCANCEL | MB_ICONWARNING);

    if (res != IDOK) return;

    int healed = 0;
    for (auto& r : g_results) {
        if (r.verdict != Verdict::Malicious) continue;
        if (HealFile(r.path)) {
            r.verdict = Verdict::Safe;
            r.threat = T(L"Вылечено", L"Healed");
            healed++;
        }
    }

    RefreshList();
    EnableWindow(hHeal, FALSE);

    wchar_t buf[128];
    wsprintfW(buf, T(L"Вылечено файлов: %d", L"Healed %d file(s)."), healed);
    SetWindowTextW(hStatus, buf);
}

static void BrowseFolder() {
    BROWSEINFOW bi = {};
    bi.hwndOwner = hWnd;
    bi.lpszTitle = T(L"Выберите папку для сканирования", L"Select folder to scan");
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t path[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, path))
            SetWindowTextW(hPath, path);
        CoTaskMemFree(pidl);
    }
}

static void UpdateLang();

static LRESULT CALLBACK WndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        hBrBg = CreateSolidBrush(clrBg);
        InitFonts();

        HMENU hMenu = CreateMenu();
        HMENU hLangMenu = CreatePopupMenu();
        AppendMenuW(hLangMenu, MF_STRING | MF_CHECKED, 2001, L"Русский");
        AppendMenuW(hLangMenu, MF_STRING, 2002, L"English");
        AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hLangMenu, L"Язык / Language");
        SetMenu(hw, hMenu);

        auto cs = [&](LPCWSTR cls, LPCWSTR text, DWORD style, int x, int y, int w, int h, int id) -> HWND {
            HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                x, y, w, h, hw, (HMENU)(intptr_t)id, GetModuleHandleW(nullptr), nullptr);
            SendMessageW(c, WM_SETFONT, (WPARAM)hFontUI, TRUE);
            return c;
        };

        HWND hTitle = cs(L"STATIC", L"RWGuard", SS_CENTER, 0, 8, 960, 26, 0);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);

        cs(L"STATIC", T(L"Папка:", L"Folder:"), 0, 16, 44, 46, 20, 3000);
        hPath = cs(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 66, 40, 600, 26, IDC_PATH_EDIT);
        hBrowse = cs(L"BUTTON", T(L"Обзор", L"Browse"), BS_PUSHBUTTON, 674, 40, 80, 26, IDC_BROWSE);
        hScan = cs(L"BUTTON", T(L"Сканировать", L"Scan"), BS_PUSHBUTTON, 762, 40, 100, 26, IDC_SCAN);

        hRecursive = cs(L"BUTTON", T(L"Сканировать подпапки", L"Scan subfolders"),
            BS_AUTOCHECKBOX, 66, 74, 200, 20, IDC_RECURSIVE);
        SendMessageW(hRecursive, BM_SETCHECK, BST_CHECKED, 0);
        hHeal = cs(L"BUTTON", T(L"Вылечить", L"Heal"), BS_PUSHBUTTON, 762, 70, 100, 26, IDC_HEAL);
        EnableWindow(hHeal, FALSE);

        hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_NOSORTHEADER,
            16, 104, 930, 400, hw, (HMENU)IDC_LIST, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(hList, WM_SETFONT, (WPARAM)hFontUI, TRUE);
        SetupListView();

        ListView_SetBkColor(hList, clrListBg);
        ListView_SetTextBkColor(hList, clrListBg);
        ListView_SetTextColor(hList, clrText);

        hStatus = cs(L"STATIC", T(L"Выберите папку и нажмите Сканировать",
            L"Select a folder and click Scan"), 0, 16, 512, 800, 20, IDC_STATUS);

        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BROWSE) BrowseFolder();
        if (LOWORD(wp) == IDC_SCAN && !scanning) DoScan();
        if (LOWORD(wp) == IDC_HEAL && !scanning) DoHeal();
        if (LOWORD(wp) == 2001) { langRu = true; UpdateLang(); }
        if (LOWORD(wp) == 2002) { langRu = false; UpdateLang(); }
        return 0;

    case WM_APP + 2: {
        auto* r = reinterpret_cast<ScanResult*>(lp);
        if (r) {
            g_results.push_back(*r);

            LVITEMW item = {};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = ListView_GetItemCount(hList);
            item.pszText = (LPWSTR)r->path.c_str();
            item.lParam = (LPARAM)r->verdict;
            ListView_InsertItem(hList, &item);

            const wchar_t* status = r->verdict == Verdict::Malicious ?
                T(L"УГРОЗА", L"MALICIOUS") : T(L"ЧИСТО", L"SAFE");
            ListView_SetItemText(hList, item.iItem, 1, (LPWSTR)status);
            ListView_SetItemText(hList, item.iItem, 2, (LPWSTR)r->threat.c_str());
            delete r;
        }
        return 0;
    }

    case WM_APP + 3: {
        int total = (int)wp;
        int threats = LOWORD(lp);
        int folders = HIWORD(lp);
        wchar_t buf[256];
        wsprintfW(buf, T(
            L"Готово. Папок: %d, файлов: %d, угроз: %d",
            L"Done. Folders: %d, files: %d, threats: %d"),
            folders, total, threats);
        SetWindowTextW(hStatus, buf);
        EnableWindow(hScan, TRUE);
        EnableWindow(hHeal, threats > 0 ? TRUE : FALSE);
        scanning = false;
        return 0;
    }

    case WM_NOTIFY: {
        auto* nm = reinterpret_cast<LPNMHDR>(lp);
        if (nm->idFrom == IDC_LIST && nm->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<LPNMLVCUSTOMDRAW>(lp);
            switch (cd->nmcd.dwDrawStage) {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT:
                return CDRF_NOTIFYSUBITEMDRAW;
            case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
                if (cd->iSubItem == 1) {
                    auto v = (Verdict)cd->nmcd.lItemlParam;
                    cd->clrText = v == Verdict::Malicious ? clrDanger : clrSafe;
                } else {
                    cd->clrText = clrText;
                }
                cd->clrTextBk = clrListBg;
                return CDRF_NEWFONT;
            }
        }
        break;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hw, &rc);
        int w = rc.right, h = rc.bottom;
        MoveWindow(hPath, 66, 40, w - 310, 26, TRUE);
        MoveWindow(hBrowse, w - 236, 40, 80, 26, TRUE);
        MoveWindow(hScan, w - 148, 40, 100, 26, TRUE);
        MoveWindow(hHeal, w - 148, 70, 100, 26, TRUE);
        MoveWindow(hList, 16, 104, w - 32, h - 146, TRUE);
        MoveWindow(hStatus, 16, h - 34, w - 32, 20, TRUE);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, clrText);
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)hBrBg;
    }

    case WM_ERASEBKGND: {
        RECT rc;
        GetClientRect(hw, &rc);
        FillRect((HDC)wp, &rc, hBrBg);
        return 1;
    }

    case WM_DESTROY:
        DeleteObject(hBrBg);
        DeleteObject(hFontUI);
        DeleteObject(hFontTitle);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hw, msg, wp, lp);
}

static void UpdateLang() {
    HMENU hMenu = GetMenu(hWnd);
    HMENU hLang = GetSubMenu(hMenu, 0);
    CheckMenuItem(hLang, 2001, langRu ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(hLang, 2002, langRu ? MF_UNCHECKED : MF_CHECKED);

    SetWindowTextW(GetDlgItem(hWnd, 3000), T(L"Папка:", L"Folder:"));
    SetWindowTextW(hBrowse, T(L"Обзор", L"Browse"));
    SetWindowTextW(hScan, T(L"Сканировать", L"Scan"));
    SetWindowTextW(hHeal, T(L"Вылечить", L"Heal"));
    SetWindowTextW(hRecursive, T(L"Сканировать подпапки", L"Scan subfolders"));
    SetWindowTextW(hStatus, T(L"Выберите папку и нажмите Сканировать",
        L"Select a folder and click Scan"));

    while (ListView_DeleteColumn(hList, 0)) {}
    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    col.pszText = (LPWSTR)T(L"Файл", L"File"); col.cx = 520; col.iSubItem = 0;
    ListView_InsertColumn(hList, 0, &col);
    col.pszText = (LPWSTR)T(L"Статус", L"Status"); col.cx = 100; col.iSubItem = 1;
    ListView_InsertColumn(hList, 1, &col);
    col.pszText = (LPWSTR)T(L"Подробности", L"Details"); col.cx = 340; col.iSubItem = 2;
    ListView_InsertColumn(hList, 2, &col);

    RefreshList();
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = CreateSolidBrush(clrBg);
    wc.lpszClassName = L"RWGuardClass";
    wc.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32518));
    wc.hIconSm = wc.hIcon;
    RegisterClassExW(&wc);

    hWnd = CreateWindowExW(0, L"RWGuardClass", L"RWGuard",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 600,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(hWnd, nShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
