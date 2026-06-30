/*
 * UACGuard.cpp
 * Сторож UAC с асинхронным диалогом, watchdog-процессом и логированием в Event Log.
 * Компиляция (MinGW x64):
 *   g++ -O2 -static UACGuard.cpp -o UACGuard.exe -ladvapi32 -luser32 -lwevtapi
 *
 * Требования: Windows Vista+, права администратора.
 * Программа устанавливается в HKLM\Run, отслеживает настройки UAC в реестре
 * и восстанавливает их после подтверждения пользователем, если они ослаблены или отключены.
 * Watchdog-процесс обеспечивает перезапуск при принудительном завершении.
 */

#include <windows.h>
#include <iostream>
#include <string>
#include <atomic>
#include <thread>
#include <sstream>
#include <iomanip>

// =========================== НАСТРОЙКИ ===========================
namespace Config {
    constexpr wchar_t REG_PATH[]       = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    constexpr wchar_t AUTORUN_KEY[]    = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    constexpr wchar_t APP_NAME[]       = L"UACGuard";
    constexpr wchar_t MUTEX_NAME[]     = L"Global\\UACGuard_Mutex";
    constexpr wchar_t WATCHDOG_ARG[]   = L"--watchdog";
    constexpr DWORD   ENABLE_LUA       = 1;    // UAC включён
    constexpr DWORD   CONSENT_PROMPT   = 5;    // Запрос согласия для админов
    constexpr DWORD   SECURE_DESKTOP   = 1;    // Безопасный рабочий стол
    constexpr DWORD   DIALOG_TIMEOUT_SEC = 30; // Таймаут диалога в секундах
    constexpr DWORD   AUTORUN_CHECK_SEC  = 60; // Период проверки автозагрузки
}

// =========================== ЛОГИРОВАНИЕ В EVENT LOG ===========================
class EventLogger {
public:
    EventLogger() : hEventLog(nullptr) {
        hEventLog = RegisterEventSourceW(nullptr, Config::APP_NAME);
        if (!hEventLog) {
            // Пробуем создать источник событий в реестре
            CreateEventSource();
            hEventLog = RegisterEventSourceW(nullptr, Config::APP_NAME);
        }
    }
    ~EventLogger() {
        if (hEventLog) DeregisterEventSource(hEventLog);
    }

    void LogInfo(const std::wstring& msg) {
        Log(EVENTLOG_INFORMATION_TYPE, msg);
    }
    void LogWarning(const std::wstring& msg) {
        Log(EVENTLOG_WARNING_TYPE, msg);
    }
    void LogError(const std::wstring& msg) {
        Log(EVENTLOG_ERROR_TYPE, msg);
    }

private:
    HANDLE hEventLog;

    void Log(WORD type, const std::wstring& msg) {
        if (!hEventLog) return;
        LPCWSTR strings[] = { msg.c_str() };
        ReportEventW(hEventLog, type, 0, 0, nullptr, 1, 0, strings, nullptr);
    }

    void CreateEventSource() {
        HKEY hKey;
        DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + std::wstring(Config::APP_NAME);
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD, (BYTE*)&dwData, sizeof(dwData));
            RegCloseKey(hKey);
        }
    }
};

// Глобальный логгер
EventLogger g_logger;

// =========================== ГЛОБАЛЬНАЯ СИНХРОНИЗАЦИЯ ===========================
struct GlobalState {
    std::atomic<bool> restoreInProgress{ false };   // Идёт восстановление настроек
    std::atomic<bool> dialogActive{ false };         // Диалог уже открыт
    std::atomic<bool> shutdownRequested{ false };    // Запрошено завершение
};

GlobalState g_state;

// Глобальные события
HANDLE g_hUacChangedEvent = nullptr;   // Сигнал: настройки UAC изменились
HANDLE g_hShutdownEvent   = nullptr;   // Сигнал: пора завершаться

// =========================== РАБОТА С РЕЕСТРОМ ===========================
bool SetRegistryDword(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD data) {
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_WRITE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return false;
    LONG res = RegSetValueExW(hKey, valueName, 0, REG_DWORD, (BYTE*)&data, sizeof(data));
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

bool GetRegistryDword(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD& out) {
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD type, size = sizeof(out);
    LONG res = RegQueryValueExW(hKey, valueName, nullptr, &type, (BYTE*)&out, &size);
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS && type == REG_DWORD);
}

// =========================== АВТОЗАГРУЗКА ===========================
void InstallAutorun() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Config::AUTORUN_KEY, 0, KEY_WRITE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, Config::APP_NAME, 0, REG_SZ,
                       (BYTE*)path, (DWORD)((wcslen(path) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
        g_logger.LogInfo(L"Запись в автозагрузку добавлена.");
    } else {
        g_logger.LogError(L"Не удалось открыть ключ автозагрузки для записи.");
    }
}

void EnsureAutorun() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Config::AUTORUN_KEY, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD type, size;
        if (RegQueryValueExW(hKey, Config::APP_NAME, nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
            type != REG_SZ) {
            RegCloseKey(hKey);
            g_logger.LogWarning(L"Запись в автозагрузке отсутствует или повреждена. Переустанавливаю.");
            InstallAutorun();
        } else {
            RegCloseKey(hKey);
        }
    } else {
        g_logger.LogWarning(L"Ключ автозагрузки не найден. Пробую создать и установить.");
        InstallAutorun();
    }
}

// =========================== ДИАЛОГ С ПОЛЬЗОВАТЕЛЕМ ===========================
bool ShowDialogAndGetConsent() {
    // Не даём открыть два диалога одновременно
    if (g_state.dialogActive.exchange(true)) {
        return false;
    }

    if (!AllocConsole()) {
        g_state.dialogActive = false;
        return false;
    }

    FILE* f;
    freopen_s(&f, "CONIN$", "r", stdin);
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::wcout << L"========================================\n";
    std::wcout << L"     UAC PROTECTION — НАСТРОЙКИ ИЗМЕНЕНЫ!\n";
    std::wcout << L"========================================\n";
    std::wcout << L"UAC был отключён или ослаблен.\n";
    std::wcout << L"Восстановить безопасные настройки? (Y/N)\n";
    std::wcout << L"Таймаут " << Config::DIALOG_TIMEOUT_SEC << L" секунд (по умолчанию: Нет).\n\n";

    std::string answer;
    bool answered = false;
    DWORD startTick = GetTickCount();
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);

    while ((GetTickCount() - startTick) < Config::DIALOG_TIMEOUT_SEC * 1000) {
        if (WaitForSingleObject(hStdIn, 100) == WAIT_OBJECT_0) {
            std::cin >> answer;
            answered = true;
            break;
        }
        if (g_state.shutdownRequested) break;
    }

    bool consent = false;
    if (answered && (answer == "Y" || answer == "y")) {
        consent = true;
        std::wcout << L"\nВосстанавливаю настройки UAC...\n";
    } else {
        std::wcout << L"\nДействие отменено или истекло время ожидания.\n";
    }

    std::wcout << L"Окно закроется через 3 секунды...\n";
    Sleep(3000);
    FreeConsole();

    g_state.dialogActive = false;
    return consent;
}

// =========================== ПРОВЕРКА И ВОССТАНОВЛЕНИЕ UAC ===========================
bool IsUACIntact() {
    DWORD enableLua, consent, secureDesktop;
    bool intact = true;

    if (!GetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"EnableLUA", enableLua) ||
        enableLua != Config::ENABLE_LUA) {
        intact = false;
    }
    if (!GetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"ConsentPromptBehaviorAdmin", consent) ||
        consent != Config::CONSENT_PROMPT) {
        intact = false;
    }
    if (!GetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"PromptOnSecureDesktop", secureDesktop) ||
        secureDesktop != Config::SECURE_DESKTOP) {
        intact = false;
    }
    return intact;
}

void RestoreUAC() {
    // Защита от повторного входа
    bool expected = false;
    if (!g_state.restoreInProgress.compare_exchange_strong(expected, true)) {
        return;
    }

    bool success = true;
    success &= SetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"EnableLUA", Config::ENABLE_LUA);
    success &= SetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"ConsentPromptBehaviorAdmin", Config::CONSENT_PROMPT);
    success &= SetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"PromptOnSecureDesktop", Config::SECURE_DESKTOP);

    if (success) {
        g_logger.LogInfo(L"Настройки UAC восстановлены.");
        // Уведомляем систему об изменении политики
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Policy",
                            SMTO_ABORTIFHUNG, 2000, nullptr);
    } else {
        g_logger.LogError(L"Не удалось восстановить одну или несколько настроек UAC.");
    }

    g_state.restoreInProgress = false;
}

// =========================== ПОТОК-ОБРАБОТЧИК ===========================
// Ждёт сигнала об изменении реестра и запускает диалог
DWORD WINAPI HandlerThreadProc(LPVOID) {
    while (!g_state.shutdownRequested) {
        DWORD waitResult = WaitForSingleObject(g_hUacChangedEvent, 1000);
        if (waitResult == WAIT_OBJECT_0) {
            ResetEvent(g_hUacChangedEvent);
            if (g_state.shutdownRequested) break;
            if (g_state.restoreInProgress) continue;
            if (!IsUACIntact()) {
                g_logger.LogWarning(L"Настройки UAC были изменены.");
                if (ShowDialogAndGetConsent()) {
                    RestoreUAC();
                } else {
                    g_logger.LogInfo(L"Пользователь отказался от восстановления.");
                }
            }
        } else if (waitResult == WAIT_TIMEOUT) {
            continue;
        } else {
            break;
        }
    }
    g_logger.LogInfo(L"Поток-обработчик завершён.");
    return 0;
}

// =========================== ПОТОК МОНИТОРИНГА РЕЕСТРА ===========================
DWORD WINAPI MonitorThreadProc(LPVOID) {
    while (!g_state.shutdownRequested) {
        HKEY hKey;
        LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Config::REG_PATH, 0,
                                 KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (res != ERROR_SUCCESS) {
            g_logger.LogError(L"Не удалось открыть ключ реестра UAC. Повтор через 5 секунд...");
            Sleep(5000);
            continue;
        }

        // Сразу сигнализируем о проверке — вдруг что-то изменилось, пока мы не следили
        SetEvent(g_hUacChangedEvent);

        while (!g_state.shutdownRequested) {
            HANDLE hRegEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (!hRegEvent) break;

            res = RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_LAST_SET, hRegEvent, TRUE);
            if (res != ERROR_SUCCESS) {
                CloseHandle(hRegEvent);
                if (res == ERROR_CALL_NOT_IMPLEMENTED) {
                    // Запасной вариант — опрос раз в секунду
                    Sleep(1000);
                    SetEvent(g_hUacChangedEvent);
                }
                break;
            }

            // Ждём изменение реестра или сигнал завершения
            HANDLE events[2] = { hRegEvent, g_hShutdownEvent };
            DWORD waitRes = WaitForMultipleObjects(2, events, FALSE, INFINITE);

            CloseHandle(hRegEvent);
            if (waitRes == WAIT_OBJECT_0) {
                // Реестр изменился
                SetEvent(g_hUacChangedEvent);
            } else if (waitRes == WAIT_OBJECT_0 + 1) {
                // Завершение
                break;
            } else {
                break;
            }
        }
        RegCloseKey(hKey);
        if (g_state.shutdownRequested) break;
        Sleep(500);
    }
    g_logger.LogInfo(L"Поток мониторинга завершён.");
    return 0;
}

// =========================== WATCHDOG ===========================
void RunWatchdog(DWORD parentPid) {
    g_logger.LogInfo(L"Watchdog запущен. Охраняю процесс PID " + std::to_wstring(parentPid));
    HANDLE hParent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!hParent) {
        g_logger.LogError(L"Watchdog: не удалось открыть родительский процесс.");
        return;
    }
    // Ждём, пока родительский процесс завершится
    WaitForSingleObject(hParent, INFINITE);
    CloseHandle(hParent);

    g_logger.LogWarning(L"Watchdog: родительский процесс завершён. Перезапускаю UACGuard...");
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessW(path, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        g_logger.LogInfo(L"Watchdog: новый экземпляр запущен.");
    } else {
        g_logger.LogError(L"Watchdog: не удалось запустить новый экземпляр.");
    }
}

void LaunchWatchdog(DWORD parentPid) {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t cmdLine[MAX_PATH + 30];
    swprintf_s(cmdLine, L"\"%s\" %s %lu", path, Config::WATCHDOG_ARG, parentPid);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        g_logger.LogInfo(L"Watchdog-процесс запущен.");
    } else {
        g_logger.LogError(L"Не удалось запустить watchdog-процесс.");
    }
}

// =========================== ТОЧКА ВХОДА ===========================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Проверяем аргументы командной строки — может, нас запустили как watchdog
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc >= 3 && wcscmp(argv[1], Config::WATCHDOG_ARG) == 0) {
        DWORD parentPid = _wtoi(argv[2]);
        LocalFree(argv);
        RunWatchdog(parentPid);
        return 0;
    }
    if (argv) LocalFree(argv);

    // Мьютекс — только один экземпляр программы
    HANDLE hMutex = CreateMutexW(nullptr, FALSE, Config::MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        g_logger.LogInfo(L"Другой экземпляр уже запущен. Выхожу.");
        CloseHandle(hMutex);
        return 0;
    }

    // Проверяем права администратора
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    if (!isElevated) {
        g_logger.LogError(L"UACGuard требует права администратора. Выхожу.");
        CloseHandle(hMutex);
        return 1;
    }

    g_logger.LogInfo(L"UACGuard запускается...");

    // Создаём глобальные события
    g_hUacChangedEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);   // Автосброс
    g_hShutdownEvent   = CreateEventW(nullptr, TRUE, FALSE, nullptr);    // Ручной сброс
    if (!g_hUacChangedEvent || !g_hShutdownEvent) {
        g_logger.LogError(L"Не удалось создать события синхронизации.");
        CloseHandle(hMutex);
        return 1;
    }

    // Устанавливаемся в автозагрузку и запускаем watchdog
    InstallAutorun();
    EnsureAutorun();
    LaunchWatchdog(GetCurrentProcessId());

    // Периодическая проверка автозагрузки в отдельном потоке
    std::thread autoRunThread([]() {
        while (!g_state.shutdownRequested) {
            for (int i = 0; i < Config::AUTORUN_CHECK_SEC; ++i) {
                if (g_state.shutdownRequested) return;
                Sleep(1000);
            }
            EnsureAutorun();
        }
    });

    // Запускаем рабочие потоки
    HANDLE hMonitorThread = CreateThread(nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr);
    HANDLE hHandlerThread = CreateThread(nullptr, 0, HandlerThreadProc, nullptr, 0, nullptr);

    if (!hMonitorThread || !hHandlerThread) {
        g_logger.LogError(L"Не удалось запустить рабочие потоки.");
        g_state.shutdownRequested = true;
        SetEvent(g_hShutdownEvent);
        if (hMonitorThread) WaitForSingleObject(hMonitorThread, 5000);
        if (hHandlerThread) WaitForSingleObject(hHandlerThread, 5000);
        return 1;
    }

    // Ждём завершения любого из потоков (или системного выключения)
    HANDLE threads[] = { hMonitorThread, hHandlerThread };
    WaitForMultipleObjects(2, threads, FALSE, INFINITE);

    // Начинаем корректное завершение
    g_state.shutdownRequested = true;
    SetEvent(g_hShutdownEvent);

    // Ждём завершения потока проверки автозагрузки
    if (autoRunThread.joinable()) {
        autoRunThread.join();
    }

    CloseHandle(hMonitorThread);
    CloseHandle(hHandlerThread);
    CloseHandle(hMutex);
    CloseHandle(g_hShutdownEvent);
    CloseHandle(g_hUacChangedEvent);

    g_logger.LogInfo(L"UACGuard завершил работу.");
    return 0;
}