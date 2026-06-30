

#include <windows.h>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>

// =========================== НАСТРОЙКИ ===========================
namespace Config {
    constexpr wchar_t REG_PATH[]       = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    constexpr wchar_t AUTORUN_KEY[]    = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    constexpr wchar_t APP_NAME[]       = L"UACGuard";
    constexpr wchar_t MUTEX_NAME[]     = L"Global\\UACGuard_Mutex";
    constexpr wchar_t WATCHDOG_ARG[]   = L"--watchdog";
    constexpr DWORD   ENABLE_LUA       = 1;
    constexpr DWORD   CONSENT_PROMPT   = 5;
    constexpr DWORD   SECURE_DESKTOP   = 1;
    constexpr DWORD   DIALOG_TIMEOUT_SEC = 30;
    constexpr DWORD   DIALOG_CLOSE_DELAY_SEC = 3;
    constexpr DWORD   AUTORUN_CHECK_SEC  = 60;
    constexpr DWORD   LOG_ERROR_INTERVAL_SEC = 60;
    constexpr DWORD   WATCHDOG_RESTART_DELAY_SEC = 5;
    constexpr DWORD   THREAD_JOIN_TIMEOUT_MS = 5000;   // Таймаут ожидания потоков при завершении
}

// =========================== ЛОГИРОВАНИЕ ===========================
class EventLogger {
public:
    EventLogger() : hEventLog(nullptr) {
        hEventLog = RegisterEventSourceW(nullptr, Config::APP_NAME);
        if (!hEventLog) {
            if (CreateEventSource()) {
                hEventLog = RegisterEventSourceW(nullptr, Config::APP_NAME);
            }
        }
    }

    ~EventLogger() {
        if (hEventLog) DeregisterEventSource(hEventLog);
    }

    void LogInfo(const std::wstring& msg)   { Log(EVENTLOG_INFORMATION_TYPE, msg); }
    void LogWarning(const std::wstring& msg) { Log(EVENTLOG_WARNING_TYPE, msg); }
    void LogError(const std::wstring& msg)   { Log(EVENTLOG_ERROR_TYPE, msg); }

private:
    HANDLE hEventLog;
    std::mutex logMutex;
    DWORD lastErrorTime = 0;
    std::wstring lastErrorMessage;

    void Log(WORD type, const std::wstring& msg) {
        std::lock_guard<std::mutex> lock(logMutex);
        if (type == EVENTLOG_ERROR_TYPE) {
            DWORD now = GetTickCount64();
            if (msg == lastErrorMessage && (now - lastErrorTime) < Config::LOG_ERROR_INTERVAL_SEC * 1000)
                return;
            lastErrorTime = now;
            lastErrorMessage = msg;
        }
        if (hEventLog) {
            LPCWSTR strings[] = { msg.c_str() };
            ReportEventW(hEventLog, type, 0, 0, nullptr, 1, 0, strings, nullptr);
        }
        OutputDebugStringW((L"UACGuard: " + msg + L"\n").c_str());
    }

    bool CreateEventSource() {
        HKEY hKey;
        DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + std::wstring(Config::APP_NAME);
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr,
                            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD, (BYTE*)&dwData, sizeof(dwData));
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }
};

EventLogger g_logger;

// =========================== ГЛОБАЛЬНАЯ СИНХРОНИЗАЦИЯ ===========================
struct GlobalState {
    std::atomic<bool> restoreInProgress{ false };
    std::atomic<bool> dialogActive{ false };
    std::atomic<bool> shutdownRequested{ false };
};

GlobalState g_state;

HANDLE g_hUacChangedEvent = nullptr;
HANDLE g_hShutdownEvent   = nullptr;
HANDLE g_hWatchdogProcess = nullptr;

// =========================== ОБРАБОТЧИК КОНСОЛЬНЫХ СОБЫТИЙ ===========================
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        g_logger.LogInfo(L"Получен сигнал завершения системы/консоли.");
        g_state.shutdownRequested = true;
        if (g_hShutdownEvent) SetEvent(g_hShutdownEvent);
        // Даём потокам время завершиться
        Sleep(1000);
        // При выключении системы убиваем watchdog, чтобы избежать перезапуска
        if (dwCtrlType == CTRL_SHUTDOWN_EVENT && g_hWatchdogProcess) {
            TerminateProcess(g_hWatchdogProcess, 0);
            CloseHandle(g_hWatchdogProcess);
            g_hWatchdogProcess = nullptr;
        }
        return TRUE;
    default:
        return FALSE;
    }
}

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
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        g_logger.LogError(L"Не удалось получить путь к исполняемому файлу.");
        return;
    }
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

// =========================== ДИАЛОГ С ПОЛЬЗОВАТЕЛЕМ (нативный консольный ввод-вывод) ===========================
bool ShowDialogAndGetConsent() {
    if (g_state.dialogActive.exchange(true))
        return false;

    // Захват консоли
    bool allocated = AllocConsole() != FALSE;
    if (!allocated) {
        if (GetLastError() == ERROR_ACCESS_DENIED) {
            // Консоль уже существует у процесса, прикрепляемся
            if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
                g_state.dialogActive = false;
                return false;
            }
        } else {
            g_state.dialogActive = false;
            return false;
        }
    }

    // Устанавливаем кодировку UTF-8 для консоли
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
    HANDLE hConsoleOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hConsoleIn  = GetStdHandle(STD_INPUT_HANDLE);

    if (hConsoleOut == INVALID_HANDLE_VALUE || hConsoleIn == INVALID_HANDLE_VALUE) {
        if (allocated) FreeConsole(); else AttachConsole(ATTACH_PARENT_PROCESS);
        g_state.dialogActive = false;
        return false;
    }

    const wchar_t* prompt =
        L"========================================\n"
        L"     UAC PROTECTION — НАСТРОЙКИ ИЗМЕНЕНЫ!\n"
        L"========================================\n"
        L"UAC был отключён или ослаблен.\n"
        L"Восстановить безопасные настройки? (Y/N)\n"
        L"Таймаут 30 секунд (по умолчанию: Нет).\n\n";

    DWORD written;
    WriteConsoleW(hConsoleOut, prompt, (DWORD)wcslen(prompt), &written, nullptr);

    std::wstring answer;
    bool answered = false;
    DWORD64 startTick = GetTickCount64();

    while ((GetTickCount64() - startTick) < static_cast<DWORD64>(Config::DIALOG_TIMEOUT_SEC) * 1000) {
        // Проверяем, есть ли ввод
        DWORD events;
        if (WaitForSingleObject(hConsoleIn, 100) == WAIT_OBJECT_0) {
            wchar_t buffer[256] = {0};
            DWORD read;
            if (ReadConsoleW(hConsoleIn, buffer, 255, &read, nullptr) && read > 0) {
                // Убираем символы \r\n в конце
                std::wstring input(buffer, read);
                size_t end = input.find_last_not_of(L"\r\n");
                if (end != std::wstring::npos)
                    input = input.substr(0, end + 1);
                answer = input;
                answered = true;
                break;
            }
        }
        if (g_state.shutdownRequested) break;
    }

    bool consent = false;
    if (answered && (answer == L"Y" || answer == L"y" || answer == L"д" || answer == L"Д" || answer == L"yes" || answer == L"Yes")) {
        consent = true;
        const wchar_t* msgRestore = L"\nВосстанавливаю настройки UAC...\n";
        WriteConsoleW(hConsoleOut, msgRestore, (DWORD)wcslen(msgRestore), &written, nullptr);
    } else {
        const wchar_t* msgCancel = L"\nДействие отменено или истекло время ожидания.\n";
        WriteConsoleW(hConsoleOut, msgCancel, (DWORD)wcslen(msgCancel), &written, nullptr);
    }

    wchar_t msgClose[128];
    swprintf_s(msgClose, L"Окно закроется через %lu секунд...\n", Config::DIALOG_CLOSE_DELAY_SEC);
    WriteConsoleW(hConsoleOut, msgClose, (DWORD)wcslen(msgClose), &written, nullptr);
    Sleep(Config::DIALOG_CLOSE_DELAY_SEC * 1000);

    // Освобождаем консоль
    if (allocated) {
        FreeConsole();
    } else {
        // Открепляемся обратно
        AttachConsole(ATTACH_PARENT_PROCESS);
    }

    g_state.dialogActive = false;
    return consent;
}

// =========================== ПРОВЕРКА И ВОССТАНОВЛЕНИЕ UAC ===========================
bool IsUACIntact() {
    DWORD val;
    if (!GetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"EnableLUA", val) || val != Config::ENABLE_LUA)
        return false;
    if (!GetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"ConsentPromptBehaviorAdmin", val) || val != Config::CONSENT_PROMPT)
        return false;
    if (!GetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"PromptOnSecureDesktop", val) || val != Config::SECURE_DESKTOP)
        return false;
    return true;
}

void RestoreUAC() {
    bool expected = false;
    if (!g_state.restoreInProgress.compare_exchange_strong(expected, true))
        return;

    bool success = true;
    success &= SetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"EnableLUA", Config::ENABLE_LUA);
    success &= SetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"ConsentPromptBehaviorAdmin", Config::CONSENT_PROMPT);
    success &= SetRegistryDword(HKEY_LOCAL_MACHINE, Config::REG_PATH, L"PromptOnSecureDesktop", Config::SECURE_DESKTOP);

    if (success) {
        g_logger.LogInfo(L"Настройки UAC восстановлены.");
        SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Policy",
                            SMTO_ABORTIFHUNG, 2000, nullptr);
    } else {
        g_logger.LogError(L"Не удалось восстановить одну или несколько настроек UAC.");
    }

    g_state.restoreInProgress = false;
}

// =========================== ПОТОК-ОБРАБОТЧИК ===========================
DWORD WINAPI HandlerThreadProc(LPVOID) {
    while (!g_state.shutdownRequested) {
        DWORD waitResult = WaitForSingleObject(g_hUacChangedEvent, 1000);
        if (waitResult == WAIT_OBJECT_0) {
            if (g_state.shutdownRequested || g_state.restoreInProgress) continue;
            if (!IsUACIntact()) {
                g_logger.LogWarning(L"Настройки UAC были изменены.");
                if (ShowDialogAndGetConsent())
                    RestoreUAC();
                else
                    g_logger.LogInfo(L"Пользователь отказался от восстановления.");
            }
        } else if (waitResult != WAIT_TIMEOUT) {
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
            WaitForSingleObject(g_hShutdownEvent, 5000);
            continue;
        }

        SetEvent(g_hUacChangedEvent);

        while (!g_state.shutdownRequested) {
            HANDLE hRegEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (!hRegEvent) break;

            res = RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_LAST_SET, hRegEvent, FALSE);
            if (res != ERROR_SUCCESS) {
                CloseHandle(hRegEvent);
                Sleep(1000);
                SetEvent(g_hUacChangedEvent);
                break;
            }

            HANDLE events[2] = { hRegEvent, g_hShutdownEvent };
            DWORD waitRes = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            CloseHandle(hRegEvent);

            if (waitRes == WAIT_OBJECT_0) {
                SetEvent(g_hUacChangedEvent);
            } else if (waitRes == WAIT_OBJECT_0 + 1) {
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
    g_logger.LogInfo(L"Watchdog запущен. Охраняю PID " + std::to_wstring(parentPid));
    HANDLE hParent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (!hParent) {
        g_logger.LogError(L"Watchdog: не удалось открыть родительский процесс.");
        return;
    }
    WaitForSingleObject(hParent, INFINITE);
    CloseHandle(hParent);

    g_logger.LogWarning(L"Watchdog: родительский процесс завершён. Перезапуск через " +
                        std::to_wstring(Config::WATCHDOG_RESTART_DELAY_SEC) + L" сек...");
    Sleep(Config::WATCHDOG_RESTART_DELAY_SEC * 1000);

    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        g_logger.LogError(L"Watchdog: не удалось получить путь к исполняемому файлу.");
        return;
    }
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
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        g_logger.LogError(L"Не удалось получить путь к исполняемому файлу.");
        return;
    }
    wchar_t cmdLine[MAX_PATH + 30];
    swprintf_s(cmdLine, L"\"%s\" %s %lu", path, Config::WATCHDOG_ARG, parentPid);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        g_hWatchdogProcess = pi.hProcess;  // Сохраняем для возможного аварийного завершения
        CloseHandle(pi.hThread);
        g_logger.LogInfo(L"Watchdog-процесс запущен.");
    } else {
        g_logger.LogError(L"Не удалось запустить watchdog-процесс.");
    }
}

// =========================== ЗАВЕРШЕНИЕ ПОТОКОВ ===========================
void JoinThreads(HANDLE h1, HANDLE h2) {
    // Ждём каждый поток отдельно с таймаутом
    if (WaitForSingleObject(h1, Config::THREAD_JOIN_TIMEOUT_MS) != WAIT_OBJECT_0)
        g_logger.LogWarning(L"Поток 1 не завершился за отведённое время.");
    if (WaitForSingleObject(h2, Config::THREAD_JOIN_TIMEOUT_MS) != WAIT_OBJECT_0)
        g_logger.LogWarning(L"Поток 2 не завершился за отведённое время.");
}

// =========================== ТОЧКА ВХОДА ===========================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // Аргументы командной строки
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc >= 3 && wcscmp(argv[1], Config::WATCHDOG_ARG) == 0) {
        DWORD parentPid = _wtoi(argv[2]);
        LocalFree(argv);
        RunWatchdog(parentPid);
        return 0;
    }
    if (argv) LocalFree(argv);

    // Мьютекс
    HANDLE hMutex = CreateMutexW(nullptr, FALSE, Config::MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        g_logger.LogInfo(L"Другой экземпляр уже запущен. Выхожу.");
        CloseHandle(hMutex);
        return 0;
    }

    // Проверка прав администратора
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size))
            isElevated = elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    if (!isElevated) {
        g_logger.LogError(L"UACGuard требует права администратора. Выхожу.");
        CloseHandle(hMutex);
        return 1;
    }

    g_logger.LogInfo(L"UACGuard v1.0.3 запускается...");

    // Создаём события ДО регистрации обработчика консоли
    g_hUacChangedEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);  // автосброс
    g_hShutdownEvent   = CreateEventW(nullptr, TRUE, FALSE, nullptr);   // ручной сброс
    if (!g_hUacChangedEvent || !g_hShutdownEvent) {
        g_logger.LogError(L"Не удалось создать события синхронизации.");
        CloseHandle(hMutex);
        return 1;
    }

    // Регистрируем обработчик консольных событий
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        g_logger.LogError(L"Не удалось зарегистрировать обработчик консольных событий.");
        // Не критично, продолжаем работу
    }

    // Автозагрузка и watchdog
    InstallAutorun();
    EnsureAutorun();
    LaunchWatchdog(GetCurrentProcessId());

    // Поток проверки автозагрузки
    std::thread autoRunThread([]() {
        while (!g_state.shutdownRequested) {
            if (WaitForSingleObject(g_hShutdownEvent, Config::AUTORUN_CHECK_SEC * 1000) == WAIT_OBJECT_0)
                break;
            EnsureAutorun();
        }
    });

    // Рабочие потоки
    HANDLE hMonitorThread = CreateThread(nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr);
    HANDLE hHandlerThread = CreateThread(nullptr, 0, HandlerThreadProc, nullptr, 0, nullptr);
    if (!hMonitorThread || !hHandlerThread) {
        g_logger.LogError(L"Не удалось запустить рабочие потоки.");
        // Watchdog не убиваем, он перезапустит программу с задержкой
        g_state.shutdownRequested = true;
        SetEvent(g_hShutdownEvent);
        JoinThreads(hMonitorThread, hHandlerThread);
        CloseHandle(hMutex);
        // Закрываем дескриптор watchdog перед выходом
        if (g_hWatchdogProcess) {
            CloseHandle(g_hWatchdogProcess);
            g_hWatchdogProcess = nullptr;
        }
        return 1;
    }

    // Главный поток ждёт завершения рабочих потоков (бесконечно, пока не придёт сигнал shutdown)
    HANDLE threads[] = { hMonitorThread, hHandlerThread };
    WaitForMultipleObjects(2, threads, FALSE, INFINITE);

    // Если дошли сюда — инициируем завершение
    g_state.shutdownRequested = true;
    SetEvent(g_hShutdownEvent);

    JoinThreads(hMonitorThread, hHandlerThread);

    if (autoRunThread.joinable())
        autoRunThread.join();

    CloseHandle(hMonitorThread);
    CloseHandle(hHandlerThread);
    CloseHandle(hMutex);
    CloseHandle(g_hShutdownEvent);
    CloseHandle(g_hUacChangedEvent);

    // Закрываем дескриптор watchdog (watchdog остаётся жив, он перезапустит нас при необходимости)
    if (g_hWatchdogProcess) {
        CloseHandle(g_hWatchdogProcess);
        g_hWatchdogProcess = nullptr;
    }

    g_logger.LogInfo(L"UACGuard завершил работу (будет перезапущен watchdog'ом при падении).");
    return 0;
}