/*
Copyright (C) 2026 Mikhail Pilin

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

#undef  _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#include <sdkddkver.h>

#include <windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <stdexcept>
#include <format>
#include <optional>
#include <string>

namespace ww898 {
template <class F>
struct on_exit_scope
{
    template <class F2>
    on_exit_scope(F2 && f) : f(std::forward<F2>(f))
    {
    }

    on_exit_scope(on_exit_scope &&) = delete;
    on_exit_scope & operator=(on_exit_scope &&) = delete;

    on_exit_scope(on_exit_scope const &) = delete;
    on_exit_scope & operator=(on_exit_scope const &) = delete;

    ~on_exit_scope()
    {
        try
        {
            std::move(f)();
        }
        catch (...)
        {
        }
    }

private:
    F f;
};

template <class F>
on_exit_scope<std::decay_t<F>> make_on_exit_scope(F && f)
{
    return {std::forward<F>(f)};
}

DWORD get_shell_pid()
{
    DWORD pid;
    DWORD const tid = GetWindowThreadProcessId(GetShellWindow(), &pid);
    if (tid == 0)
        throw std::runtime_error(std::format("Can't get shell process identifier: {}", GetLastError()));

    std::wcout << L"Use shell process identifier: " << pid << std::endl;
    return pid;
}

std::optional<std::wstring> get_environment_variable(wchar_t const * const name)
{
    size_t size;
    if (auto err = _wgetenv_s(&size, nullptr, 0, name))
        throw std::runtime_error(std::format("Can't get buffer size for environment variable: {}", err));
    if (size == 0)
        return {};
    auto const str = std::make_unique<wchar_t[]>(size);
    if (auto err = _wgetenv_s(&size, str.get(), size, name))
        throw std::runtime_error(std::format("Can't get environment variable: {}", err));
    return str.get();
}

DWORD parse_pid(std::wstring const & str)
{
    size_t processed;
    auto const pid = std::stoul(str, &processed);
    if (processed != str.size())
        throw std::runtime_error("Incorrect pid format");
    return pid;
}

void create_process(DWORD const ppid, std::wstring cmd)
{
    HANDLE handle = OpenProcess(PROCESS_CREATE_PROCESS, false, ppid);
    if (!handle)
        throw std::runtime_error("Can't open process by process identifier");
    auto on_exit_parent_process_handle = make_on_exit_scope([=]() noexcept { CloseHandle(handle); });

    SIZE_T attribute_list_size;
    if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_list_size))
    {
        DWORD const error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER)
            throw std::runtime_error(std::format("Can't get attribute list size: {}", error));
    }

    LPVOID const raw_attribute_list = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attribute_list_size);
    auto on_exit_raw_attribute_list = make_on_exit_scope([=]() noexcept { HeapFree(GetProcessHeap(), 0, raw_attribute_list); });

    auto const attribute_list = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(raw_attribute_list);

    if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_list_size))
        throw std::runtime_error(std::format("Can't initialize attributes list: {}", GetLastError()));
    auto on_exit_attribute_list = make_on_exit_scope([=]() noexcept { DeleteProcThreadAttributeList(attribute_list); });

    if (!UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &handle, sizeof(HANDLE), nullptr, nullptr))
        throw std::runtime_error(std::format("Can't update attributes list: {}", GetLastError()));

    STARTUPINFOEXW si = {.StartupInfo = {.cb = sizeof(STARTUPINFOEXW)}, .lpAttributeList = attribute_list};
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, false, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi))
        throw std::runtime_error(std::format("Can't create process: {}", GetLastError()));
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
}

int wmain()
{
    try
    {
        auto const cmd_env = ww898::get_environment_variable(L"PPID_SPOOFER_CMD");
        auto const ppid_env = ww898::get_environment_variable(L"PPID_SPOOFER_PPID");

        ww898::create_process(
            !!ppid_env && ppid_env != L"auto" ? ww898::parse_pid(ppid_env.value()) : ww898::get_shell_pid(),
            !!cmd_env ? cmd_env.value() : throw std::runtime_error("The command line environment variable should be defined"));
        return 0;
    }
    catch (std::exception const & e)
    {
        std::cout << "ERROR: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cout << "ERROR: Unknown error" << std::endl;
        return 1;
    }
}
