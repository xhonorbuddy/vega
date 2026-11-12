#include <windows.h>
#include <TlHelp32.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

import manualmap.mmap;

namespace {

    constexpr int kExitSuccess = 0;
    constexpr int kExitUsage = 1;
    constexpr int kExitMapFailed = 2;
    constexpr int kExitUnloadFailed = 3;

    struct CommandLine {
        std::string process;
        std::string dll;
        std::string module;
        DWORD pid = 0;
        DWORD wait_seconds = 0;
        DWORD timeout_ms = 60'000;
        bool unload = false;
        bool list = false;
        bool quiet = false;
        bool tls = true;
        bool exceptions = true;
        bool preferred_base = true;
        bool entry_point = true;
        bool loader_entry = false;
        bool hijack = false;
        bool force = false;
        DWORD ddag_state = 9;
        bool help = false;
    };

    void print_usage() {
        std::printf(
            "vega - x64 manual mapper\n"
            "\n"
            "Usage:\n"
            "  vega --process <name> --dll <path> [options]   map a DLL\n"
            "  vega --process <name> --unload [--module <name>]  unload a mapped DLL\n"
            "  vega --process <name> --list                  list mapped modules\n"
            "\n"
            "Required (map):\n"
            "  -p, --process <name>   target process image name, e.g. game.exe\n"
            "  -d, --dll <path>       DLL to map, absolute or relative\n"
            "\n"
            "Required (unload / list):\n"
            "  -p, --process <name>   target process image name\n"
            "\n"
            "Options:\n"
            "  -u, --unload           unload a previously mapped module\n"
            "  -m, --module <name>    module name for --unload (default: DLL file name)\n"
            "      --list             list modules this tool mapped into the process\n"
            "      --pid <pid>        target by process id instead of image name\n"
            "      --wait <seconds>   wait for the process to appear (default: 0)\n"
            "      --timeout <ms>     timeout per in-target call (default: 60000)\n"
            "      --no-tls           skip TLS callback execution\n"
            "      --no-exceptions    skip exception (.pdata) table registration\n"
            "      --no-preferred     ignore the DLL's preferred base (force relocation)\n"
            "      --no-entry         map without calling DllMain (debugging aid)\n"
            "      --loader-entry     also link the image into the loader list (experimental)\n"
            "      --hijack           run in-target calls on an existing thread\n"
            "      --force            unload even if a thread is inside the image\n"
            "      --ddag-state <n>   Ddag node state used by --loader-entry (default 9)\n"
            "  -q, --quiet            print only errors\n"
            "  -h, --help             show this help\n"
            "\n"
            "Exit codes: 0 success, 1 usage, 2 mapping failed, 3 unload failed\n"
        );
    }

    [[nodiscard]] bool process_is_running(std::string_view process_name) {
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        bool found = false;

        if (Process32FirstW(snapshot, &entry)) {
            do {
                const std::wstring wide_name = entry.szExeFile;

                if (_wcsicmp(wide_name.c_str(), std::wstring(process_name.begin(), process_name.end()).c_str()) == 0) {
                    found = true;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return found;
    }

    [[nodiscard]] bool parse_command_line(int argc, char** argv, CommandLine& command) {
        for (int index = 1; index < argc; ++index) {
            const std::string_view argument = argv[index];

            auto require_value = [&](std::string& destination) -> bool {
                if (index + 1 >= argc) {
                    std::printf("error: %.*s requires a value\n", static_cast<int>(argument.size()), argument.data());
                    return false;
                }

                destination = argv[++index];
                return !destination.empty();
                };

            if (argument == "-p" || argument == "--process") {
                if (!require_value(command.process)) {
                    return false;
                }
            }
            else if (argument == "-d" || argument == "--dll") {
                if (!require_value(command.dll)) {
                    return false;
                }
            }
            else if (argument == "-m" || argument == "--module") {
                if (!require_value(command.module)) {
                    return false;
                }
            }
            else if (argument == "-u" || argument == "--unload") {
                command.unload = true;
            }
            else if (argument == "--list") {
                command.list = true;
            }
            else if (argument == "-q" || argument == "--quiet") {
                command.quiet = true;
            }
            else if (argument == "--no-tls") {
                command.tls = false;
            }
            else if (argument == "--no-exceptions") {
                command.exceptions = false;
            }
            else if (argument == "--no-preferred") {
                command.preferred_base = false;
            }
            else if (argument == "--no-entry") {
                command.entry_point = false;
            }
            else if (argument == "--loader-entry") {
                command.loader_entry = true;
            }
            else if (argument == "--hijack") {
                command.hijack = true;
            }
            else if (argument == "--force") {
                command.force = true;
            }
            else if (argument == "--ddag-state") {
                std::string value;

                if (!require_value(value)) {
                    return false;
                }

                command.ddag_state = static_cast<DWORD>(std::strtoul(value.c_str(), nullptr, 10));
            }
            else if (argument == "-h" || argument == "--help") {
                command.help = true;
            }
            else if (argument == "--pid") {
                std::string value;

                if (!require_value(value)) {
                    return false;
                }

                command.pid = static_cast<DWORD>(std::strtoul(value.c_str(), nullptr, 10));
            }
            else if (argument == "--wait") {
                std::string value;

                if (!require_value(value)) {
                    return false;
                }

                command.wait_seconds = static_cast<DWORD>(std::strtoul(value.c_str(), nullptr, 10));
            }
            else if (argument == "--timeout") {
                std::string value;

                if (!require_value(value)) {
                    return false;
                }

                command.timeout_ms = static_cast<DWORD>(std::strtoul(value.c_str(), nullptr, 10));
            }
            else {
                std::printf("error: unknown argument %.*s\n", static_cast<int>(argument.size()), argument.data());
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] std::string basename_of(const std::string& path) {
        return std::filesystem::path(path).filename().string();
    }

    [[nodiscard]] manualmap::MapOptions make_map_options(const CommandLine& command, int padding = 0) {
        manualmap::MapOptions options;
        options.verbose = !command.quiet;
        options.print_padding = padding;
        options.call_tls_callbacks = command.tls;
        options.register_exception_table = command.exceptions;
        options.resolve_delay_imports = true;
        options.prefer_preferred_base = command.preferred_base;
        options.call_entry_point = command.entry_point;
        options.register_loader_entry = command.loader_entry;
        options.thread_hijack = command.hijack;
        options.force = command.force;
        options.ddag_state = command.ddag_state;
        options.call_timeout_ms = command.timeout_ms;
        return options;
    }

    int map_command(CommandLine& command) {
        if (command.process.empty() && command.pid == 0) {
            std::printf("error: --process or --pid is required\n");
            return kExitUsage;
        }

        if (command.dll.empty()) {
            std::printf("error: --dll is required when mapping\n");
            return kExitUsage;
        }

        if (command.wait_seconds != 0 && command.pid == 0) {
            for (DWORD elapsed = 0; elapsed < command.wait_seconds; ++elapsed) {
                if (process_is_running(command.process)) {
                    break;
                }

                Sleep(1000);
            }
        }

        manualmap::Mmap mapper;

        try {
            const manualmap::MappedModule module = mapper.map_dll(
                command.process,
                command.dll,
                make_map_options(command)
            );

            if (!command.quiet) {
                std::printf(
                    "\n[+] Mapped %s\n    base:        0x%llx\n    image size:  0x%zx\n    entry point: 0x%llx\n",
                    module.name.c_str(),
                    static_cast<unsigned long long>(module.base),
                    module.image_size,
                    static_cast<unsigned long long>(module.entry_point)
                );
            }

            return kExitSuccess;
        }
        catch (const manualmap::MapError& error) {
            std::printf("error: %s\n", error.what());
            return kExitMapFailed;
        }
        catch (const std::exception& error) {
            std::printf("error: unexpected failure: %s\n", error.what());
            return kExitMapFailed;
        }
    }

    int unload_command(CommandLine& command) {
        if (command.process.empty() && command.pid == 0) {
            std::printf("error: --process or --pid is required\n");
            return kExitUsage;
        }

        std::string module_name = command.module;

        if (module_name.empty() && !command.dll.empty()) {
            module_name = basename_of(command.dll);
        }

        manualmap::Mmap mapper;

        try {
            const std::size_t unloaded = mapper.unload_module(
                command.process,
                module_name,
                make_map_options(command)
            );

            if (unloaded == 0) {
                std::printf("error: no mapped module%s found in %s\n",
                    module_name.empty() ? "" : (" named '" + module_name + "'").c_str(),
                    command.process.c_str()
                );
                return kExitUnloadFailed;
            }

            if (!command.quiet) {
                std::printf("\n[+] Unloaded %zu module(s)\n", unloaded);
            }

            return kExitSuccess;
        }
        catch (const std::exception& error) {
            std::printf("error: %s\n", error.what());
            return kExitUnloadFailed;
        }
    }

    int list_command(CommandLine& command) {
        if (command.process.empty() && command.pid == 0) {
            std::printf("error: --process or --pid is required\n");
            return kExitUsage;
        }

        manualmap::Mmap mapper;

        try {
            const auto modules = mapper.list_modules(command.process);

            if (modules.empty()) {
                std::printf("No modules mapped by vega in %s\n", command.process.c_str());
                return kExitSuccess;
            }

            std::printf("%-32s %-18s %-12s\n", "module", "base", "size");

            for (const auto& module : modules) {
                std::printf("%-32s 0x%-16llx 0x%-10zx\n",
                    module.name.c_str(),
                    static_cast<unsigned long long>(module.base),
                    module.image_size
                );
            }

            return kExitSuccess;
        }
        catch (const std::exception& error) {
            std::printf("error: %s\n", error.what());
            return kExitMapFailed;
        }
    }

} // namespace

int main(int argc, char** argv) {
    CommandLine command;

    if (argc <= 1) {
        print_usage();
        return kExitUsage;
    }

    if (!parse_command_line(argc, argv, command)) {
        return kExitUsage;
    }

    if (command.help) {
        print_usage();
        return kExitSuccess;
    }

    if (command.list) {
        return list_command(command);
    }

    if (command.unload) {
        return unload_command(command);
    }

    return map_command(command);
}