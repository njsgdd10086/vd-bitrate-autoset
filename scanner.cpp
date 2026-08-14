#include "scanner.h"
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <set>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

bool EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(hToken);
    // 非管理员会返回 ERROR_NOT_ALL_ASSIGNED(属预期)：同用户进程无需该特权即可附加。
    // 这里只返回是否真正启用，供调用方判断；附加失败时 main.cpp 会给出权限提示。
    return err == ERROR_SUCCESS;
}

uintptr_t ParseNum(const std::wstring& s)
{
    std::wstring t = s;
    if (t.size() > 2 && t[0] == L'0' && (t[1] == L'x' || t[1] == L'X'))
        t = t.substr(2);
    bool hex = false;
    for (wchar_t c : t)
        if ((c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))
            hex = true;
    return hex ? wcstoull(t.c_str(), nullptr, 16)
               : wcstoull(t.c_str(), nullptr, 10);
}

}  // namespace

std::wstring PtrPath::ToString() const
{
    wchar_t buf[256];
    swprintf_s(buf, _countof(buf), L"%s+0x%llX", module.c_str(),
               static_cast<unsigned long long>(baseOffset));
    std::wstring s = buf;
    for (uintptr_t h : hops) {
        swprintf_s(buf, _countof(buf), L":0x%llX",
                   static_cast<unsigned long long>(h));
        s += buf;
    }
    return s;
}

bool PtrPath::Parse(const std::wstring& text, PtrPath& out)
{
    std::vector<std::wstring> parts;
    std::wstring rest = text;
    size_t pos = 0;
    while ((pos = rest.find(L':')) != std::wstring::npos) {
        parts.push_back(rest.substr(0, pos));
        rest.erase(0, pos + 1);
    }
    parts.push_back(rest);
    if (parts.empty())
        return false;

    const std::wstring& first = parts[0];
    const size_t plus = first.find(L'+');
    if (plus == std::wstring::npos || plus == 0)
        return false;
    out.module = first.substr(0, plus);
    out.baseOffset = ParseNum(first.substr(plus + 1));
    out.hops.clear();
    for (size_t i = 1; i < parts.size(); ++i)
        out.hops.push_back(ParseNum(parts[i]));
    return true;
}

VdScanner::VdScanner(DWORD pid) : pid_(pid) {}

VdScanner::~VdScanner()
{
    if (h_) CloseHandle(h_);
}

bool VdScanner::Attach()
{
    EnableDebugPrivilege();
    h_ = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                         PROCESS_QUERY_INFORMATION,
                     FALSE, pid_);
    if (!h_)
        return false;
    CollectModules();
    CollectRegions();
    return !modules_.empty();
}

void VdScanner::CollectModules()
{
    DWORD needed = 0;
    if (!EnumProcessModules(h_, nullptr, 0, &needed))
        return;
    std::vector<HMODULE> mods(needed / sizeof(HMODULE));
    if (!EnumProcessModules(h_, mods.data(), needed, &needed))
        return;

    for (HMODULE m : mods) {
        wchar_t name[MAX_PATH]{};
        if (!GetModuleBaseNameW(h_, m, name, MAX_PATH))
            continue;
        MODULEINFO mi{};
        if (!GetModuleInformation(h_, m, &mi, sizeof(mi)))
            continue;
        modules_.push_back({ reinterpret_cast<uintptr_t>(mi.lpBaseOfDll),
                             mi.SizeOfImage, name });
    }

    for (const auto& m : modules_) {
        if (_wcsicmp(m.name.c_str(), L"virtualdesktop.streamer.exe") == 0) {
            moduleBase_ = m.base;
            moduleSize_ = m.size;
            moduleName_ = m.name;
            break;
        }
    }
    if (moduleBase_ == 0 && !modules_.empty()) {
        moduleBase_ = modules_[0].base;
        moduleSize_ = modules_[0].size;
        moduleName_ = modules_[0].name;
    }

    // 按基址排序，后续 ModuleAt / 区域重叠判定用二分查找
    std::sort(modules_.begin(), modules_.end(),
              [](const ModInfo& a, const ModInfo& b) { return a.base < b.base; });
}

void VdScanner::CollectRegions()
{
    regions_.clear();
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQueryEx(h_, reinterpret_cast<LPCVOID>(addr), &mbi,
                          sizeof(mbi)) == sizeof(mbi)) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        addr = base + mbi.RegionSize;
        if (mbi.RegionSize == 0 || addr <= base)
            break;
        if (mbi.State != MEM_COMMIT)
            continue;
        const DWORD p = mbi.Protect;
        if (p & (PAGE_GUARD | PAGE_NOACCESS))
            continue;
        const bool readable = (p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                    PAGE_EXECUTE_WRITECOPY)) != 0;
        if (!readable)
            continue;
        regions_.push_back({ base, mbi.RegionSize });
    }
}

const VdScanner::ModInfo* VdScanner::ModuleAt(uintptr_t addr) const
{
    // modules_ 已按 base 排序，二分定位包含 addr 的模块
    auto it = std::upper_bound(modules_.begin(), modules_.end(), addr,
        [](uintptr_t a, const ModInfo& m) { return a < m.base; });
    if (it == modules_.begin())
        return nullptr;
    --it;
    if (addr < it->base + it->size)
        return &(*it);
    return nullptr;
}

std::vector<ScanMatch> VdScanner::ScanValue(uint32_t value, size_t maxResults,
                                            bool* truncated) const
{
    std::vector<ScanMatch> out;
    if (truncated)
        *truncated = false;
    std::vector<uint8_t> buf(64 * 1024);
    for (const Region& r : regions_) {
        for (SIZE_T off = 0; off < r.size; off += buf.size()) {
            const SIZE_T n = (std::min)(buf.size(), r.size - off);
            SIZE_T rd = 0;
            if (!ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(r.base + off),
                                   buf.data(), n, &rd) || rd < 4)
                continue;
            for (SIZE_T i = 0; i + 3 < rd; ++i) {
                uint32_t v = 0;
                std::memcpy(&v, buf.data() + i, sizeof(v));
                if (v == value) {
                    out.push_back({ r.base + off + i, v });
                    if (maxResults && out.size() >= maxResults) {
                        if (truncated)
                            *truncated = true;
                        return out;
                    }
                }
            }
        }
    }
    return out;
}

bool VdScanner::Read32(uintptr_t addr, uint32_t* out) const
{
    SIZE_T rd = 0;
    return ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(addr), out,
                             sizeof(*out), &rd) && rd == sizeof(*out);
}

bool VdScanner::Write32(uintptr_t addr, uint32_t v) const
{
    SIZE_T wb = 0;
    return WriteProcessMemory(h_, reinterpret_cast<LPVOID>(addr), &v,
                              sizeof(v), &wb) && wb == sizeof(v);
}

std::vector<PtrPath> VdScanner::FindPointerPaths(uintptr_t leaf, int maxDepth,
                                                 size_t maxNodes,
                                                 DWORD timeLimitMs,
                                                 PtrScanProgress progress,
                                                 void* progressCtx) const
{
    constexpr uintptr_t kMaxOff = 0x10000;  // 指针与目标地址的最大间距(64KB)
    struct Node {
        uintptr_t loc;
        std::vector<uintptr_t> hops;  // 从本节点到 leaf 的每跳偏移
    };

    std::vector<PtrPath> result;
    std::vector<Node> targets{ { leaf, {} } };
    std::set<uintptr_t> visited;
    std::vector<uint8_t> buf(64 * 1024);
    const ULONGLONG t0 = GetTickCount64();

    // 标记哪些区域属于模块映像——优先扫它们(根指针一定在模块里)。
    // modules_ 已按 base 排序，用二分判断区域是否与任一模块重叠。
    std::vector<uint8_t> inModule(regions_.size(), 0);
    for (size_t ri = 0; ri < regions_.size(); ++ri) {
        const Region& r = regions_[ri];
        auto it = std::lower_bound(modules_.begin(), modules_.end(), r.base,
            [](const ModInfo& m, uintptr_t a) { return m.base < a; });
        if (it != modules_.end() && it->base < r.base + r.size) {
            inModule[ri] = 1;
        } else if (it != modules_.begin()) {
            --it;
            if (r.base < it->base + it->size)
                inModule[ri] = 1;
        }
    }

    const auto overBudget = [&]() {
        return timeLimitMs &&
               GetTickCount64() - t0 >
                   static_cast<ULONGLONG>(timeLimitMs);
    };

    // 单趟多目标：每个区域每层只读一遍，同时匹配所有目标节点(受 maxNodes 上限，
    // 目标数通常 ≤8)，相比"逐节点全量重扫"可减少数倍的 ReadProcessMemory。
    for (int depth = 1; depth <= maxDepth && !targets.empty(); ++depth) {
        if (progress)
            progress(progressCtx, depth, targets.size(),
                     static_cast<DWORD>(GetTickCount64() - t0));
        std::vector<Node> next;
        for (int pass = 0; pass < 2 && !overBudget(); ++pass) {
            for (size_t ri = 0; ri < regions_.size() && !overBudget(); ++ri) {
                if ((inModule[ri] != 0) != (pass == 0))
                    continue;
                const Region& r = regions_[ri];
                for (SIZE_T off = 0; off < r.size && !overBudget();
                     off += buf.size()) {
                    const SIZE_T n = (std::min)(buf.size(), r.size - off);
                    SIZE_T rd = 0;
                    if (!ReadProcessMemory(h_,
                                           reinterpret_cast<LPCVOID>(r.base + off),
                                           buf.data(), n, &rd) || rd < 8)
                        continue;
                    // x64 下指针按 8 字节对齐存储，按对齐步进可省约 8 倍比较，
                    // 并避免大量未对齐假候选逐层放大。
                    for (SIZE_T i = 0; i + 7 < rd; i += 8) {
                        uintptr_t q = 0;
                        std::memcpy(&q, buf.data() + i, sizeof(q));
                        const uintptr_t loc = r.base + off + i;
                        if (visited.count(loc))
                            continue;
                        bool matched = false;
                        for (const Node& t : targets) {
                            const uintptr_t lo =
                                (t.loc > kMaxOff) ? t.loc - kMaxOff : 0;
                            if (q < lo || q > t.loc)
                                continue;
                            matched = true;
                            const uintptr_t gap = t.loc - q;
                            std::vector<uintptr_t> hops;
                            hops.reserve(t.hops.size() + 1);
                            hops.push_back(gap);
                            hops.insert(hops.end(), t.hops.begin(),
                                        t.hops.end());

                            if (const ModInfo* m = ModuleAt(loc)) {
                                PtrPath p;
                                p.module     = m->name;
                                p.baseOffset = loc - m->base;
                                p.hops       = hops;
                                result.push_back(std::move(p));
                            } else if (next.size() < maxNodes) {
                                next.push_back({ loc, std::move(hops) });
                            }
                        }
                        if (matched)
                            visited.insert(loc);
                    }
                }
            }
        }
        targets = std::move(next);
        if (result.size() >= 500)
            break;
    }
    return result;
}

bool VdScanner::Resolve(const PtrPath& path, uintptr_t* finalAddr) const
{
    const ModInfo* m = nullptr;
    for (const auto& mi : modules_)
        if (_wcsicmp(mi.name.c_str(), path.module.c_str()) == 0) {
            m = &mi;
            break;
        }
    if (!m)
        return false;

    uintptr_t addr = m->base + path.baseOffset;
    for (uintptr_t hop : path.hops) {
        uintptr_t q = 0;
        SIZE_T rd = 0;
        if (!ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(addr), &q,
                               sizeof(q), &rd) || rd != sizeof(q))
            return false;
        addr = q + hop;
    }
    *finalAddr = addr;
    return true;
}
