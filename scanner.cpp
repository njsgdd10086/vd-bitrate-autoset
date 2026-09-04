#include "scanner.h"
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cwchar>
#include <limits>
#include <numeric>
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

bool ParseNum(const std::wstring& s, uintptr_t* out)
{
    if (s.empty() || !out)
        return false;
    std::wstring t = s;
    bool hex = false;
    if (t.size() > 2 && t[0] == L'0' && (t[1] == L'x' || t[1] == L'X')) {
        hex = true;
        t = t.substr(2);
    }
    if (t.empty())
        return false;
    for (wchar_t c : t) {
        const bool digit = (c >= L'0' && c <= L'9') ||
                           (c >= L'a' && c <= L'f') ||
                           (c >= L'A' && c <= L'F');
        if (!digit)
            return false;
        if ((c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))
            hex = true;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long v = wcstoull(t.c_str(), &end, hex ? 16 : 10);
    if (errno == ERANGE || !end || *end != L'\0' ||
        v > (std::numeric_limits<uintptr_t>::max)())
        return false;
    *out = static_cast<uintptr_t>(v);
    return true;
}

bool IsWritableProtect(DWORD protect)
{
    return (protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
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
    constexpr size_t kMaxPathHops = 32;
    constexpr size_t kMaxModuleName = 260;
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
    if (out.module.empty() || out.module.size() > kMaxModuleName ||
        parts.size() - 1 > kMaxPathHops ||
        !ParseNum(first.substr(plus + 1), &out.baseOffset))
        return false;
    out.hops.clear();
    for (size_t i = 1; i < parts.size(); ++i)
    {
        uintptr_t hop = 0;
        if (!ParseNum(parts[i], &hop))
            return false;
        out.hops.push_back(hop);
    }
    return true;
}

VdScanner::VdScanner(DWORD pid) : pid_(pid) {}

VdScanner::~VdScanner()
{
    if (h_) CloseHandle(h_);
}

bool VdScanner::Attach()
{
    if (h_) {
        CloseHandle(h_);
        h_ = nullptr;
    }
    modules_.clear();
    regions_.clear();
    moduleBase_ = 0;
    moduleSize_ = 0;
    moduleName_.clear();
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
        regions_.push_back({ base, mbi.RegionSize, mbi.Protect, mbi.Type });
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
    if (it->size <= (std::numeric_limits<uintptr_t>::max)() - it->base &&
        addr < it->base + it->size)
        return &(*it);
    return nullptr;
}

std::vector<ScanMatch> VdScanner::ScanValue(uint32_t value, size_t maxResults,
                                             bool* truncated,
                                             CancelCheck cancel,
                                             void* cancelCtx) const
{
    std::vector<ScanMatch> out;
    if (truncated)
        *truncated = false;
    constexpr SIZE_T kChunk = 64 * 1024;
    std::vector<uint8_t> buf(kChunk + sizeof(uint32_t) - 1);
    for (const Region& r : regions_) {
        if (cancel && cancel(cancelCtx))
            break;
        SIZE_T off = 0;
        SIZE_T carry = 0;
        while (off < r.size) {
            if (cancel && cancel(cancelCtx))
                return out;
            const SIZE_T n = (std::min)(kChunk, r.size - off);
            SIZE_T rd = 0;
            const bool ok = ReadProcessMemory(
                h_, reinterpret_cast<LPCVOID>(r.base + off),
                buf.data() + carry, n, &rd);
            if (!ok && rd == 0) {
                off += n;
                carry = 0;
                continue;
            }
            if (rd == 0) {
                off += n;
                carry = 0;
                continue;
            }
            const SIZE_T total = carry + rd;
            const uintptr_t chunkBase = r.base + off - carry;
            for (SIZE_T i = 0; i + sizeof(uint32_t) <= total; ++i) {
                uint32_t v = 0;
                std::memcpy(&v, buf.data() + i, sizeof(v));
                if (v == value) {
                    out.push_back({ chunkBase + i, v });
                    if (maxResults && out.size() >= maxResults) {
                        if (truncated)
                            *truncated = true;
                        return out;
                    }
                }
            }
            off += rd;
            carry = (std::min)(sizeof(uint32_t) - 1, total);
            if (carry)
                std::memmove(buf.data(), buf.data() + total - carry, carry);
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

std::vector<uintptr_t> VdScanner::FindValuePatterns(
    uint32_t value, const std::vector<uintptr_t>& offsets, size_t maxGroups,
    bool* truncated, CancelCheck cancel, void* cancelCtx) const
{
    std::vector<uintptr_t> groups;
    if (truncated)
        *truncated = false;
    if (offsets.empty())
        return groups;

    bool hasZero = false;
    uintptr_t maxOffset = 0;
    for (uintptr_t off : offsets) {
        if (off == 0)
            hasZero = true;
        if (off > maxOffset)
            maxOffset = off;
    }
    if (!hasZero || maxOffset > (std::numeric_limits<uintptr_t>::max)() - sizeof(uint32_t))
        return groups;

    std::vector<ScanMatch> matches =
        ScanValue(value, 0, nullptr, cancel, cancelCtx);
    if (cancel && cancel(cancelCtx))
        return groups;
    std::sort(matches.begin(), matches.end(),
              [](const ScanMatch& a, const ScanMatch& b) {
                  return a.addr < b.addr;
              });
    matches.erase(std::unique(matches.begin(), matches.end(),
                              [](const ScanMatch& a, const ScanMatch& b) {
                                  return a.addr == b.addr;
                              }),
                  matches.end());
    std::vector<uintptr_t> addresses;
    addresses.reserve(matches.size());
    for (const ScanMatch& m : matches)
        addresses.push_back(m.addr);

    auto writable = [&](uintptr_t addr) {
        for (const Region& r : regions_) {
            if (addr < r.base)
                continue;
            const uintptr_t delta = addr - r.base;
            if (delta <= r.size && sizeof(uint32_t) <= r.size - delta)
                return IsWritableProtect(r.protect);
        }
        return false;
    };

    for (uintptr_t base : addresses) {
        if (cancel && cancel(cancelCtx))
            break;
        if (!writable(base))
            continue;
        bool found = true;
        for (uintptr_t off : offsets) {
            if (off > (std::numeric_limits<uintptr_t>::max)() - base) {
                found = false;
                break;
            }
            const uintptr_t addr = base + off;
            if (!std::binary_search(addresses.begin(), addresses.end(), addr) ||
                !writable(addr)) {
                found = false;
                break;
            }
        }
        if (!found)
            continue;
        if (maxGroups && groups.size() >= maxGroups) {
            if (truncated)
                *truncated = true;
            break;
        }
        groups.push_back(base);
    }
    return groups;
}

std::vector<PtrPath> VdScanner::FindPointerPaths(uintptr_t leaf, int maxDepth,
                                                 size_t maxNodes,
                                                 DWORD timeLimitMs,
                                                 PtrScanProgress progress,
                                                 void* progressCtx,
                                                 CancelCheck cancel,
                                                 void* cancelCtx,
                                                 PtrScanStats* stats,
                                                 bool scanUnaligned) const
{
    constexpr uintptr_t kMaxOff = 0x10000;  // 指针与目标地址的最大间距(64KB)
    struct Node {
        uintptr_t loc;
        std::vector<uintptr_t> hops;  // 从本节点到 leaf 的每跳偏移
    };

    if (stats) {
        *stats = {};
        stats->unaligned = scanUnaligned;
    }
    std::vector<PtrPath> result;
    std::vector<Node> targets{ { leaf, {} } };
    std::set<uintptr_t> visited;
    constexpr SIZE_T kChunk = 64 * 1024;
    constexpr SIZE_T kCarry = sizeof(uintptr_t) - 1;
    std::vector<uint8_t> buf(kChunk + kCarry);
    const ULONGLONG t0 = GetTickCount64();

    // 标记哪些区域属于模块映像——优先扫它们(根指针一定在模块里)。
    // modules_ 已按 base 排序，用二分判断区域是否与任一模块重叠。
    std::vector<uint8_t> inModule(regions_.size(), 0);
    for (size_t ri = 0; ri < regions_.size(); ++ri) {
        const Region& r = regions_[ri];
        auto it = std::lower_bound(modules_.begin(), modules_.end(), r.base,
            [](const ModInfo& m, uintptr_t a) { return m.base < a; });
        const uintptr_t rEnd =
            (r.size <= (std::numeric_limits<uintptr_t>::max)() - r.base)
                ? r.base + r.size : (std::numeric_limits<uintptr_t>::max)();
        if (it != modules_.end() && it->base < rEnd) {
            inModule[ri] = 1;
        } else if (it != modules_.begin()) {
            --it;
            if (it->size <= (std::numeric_limits<uintptr_t>::max)() - it->base &&
                r.base < it->base + it->size)
                inModule[ri] = 1;
        }
    }

    const auto overBudget = [&]() {
        return (cancel && cancel(cancelCtx)) ||
               (timeLimitMs &&
               GetTickCount64() - t0 >
                   static_cast<ULONGLONG>(timeLimitMs));
    };

    // 单趟多目标：每个区域每层只读一遍；目标按地址排序后用区间查找，
    // 即使扩大 maxNodes 也不会退化为“每个内存槽都和所有目标比较”。
    for (int depth = 1; depth <= maxDepth && !targets.empty(); ++depth) {
        if (stats)
            stats->levels = static_cast<size_t>(depth);
        if (progress)
            progress(progressCtx, depth, targets.size(),
                     static_cast<DWORD>(GetTickCount64() - t0));
        std::vector<Node> next;
        std::vector<size_t> targetOrder(targets.size());
        std::iota(targetOrder.begin(), targetOrder.end(), size_t{0});
        std::sort(targetOrder.begin(), targetOrder.end(),
                  [&](size_t a, size_t b) {
                      return targets[a].loc < targets[b].loc;
                  });
        for (int pass = 0; pass < 2 && !overBudget(); ++pass) {
            for (size_t ri = 0; ri < regions_.size() && !overBudget(); ++ri) {
                if ((inModule[ri] != 0) != (pass == 0))
                    continue;
                const Region& r = regions_[ri];
                SIZE_T off = 0;
                SIZE_T carry = 0;
                while (off < r.size && !overBudget()) {
                    const SIZE_T n = (std::min)(kChunk, r.size - off);
                    SIZE_T rd = 0;
                    const bool ok = ReadProcessMemory(
                        h_, reinterpret_cast<LPCVOID>(r.base + off),
                        buf.data() + carry, n, &rd);
                    if (!ok && rd == 0) {
                        off += n;
                        carry = 0;
                        continue;
                    }
                    if (rd == 0) {
                        off += n;
                        carry = 0;
                        continue;
                    }
                    const SIZE_T total = carry + rd;
                    const uintptr_t chunkBase = r.base + off - carry;
                    // 默认按 x64 8 字节对齐扫描；回退模式改为逐字节扫描。
                    SIZE_T i = 0;
                    if (!scanUnaligned) {
                        const SIZE_T rem =
                            static_cast<SIZE_T>(chunkBase & (sizeof(uintptr_t) - 1));
                        if (rem)
                            i = sizeof(uintptr_t) - rem;
                    }
                    const SIZE_T stride = scanUnaligned ? 1 : sizeof(uintptr_t);
                    for (; i + sizeof(uintptr_t) <= total; i += stride) {
                        uintptr_t q = 0;
                        std::memcpy(&q, buf.data() + i, sizeof(q));
                        const uintptr_t loc = chunkBase + i;
                        if (visited.count(loc))
                            continue;
                        bool matched = false;
                        const auto first = std::lower_bound(
                            targetOrder.begin(), targetOrder.end(), q,
                            [&](size_t index, uintptr_t value) {
                                return targets[index].loc < value;
                            });
                        for (auto targetIt = first; targetIt != targetOrder.end();
                             ++targetIt) {
                            const Node& t = targets[*targetIt];
                            if (t.loc - q > kMaxOff)
                                break;
                            matched = true;
                            if (stats)
                                ++stats->matches;
                            const uintptr_t gap = t.loc - q;
                            std::vector<uintptr_t> hops;
                            hops.reserve(t.hops.size() + 1);
                            hops.push_back(gap);
                            hops.insert(hops.end(), t.hops.begin(),
                                        t.hops.end());

                            const ModInfo* m = ModuleAt(loc);
                            const bool targetModule =
                                m && _wcsicmp(m->name.c_str(), moduleName_.c_str()) == 0;
                            if (m && IsWritableProtect(r.protect)) {
                                PtrPath p;
                                p.module     = m->name;
                                p.baseOffset = loc - m->base;
                                p.hops       = hops;
                                result.push_back(std::move(p));
                                if (stats) {
                                    if (targetModule)
                                        ++stats->moduleRoots;
                                    else
                                        ++stats->otherModuleRoots;
                                }
                            } else if (m) {
                                if (stats) {
                                    if (targetModule)
                                        ++stats->readOnlyModuleMatches;
                                    else
                                        ++stats->otherModuleMatches;
                                }
                                // 目标模块和其他模块的代码区/.rdata 命中不作为根，
                                // 也不继续扩展，避免挤占真正的数据指针候选。
                            } else if (next.size() < maxNodes) {
                                if (stats)
                                    ++stats->nonModuleMatches;
                                next.push_back({ loc, std::move(hops) });
                                if (stats)
                                    ++stats->kept;
                            } else if (stats) {
                                ++stats->nonModuleMatches;
                                ++stats->dropped;
                                stats->truncated = true;
                            }
                        }
                        if (matched)
                            visited.insert(loc);
                    }
                    off += rd;
                    carry = (std::min)(kCarry, total);
                    if (carry)
                        std::memmove(buf.data(), buf.data() + total - carry, carry);
                }
            }
        }
        targets = std::move(next);
        if (result.size() >= 10000)
            break;
    }
    if (stats) {
        stats->cancelled = cancel && cancel(cancelCtx);
        stats->timedOut = !stats->cancelled && timeLimitMs &&
                          GetTickCount64() - t0 >
                              static_cast<ULONGLONG>(timeLimitMs);
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

    if (path.baseOffset > (std::numeric_limits<uintptr_t>::max)() - m->base)
        return false;
    uintptr_t addr = m->base + path.baseOffset;
    for (uintptr_t hop : path.hops) {
        uintptr_t q = 0;
        SIZE_T rd = 0;
        if (!ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(addr), &q,
                               sizeof(q), &rd) || rd != sizeof(q))
            return false;
        if (hop > (std::numeric_limits<uintptr_t>::max)() - q)
            return false;
        addr = q + hop;
    }
    *finalAddr = addr;
    return true;
}
