// scanner.h - 进程内存扫描 / 差分定位 / 指针路径查找
#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

struct ScanMatch {
    uintptr_t addr;
    uint32_t  value;
};

// 指针路径: 形如 virtualdesktop.streamer.exe+0x2A5C8D0:0x48:0x1C
struct PtrPath {
    std::wstring module;
    uintptr_t baseOffset = 0;
    std::vector<uintptr_t> hops;

    std::wstring ToString() const;
    static bool Parse(const std::wstring& text, PtrPath& out);
};

class VdScanner {
public:
    explicit VdScanner(DWORD pid);
    ~VdScanner();
    VdScanner(const VdScanner&) = delete;
    VdScanner& operator=(const VdScanner&) = delete;

    bool Attach();  // 打开进程、提权、缓存内存区域与模块信息
    DWORD Pid() const { return pid_; }
    const std::wstring& ModuleName() const { return moduleName_; }
    uintptr_t ModuleBase() const { return moduleBase_; }

    // 全内存精确扫描 value；maxResults>0 时达到上限即停止，truncated 标记是否被截断
    std::vector<ScanMatch> ScanValue(uint32_t value, size_t maxResults = 0,
                                     bool* truncated = nullptr) const;
    bool Read32(uintptr_t addr, uint32_t* out) const;
    bool Write32(uintptr_t addr, uint32_t v) const;

    // 从 leaf 地址反向查找指针链，返回所有静态可达路径
    // timeLimitMs > 0 时整个叶扫描限时，超时提前返回已找到的结果；
    // progress 每层开始时回调(depth, 候选数, 已用毫秒)，用于日志进度
    using PtrScanProgress = void (*)(void* ctx, int depth, size_t candidates,
                                     DWORD elapsedMs);
    std::vector<PtrPath> FindPointerPaths(uintptr_t leaf, int maxDepth,
                                          size_t maxNodes,
                                          DWORD timeLimitMs = 0,
                                          PtrScanProgress progress = nullptr,
                                          void* progressCtx = nullptr) const;
    // 按路径解析出最终地址
    bool Resolve(const PtrPath& path, uintptr_t* finalAddr) const;

private:
    struct Region { uintptr_t base; SIZE_T size; };
    struct ModInfo { uintptr_t base; SIZE_T size; std::wstring name; };

    DWORD pid_ = 0;
    HANDLE h_ = nullptr;
    uintptr_t moduleBase_ = 0;
    SIZE_T moduleSize_ = 0;
    std::wstring moduleName_;
    std::vector<Region> regions_;
    std::vector<ModInfo> modules_;

    void CollectModules();
    void CollectRegions();
    const ModInfo* ModuleAt(uintptr_t addr) const;
};
