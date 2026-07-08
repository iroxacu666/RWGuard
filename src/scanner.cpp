#include "scanner.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <set>

namespace fs = std::filesystem;

static bool ReadExact(std::ifstream& f, void* buf, size_t sz) {
    f.read(reinterpret_cast<char*>(buf), sz);
    return f.gcount() == static_cast<std::streamsize>(sz);
}

Verdict ScanTxd(const std::wstring& path, std::wstring& threat) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return Verdict::Error;

    RW::ChunkHeader outer{}, inner{};
    if (!ReadExact(f, &outer, 12)) return Verdict::Error;
    if (outer.type != RW::TEXDICT) return Verdict::Safe;
    if (!ReadExact(f, &inner, 12)) return Verdict::Error;
    if (inner.type != RW::STRUCT) return Verdict::Safe;

    if (inner.length != RW::TEXDICT_STRUCT_OK) {
        threat = L"TXD STRUCT overflow (size=" + std::to_wstring(inner.length) + L", max=" + std::to_wstring(RW::TEXDICT_STRUCT_OK) + L")";
        return Verdict::Malicious;
    }
    return Verdict::Safe;
}

Verdict ScanDff(const std::wstring& path, std::wstring& threat) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return Verdict::Error;

    RW::ChunkHeader clump{};
    if (!ReadExact(f, &clump, 12)) return Verdict::Error;
    if (clump.type != RW::CLUMP) return Verdict::Safe;

    uint32_t clumpEnd = 12 + clump.length;

    while (static_cast<uint32_t>(f.tellg()) + 12 <= clumpEnd) {
        RW::ChunkHeader chunk{};
        if (!ReadExact(f, &chunk, 12)) break;

        if (chunk.type == RW::ATOMIC || chunk.type == RW::LIGHT || chunk.type == RW::CAMERA) {
            auto parentEnd = static_cast<uint32_t>(f.tellg()) + chunk.length;

            RW::ChunkHeader inner{};
            if (ReadExact(f, &inner, 12) && inner.type == RW::STRUCT) {
                uint32_t maxSize = 0;
                const wchar_t* name = nullptr;

                if (chunk.type == RW::ATOMIC)  { maxSize = RW::ATOMIC_STRUCT_MAX; name = L"Atomic"; }
                if (chunk.type == RW::LIGHT)   { maxSize = RW::LIGHT_STRUCT_MAX;  name = L"Light";  }
                if (chunk.type == RW::CAMERA)  { maxSize = RW::CAMERA_STRUCT_MAX; name = L"Camera"; }

                if (maxSize && inner.length > maxSize) {
                    threat = std::wstring(name) + L" STRUCT overflow (size=" +
                             std::to_wstring(inner.length) + L", max=" + std::to_wstring(maxSize) + L")";
                    return Verdict::Malicious;
                }
            }

            f.seekg(parentEnd, std::ios::beg);
            continue;
        }

        f.seekg(chunk.length, std::ios::cur);
    }

    return Verdict::Safe;
}

bool HealFile(const std::wstring& path) {
    std::vector<uint8_t> data;
    {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        data.assign(std::istreambuf_iterator<char>(f), {});
    }
    if (data.size() < 24) return false;

    bool changed = false;
    auto r32 = [&](size_t off) -> uint32_t { uint32_t v; memcpy(&v, &data[off], 4); return v; };
    auto w32 = [&](size_t off, uint32_t v) { memcpy(&data[off], &v, 4); };

    uint32_t outerType = r32(0);

    if (outerType == RW::TEXDICT) {
        if (r32(12) == RW::STRUCT && r32(16) != RW::TEXDICT_STRUCT_OK) {
            uint32_t badLen = r32(16);
            uint32_t cut = badLen - RW::TEXDICT_STRUCT_OK;
            w32(16, RW::TEXDICT_STRUCT_OK);
            w32(4, r32(4) - cut);
            data.erase(data.begin() + 24 + RW::TEXDICT_STRUCT_OK, data.begin() + 24 + badLen);
            changed = true;
        }
    }

    if (outerType == RW::CLUMP) {
        uint32_t clumpSize = r32(4);
        size_t pos = 12;
        while (pos + 12 <= 12 + clumpSize && pos + 12 <= data.size()) {
            uint32_t cType = r32(pos);
            uint32_t cSize = r32(pos + 4);

            if (cType == RW::ATOMIC || cType == RW::LIGHT || cType == RW::CAMERA) {
                size_t innerOff = pos + 12;
                if (innerOff + 12 <= data.size() && r32(innerOff) == RW::STRUCT) {
                    uint32_t sLen = r32(innerOff + 4);
                    uint32_t maxLen = 0;
                    if (cType == RW::ATOMIC) maxLen = RW::ATOMIC_STRUCT_MAX;
                    if (cType == RW::LIGHT)  maxLen = RW::LIGHT_STRUCT_MAX;
                    if (cType == RW::CAMERA) maxLen = RW::CAMERA_STRUCT_MAX;

                    if (maxLen && sLen > maxLen) {
                        uint32_t cut = sLen - maxLen;
                        w32(innerOff + 4, maxLen);
                        size_t eraseStart = innerOff + 12 + maxLen;
                        size_t eraseEnd = innerOff + 12 + sLen;
                        if (eraseEnd <= data.size()) {
                            data.erase(data.begin() + eraseStart, data.begin() + eraseEnd);
                            w32(pos + 4, cSize - cut);
                            w32(4, r32(4) - cut);
                            changed = true;
                        }
                    }
                }
            }

            pos += 12 + r32(pos + 4);
        }
    }

    if (!changed) return false;

    std::ofstream out(path, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<char*>(data.data()), data.size());
    return true;
}

std::vector<ScanResult> ScanDirectory(const std::wstring& dir, bool recursive, ScanStats& stats) {
    std::vector<ScanResult> results;
    std::set<std::wstring> dirs;

    auto scan = [&](const fs::path& p) {
        auto ext = p.extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

        if (ext != L".txd" && ext != L".dff") return;

        dirs.insert(p.parent_path().wstring());

        ScanResult r;
        r.path = p.wstring();
        r.fileName = p.filename().wstring();

        if (ext == L".txd")
            r.verdict = ScanTxd(r.path, r.threat);
        else
            r.verdict = ScanDff(r.path, r.threat);

        if (r.verdict == Verdict::Malicious) stats.threats++;
        results.push_back(std::move(r));
    };

    try {
        if (recursive) {
            for (auto& e : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied))
                if (e.is_regular_file()) scan(e.path());
        } else {
            for (auto& e : fs::directory_iterator(dir))
                if (e.is_regular_file()) scan(e.path());
        }
    } catch (...) {}

    stats.folders = (int)dirs.size();
    stats.files = (int)results.size();
    return results;
}
