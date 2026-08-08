#include "scanner.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <set>
#include <vector>
#include <cwchar>

namespace fs = std::filesystem;

static bool ReadExact(std::ifstream& f, void* buf, size_t sz) {
    f.read(reinterpret_cast<char*>(buf), sz);
    return f.gcount() == static_cast<std::streamsize>(sz);
}

#pragma pack(push, 1)
struct RasterHdr {
    uint32_t platformId;
    uint32_t filterFlags;
    char     texName[32];
    char     maskName[32];
    uint32_t rasterFormat;
    uint32_t d3dFormat;
    uint16_t width, height;
    uint8_t  depth, numMips, rasterType, compression;
};
#pragma pack(pop)
static_assert(sizeof(RasterHdr) == 88, "RasterHdr size mismatch");

static uint32_t PaletteBytes(uint32_t rasterFormat) {
    if (rasterFormat & 0x4000) return 128;
    if (rasterFormat & 0x2000) return 1024;
    return 0;
}

static uint32_t ActualMipBytes(uint32_t d3dFmt, uint8_t compression, uint8_t depth, uint32_t mw, uint32_t mh) {
    if (compression & 0x08) {
        uint32_t bw = std::max(1u, (mw + 3u) / 4u);
        uint32_t bh = std::max(1u, (mh + 3u) / 4u);
        uint32_t bpb = (d3dFmt == 0x31545844u) ? 8u : 16u;
        return bw * bh * bpb;
    }
    uint32_t bpp = (depth >= 8u) ? depth / 8u : 1u;
    return std::max(1u, mw) * std::max(1u, mh) * bpp;
}

static std::wstring FmtHex(uint32_t v) {
    wchar_t buf[12]; swprintf_s(buf, L"0x%X", v); return buf;
}

Verdict ScanTxd(const std::wstring& path, std::wstring& threat) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return Verdict::Error;

    RW::ChunkHeader outer{}, txdStruct{};
    if (!ReadExact(f, &outer, 12)) return Verdict::Error;
    if (outer.type != RW::TEXDICT) return Verdict::Safe;
    if (!ReadExact(f, &txdStruct, 12)) return Verdict::Error;
    if (txdStruct.type != RW::STRUCT) return Verdict::Safe;

    if (txdStruct.length != RW::TEXDICT_STRUCT_OK) {
        threat = L"TexDict STRUCT overflow";
        return Verdict::Malicious;
    }

    uint32_t numTex = 0;
    if (!ReadExact(f, &numTex, 4)) return Verdict::Safe;

    uint32_t txdEnd = 12u + outer.length;

    for (uint32_t ti = 0; ti < numTex; ti++) {
        if (static_cast<uint32_t>(f.tellg()) + 12u > txdEnd) break;

        RW::ChunkHeader tn{};
        if (!ReadExact(f, &tn, 12)) break;
        uint32_t tnEnd = static_cast<uint32_t>(f.tellg()) + tn.length;

        if (tn.type != RW::TEXNATIVE) {
            f.seekg(tn.length, std::ios::cur);
            continue;
        }

        RW::ChunkHeader ts{};
        if (!ReadExact(f, &ts, 12)) break;
        if (ts.type != RW::STRUCT || ts.length < sizeof(RasterHdr)) {
            f.seekg(tnEnd, std::ios::beg);
            continue;
        }

        RasterHdr hdr{};
        if (!ReadExact(f, &hdr, sizeof(hdr))) break;

        f.seekg(PaletteBytes(hdr.rasterFormat), std::ios::cur);
        if (!f.good()) { f.seekg(tnEnd, std::ios::beg); continue; }

        uint32_t mw = hdr.width  ? (uint32_t)hdr.width  : 1u;
        uint32_t mh = hdr.height ? (uint32_t)hdr.height : 1u;

        for (uint8_t m = 0; m < hdr.numMips; m++) {
            uint32_t dataSize = 0;
            if (!ReadExact(f, &dataSize, 4)) goto next_tex;

            {
                uint32_t expMax = ActualMipBytes(hdr.d3dFormat, hdr.compression, hdr.depth, mw, mh);
                if (dataSize > expMax * 2u && dataSize > 4096u) {
                    threat = L"Mipmap heap overflow";
                    return Verdict::Malicious;
                }
            }

            f.seekg(dataSize, std::ios::cur);
            if (mw > 1u) mw >>= 1;
            if (mh > 1u) mh >>= 1;
        }

    next_tex:
        f.seekg(tnEnd, std::ios::beg);
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
                    threat = std::wstring(name) + L" STRUCT overflow";
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

        [&]() {
            if (data.size() < 28) return;
            if (r32(12) != RW::STRUCT || r32(16) != RW::TEXDICT_STRUCT_OK) return;

            uint32_t numTex = r32(24);
            uint32_t txdEnd = 12u + r32(4);
            if (txdEnd > data.size()) txdEnd = (uint32_t)data.size();

            struct B1Fix {
                size_t   mipSizeOff;
                uint32_t origSize, capSize;
                size_t   structSizeOff, tnSizeOff;
            };
            std::vector<B1Fix> b1fixes;

            size_t pos = 28;

            for (uint32_t ti = 0; pos + 12 <= data.size() && pos < txdEnd; ti++) {
                uint32_t tnType = r32(pos);
                uint32_t tnSize = r32(pos + 4);
                size_t   tnEnd  = pos + 12 + tnSize;
                if (tnSize == 0) break;

                if (tnType != RW::TEXNATIVE) { pos = tnEnd; continue; }

                bool hdrOk = pos + 24 + sizeof(RasterHdr) <= data.size()
                          && r32(pos + 12) == RW::STRUCT
                          && r32(pos + 16) >= sizeof(RasterHdr);
                if (!hdrOk) { pos = tnEnd; continue; }

                size_t tnSizeOff    = pos + 4;
                size_t structSizeOff = pos + 16;
                size_t hdrOff       = pos + 24;

                RasterHdr hdr{};
                memcpy(&hdr, &data[hdrOff], sizeof(hdr));

                uint32_t palSize = PaletteBytes(hdr.rasterFormat);
                size_t   mipOff  = hdrOff + sizeof(RasterHdr) + palSize;
                uint32_t mw = hdr.width  ? hdr.width  : 1u;
                uint32_t mh = hdr.height ? hdr.height : 1u;

                for (uint8_t m = 0; m < hdr.numMips && mipOff + 4 <= data.size(); m++) {
                    uint32_t ds     = r32(mipOff);
                    uint32_t expMax = ActualMipBytes(hdr.d3dFormat, hdr.compression, hdr.depth, mw, mh);
                    if (ds > expMax * 2u && ds > 4096u)
                        b1fixes.push_back({ mipOff, ds, expMax, structSizeOff, tnSizeOff });
                    mipOff += 4 + ds;
                    if (mw > 1u) mw >>= 1;
                    if (mh > 1u) mh >>= 1;
                }

                pos = tnEnd;
            }

            uint32_t totalCut = 0;
            for (int i = (int)b1fixes.size() - 1; i >= 0; i--) {
                auto& fx = b1fixes[i];
                uint32_t cut = fx.origSize - fx.capSize;

                size_t eraseStart = fx.mipSizeOff + 4 + fx.capSize;
                size_t eraseEnd   = fx.mipSizeOff + 4 + fx.origSize;
                if (eraseEnd > data.size()) eraseEnd = data.size();
                if (eraseStart < eraseEnd)
                    data.erase(data.begin() + eraseStart, data.begin() + eraseEnd);

                w32(fx.mipSizeOff,    fx.capSize);
                w32(fx.structSizeOff, r32(fx.structSizeOff) - cut);
                w32(fx.tnSizeOff,     r32(fx.tnSizeOff)     - cut);
                totalCut += cut;
                changed = true;
            }
            if (totalCut > 0)
                w32(4, r32(4) - totalCut);
        }();
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
                        size_t eraseEnd   = innerOff + 12 + sLen;
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
        r.path     = p.wstring();
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
    stats.files   = (int)results.size();
    return results;
}
