#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace RW {

struct ChunkHeader {
    uint32_t type;
    uint32_t length;
    uint32_t version;
};

constexpr uint32_t STRUCT     = 0x01;
constexpr uint32_t EXTENSION  = 0x03;
constexpr uint32_t CAMERA     = 0x05;
constexpr uint32_t FRAMELIST  = 0x0E;
constexpr uint32_t GEOMETRY   = 0x0F;
constexpr uint32_t CLUMP      = 0x10;
constexpr uint32_t LIGHT      = 0x12;
constexpr uint32_t ATOMIC     = 0x14;
constexpr uint32_t TEXDICT    = 0x16;
constexpr uint32_t GEOMLIST   = 0x1A;

constexpr uint32_t ATOMIC_STRUCT_MAX = 16;
constexpr uint32_t LIGHT_STRUCT_MAX  = 24;
constexpr uint32_t CAMERA_STRUCT_MAX = 32;
constexpr uint32_t TEXDICT_STRUCT_OK = 4;

}

enum class Verdict {
    Safe,
    Malicious,
    Error
};

struct ScanResult {
    std::wstring path;
    std::wstring fileName;
    Verdict verdict;
    std::wstring threat;
};

struct ScanStats {
    int folders = 0;
    int files = 0;
    int threats = 0;
};

Verdict ScanTxd(const std::wstring& path, std::wstring& threat);
Verdict ScanDff(const std::wstring& path, std::wstring& threat);
bool HealFile(const std::wstring& path);
std::vector<ScanResult> ScanDirectory(const std::wstring& dir, bool recursive, ScanStats& stats);
