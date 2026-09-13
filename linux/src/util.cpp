// Femboi Firewall utility implementations
#include "fw.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

namespace femboifw {

namespace {
int g_log_level = 2;
std::string g_log_path;
std::mutex g_log_mu;

// Return log level string tag
const char* level_tag(int level) {
    switch (level) {
        case 0: return "ERROR";
        case 1: return "WARN ";
        case 2: return "INFO ";
        default: return "DEBUG";
    }
}

// Generate formatted timestamp string
std::string timestamp() {
    char buf[32];
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}
} // namespace

// Set active log filter level
void LogSetLevel(int level) { g_log_level = level; }

// Configure log file output path
void LogSetFile(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_log_mu);
    g_log_path = path;
}

// Write formatted log message
void Logf(int level, const char* fmt, ...) {
    if (level > g_log_level) return;

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lk(g_log_mu);
    const std::string line = timestamp() + " [" + level_tag(level) + "] " + msg;

    fprintf(level <= 1 ? stderr : stdout, "%s\n", line.c_str());
    fflush(nullptr);

    if (!g_log_path.empty()) {
        std::ofstream out(g_log_path, std::ios::app);
        if (out) out << line << "\n";
    }
}

namespace {

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
};

// SHA-256 round constants
constexpr uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffeu, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint32_t ror(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

// Process 64-byte SHA-256 block
void sha256_transform(Sha256Ctx& ctx, const uint8_t* data) {
    uint32_t m[64];
    for (size_t i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)data[i * 4 + 0] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (size_t i = 16; i < 64; ++i) {
        const uint32_t s0 = ror(m[i - 15], 7) ^ ror(m[i - 15], 18) ^ (m[i - 15] >> 3);
        const uint32_t s1 = ror(m[i - 2], 17) ^ ror(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
    uint32_t e = ctx.state[4], f = ctx.state[5], g = ctx.state[6], h = ctx.state[7];

    for (size_t i = 0; i < 64; ++i) {
        const uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + S1 + ch + kSha256K[i] + m[i];
        const uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
    ctx.state[4] += e; ctx.state[5] += f; ctx.state[6] += g; ctx.state[7] += h;
}

// Initialize SHA-256 state
void sha256_init(Sha256Ctx& ctx) {
    ctx.state[0] = 0x6a09e667u; ctx.state[1] = 0xbb67ae85u;
    ctx.state[2] = 0x3c6ef372u; ctx.state[3] = 0xa54ff53au;
    ctx.state[4] = 0x510e527fu; ctx.state[5] = 0x9b05688cu;
    ctx.state[6] = 0x1f83d9abu; ctx.state[7] = 0x5be0cd19u;
    ctx.bitlen = 0;
    ctx.buflen = 0;
}

// Append data to hash stream
void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx.buf[ctx.buflen++] = data[i];
        if (ctx.buflen == 64) {
            sha256_transform(ctx, ctx.buf);
            ctx.bitlen += 512;
            ctx.buflen = 0;
        }
    }
}

// Finalize hash and write digest
void sha256_final(Sha256Ctx& ctx, uint8_t out[32]) {
    size_t i = ctx.buflen;
    ctx.buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx.buf[i++] = 0x00;
        sha256_transform(ctx, ctx.buf);
        i = 0;
    }
    while (i < 56) ctx.buf[i++] = 0x00;
    ctx.bitlen += (uint64_t)ctx.buflen * 8;
    for (size_t j = 0; j < 8; ++j) {
        ctx.buf[63 - j] = (uint8_t)(ctx.bitlen >> (j * 8));
    }
    sha256_transform(ctx, ctx.buf);

    for (size_t j = 0; j < 8; ++j) {
        out[j * 4 + 0] = (uint8_t)(ctx.state[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(ctx.state[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(ctx.state[j] >> 8);
        out[j * 4 + 3] = (uint8_t)(ctx.state[j]);
    }
}

// Format binary buffer as hexadecimal string
std::string to_hex(const uint8_t* d, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s[i * 2] = kHex[d[i] >> 4];
        s[i * 2 + 1] = kHex[d[i] & 0x0F];
    }
    return s;
}

} // namespace

// Calculate SHA-256 hash of file
std::string Sha256File(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};

    Sha256Ctx ctx;
    sha256_init(ctx);
    std::vector<char> chunk(65536);
    while (in) {
        in.read(chunk.data(), (std::streamsize)chunk.size());
        std::streamsize got = in.gcount();
        if (got > 0) {
            sha256_update(ctx, reinterpret_cast<const uint8_t*>(chunk.data()), (size_t)got);
        }
    }
    uint8_t digest[32];
    sha256_final(ctx, digest);
    return to_hex(digest, sizeof(digest));
}

// Current epoch timestamp in seconds
int64_t NowEpoch() {
    return (int64_t)std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Format network IP to dot-decimal notation
std::string FormatIp(uint32_t ip_nbo) {
    char buf[INET_ADDRSTRLEN] = {0};
    struct in_addr a;
    a.s_addr = ip_nbo;
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return "0.0.0.0";
    return buf;
}

// Parse dot-decimal string to network IP
bool ParseIp(const std::string& text, uint32_t* out_nbo) {
    std::string s = text;
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return false;
    s = s.substr(b, e - b + 1);

    struct in_addr a;
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
    *out_nbo = a.s_addr;
    return true;
}

// Format 32-bit integer as hex string
std::string Hex8(uint32_t v) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%08x", v);
    return buf;
}

// Return system host name
std::string MachineName() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf) - 1) != 0) return "UNKNOWN";
    buf[sizeof(buf) - 1] = '\0';
    return buf[0] ? buf : "UNKNOWN";
}

// Generate machine hardware fingerprint
std::string MachineHwid() {
    uint32_t h = 0;

#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        h = ebx ^ ecx ^ edx;
    }
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        h ^= eax;
    }
#endif

    struct stat st{};
    if (stat("/", &st) == 0) {
        h ^= (uint32_t)(st.st_dev & 0xFFFFFFFFu);
    }

    const std::string name = MachineName();
    for (unsigned char c : name) {
        h = (h * 33u) + (uint32_t)c;
    }

    return "HW-" + Hex8(h) + "-" + Hex8(h ^ 0x5A5A5A5Au);
}

} // namespace femboifw
