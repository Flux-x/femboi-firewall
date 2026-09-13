#pragma once
// HTTP and TLS Layer 7 inspection
#include <cstdint>
#include <cstring>
#include <cctype>

enum L7Result {
    L7_OK = 0,
    L7_MALFORMED_METHOD,
    L7_SCANNER_PROBE,
    L7_EXPLOIT_PAYLOAD,
    L7_SLOWLORIS_FRAGMENT,
    L7_TLS_INVALID,
    L7_TLS_OK
};

// Case-insensitive substring search
static inline bool l7_find_substr_ci(const char* buf, size_t buf_len, const char* needle, size_t needle_len) {
    if (needle_len == 0 || buf_len < needle_len) return false;
    size_t limit = buf_len - needle_len;
    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle_len; ++j) {
            char c1 = (char)tolower((unsigned char)buf[i + j]);
            char c2 = (char)tolower((unsigned char)needle[j]);
            if (c1 != c2) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Convert hex character to integer
static inline int l7_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decode URL percent encoded string
static inline size_t l7_url_decode(const char* src, size_t src_len, char* out_buf, size_t out_max) {
    if (src_len == 0 || out_max == 0) return 0;
    size_t si = 0, di = 0;

    while (si < src_len && di + 1 < out_max) {
        if (src[si] == '%' && si + 2 < src_len) {
            int h1 = l7_hex_val(src[si + 1]);
            int h2 = l7_hex_val(src[si + 2]);
            if (h1 >= 0 && h2 >= 0) {
                char dec = (char)((h1 << 4) | h2);
                out_buf[di++] = dec;
                si += 3;
                continue;
            }
        } else if (src[si] == '+') {
            out_buf[di++] = ' ';
            si++;
            continue;
        }
        out_buf[di++] = src[si++];
    }
    out_buf[di] = '\0';

    char temp[512];
    size_t pass1_len = di;
    bool has_nested_pct = false;
    for (size_t i = 0; i < pass1_len; ++i) {
        if (out_buf[i] == '%') {
            has_nested_pct = true;
            break;
        }
    }

    if (has_nested_pct && pass1_len < sizeof(temp)) {
        size_t t_di = 0;
        for (size_t i = 0; i < pass1_len && t_di + 1 < out_max; ) {
            if (out_buf[i] == '%' && i + 2 < pass1_len) {
                int h1 = l7_hex_val(out_buf[i + 1]);
                int h2 = l7_hex_val(out_buf[i + 2]);
                if (h1 >= 0 && h2 >= 0) {
                    temp[t_di++] = (char)((h1 << 4) | h2);
                    i += 3;
                    continue;
                }
            }
            temp[t_di++] = out_buf[i++];
        }
        temp[t_di] = '\0';
        memcpy(out_buf, temp, t_di + 1);
        di = t_di;
    }

    return di;
}

// Normalize URI path separators
static inline size_t l7_normalize_path(char* path, size_t len) {
    if (len == 0) return 0;
    size_t w = 0;
    for (size_t r = 0; r < len; ++r) {
        char c = path[r];
        if (c == '\\') c = '/';

        if (c == '/' && w > 0 && path[w - 1] == '/') {
            continue;
        }
        path[w++] = c;
    }
    path[w] = '\0';
    return w;
}

// Known attack signatures
static const struct {
    const char* pattern;
    size_t len;
} kMaliciousPatterns[] = {
    { "/.env", sizeof("/.env") - 1 },
    { ".env", sizeof(".env") - 1 },
    { "/wp-login", sizeof("/wp-login") - 1 },
    { "/wp-admin", sizeof("/wp-admin") - 1 },
    { "/xmlrpc.php", sizeof("/xmlrpc.php") - 1 },
    { "/phpmyadmin", sizeof("/phpmyadmin") - 1 },
    { "/pma", sizeof("/pma") - 1 },
    { "/adminer", sizeof("/adminer") - 1 },
    { "/cgi-bin", sizeof("/cgi-bin") - 1 },
    { "/setup.cgi", sizeof("/setup.cgi") - 1 },
    { "/eval-stdin", sizeof("/eval-stdin") - 1 },
    { "/.git", sizeof("/.git") - 1 },
    { "/actuator", sizeof("/actuator") - 1 },
    { "/.aws", sizeof("/.aws") - 1 },
    { "/shell.php", sizeof("/shell.php") - 1 },
    { "/alfa.php", sizeof("/alfa.php") - 1 },
    { "/wso.php", sizeof("/wso.php") - 1 },
    { "/vendor/phpunit", sizeof("/vendor/phpunit") - 1 },
    { "/boaform", sizeof("/boaform") - 1 },
    { "/solr", sizeof("/solr") - 1 },
    { "${jndi:", sizeof("${jndi:") - 1 },
    { "../..", sizeof("../..") - 1 },
    { "..\\..", sizeof("..\\..") - 1 },
    { "/config.json", sizeof("/config.json") - 1 },
    { "/database.db", sizeof("/database.db") - 1 },
    { "/web.config", sizeof("/web.config") - 1 },
    { "/.htaccess", sizeof("/.htaccess") - 1 },
    { "/etc/passwd", sizeof("/etc/passwd") - 1 },
    { "cmd.exe", sizeof("cmd.exe") - 1 },
    { "/bin/sh", sizeof("/bin/sh") - 1 },
    { "/bin/bash", sizeof("/bin/bash") - 1 },
    { "powershell", sizeof("powershell") - 1 },
    { "union select", sizeof("union select") - 1 },
    { "information_schema", sizeof("information_schema") - 1 },
    { "benchmark(", sizeof("benchmark(") - 1 },
    { "swagger-ui", sizeof("swagger-ui") - 1 },
    { "thinkphp", sizeof("thinkphp") - 1 },
    { "sqlmap", sizeof("sqlmap") - 1 },
    { "nikto", sizeof("nikto") - 1 },
    { "wpscan", sizeof("wpscan") - 1 },
    { "dirbuster", sizeof("dirbuster") - 1 },
    { "gobuster", sizeof("gobuster") - 1 },
    { "acunetix", sizeof("acunetix") - 1 },
    { "nessus", sizeof("nessus") - 1 },
    { "nuclei", sizeof("nuclei") - 1 },
    { "() { :; };", sizeof("() { :; };") - 1 }
};

// Inspect HTTP request payload
static inline L7Result l7_inspect_http(const unsigned char* payload, unsigned int len) {
    if (len == 0) return L7_OK;
    if (len < 4) {
        return L7_SLOWLORIS_FRAGMENT;
    }

    const char* str = reinterpret_cast<const char*>(payload);

    size_t offset = 0;
    while (offset < len && (payload[offset] == ' ' || payload[offset] == '\r' || payload[offset] == '\n' || payload[offset] == '\t')) {
        offset++;
    }
    if (offset >= len) return L7_OK;

    const char* req_start = str + offset;
    size_t remaining_len = len - offset;

    bool method_valid = false;
    size_t method_len = 0;

    static const char* kMethods[] = {
        "GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"
    };

    for (const char* m : kMethods) {
        size_t mlen = strlen(m);
        if (remaining_len > mlen && memcmp(req_start, m, mlen) == 0) {
            if (req_start[mlen] == ' ' || req_start[mlen] == '\t') {
                method_valid = true;
                method_len = mlen;
                while (method_len < remaining_len && (req_start[method_len] == ' ' || req_start[method_len] == '\t')) {
                    method_len++;
                }
                break;
            }
        }
    }

    if (!method_valid && remaining_len >= 14 && memcmp(req_start, "PRI * HTTP/2.0", 14) == 0) {
        return L7_OK;
    }

    size_t scan_len = remaining_len < 512 ? remaining_len : 512;

    for (size_t i = 0; i < scan_len; ++i) {
        if (req_start[i] == 0x00) {
            return L7_EXPLOIT_PAYLOAD;
        }
    }

    for (const auto& p : kMaliciousPatterns) {
        if (l7_find_substr_ci(req_start, scan_len, p.pattern, p.len)) {
            return L7_SCANNER_PROBE;
        }
    }

    char decoded_buf[512];
    size_t decoded_len = l7_url_decode(req_start, scan_len, decoded_buf, sizeof(decoded_buf));
    if (decoded_len > 0) {
        decoded_len = l7_normalize_path(decoded_buf, decoded_len);

        for (const auto& p : kMaliciousPatterns) {
            if (l7_find_substr_ci(decoded_buf, decoded_len, p.pattern, p.len)) {
                return L7_SCANNER_PROBE;
            }
        }
    }

    if (!method_valid) {
        for (unsigned int i = 0; i < (remaining_len < 16 ? remaining_len : 16); ++i) {
            unsigned char c = (unsigned char)req_start[i];
            if (c == 0x00 || (c < 0x20 && c != '\r' && c != '\n' && c != '\t')) {
                return L7_EXPLOIT_PAYLOAD;
            }
        }
        return L7_OK;
    }

    return L7_OK;
}

// Inspect TLS packet header
static inline L7Result l7_inspect_tls(const unsigned char* payload, unsigned int len) {
    if (len == 0) return L7_TLS_OK;

    if (len >= 4) {
        if (memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST", 4) == 0 ||
            memcmp(payload, "HEAD", 4) == 0 || memcmp(payload, "PRI ", 4) == 0 ||
            memcmp(payload, "PUT ", 4) == 0 || memcmp(payload, "DELE", 4) == 0 ||
            memcmp(payload, "OPTI", 4) == 0) {
            return L7_TLS_INVALID;
        }
    }

    if (len >= 3 && (payload[0] >= 0x14 && payload[0] <= 0x17)) {
        uint8_t ver_major = payload[1];
        uint8_t ver_minor = payload[2];
        if (ver_major != 0x03 || ver_minor > 0x04) {
            return L7_TLS_INVALID;
        }
    }

    return L7_TLS_OK;
}
