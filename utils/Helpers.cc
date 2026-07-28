#include "Helpers.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>

namespace cliuno
{
namespace
{
const char *jwtSecret()
{
    if (const char *s = std::getenv("JWT_SECRET_KEY")) return s;
    if (const char *s = std::getenv("JWT_SECRET")) return s;
    return "cliuno-drogon-development-secret-change-me";
}

std::string compactJson(const Json::Value &v)
{
    Json::StreamWriterBuilder b;
    b["indentation"] = "";
    b["commentStyle"] = "None";
    std::string out = Json::writeString(b, v);
    // writeString can append a trailing newline depending on the build.
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

std::string toHex(const unsigned char *data, size_t len)
{
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

std::string fromHex(const std::string &hex)
{
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        auto val = static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        out.push_back(val);
    }
    return out;
}

std::string base64url(const unsigned char *data, size_t len)
{
    static const char *tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    for (size_t i = 0; i < len; i += 3)
    {
        int n = data[i] << 16;
        if (i + 1 < len) n |= data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        if (i + 1 < len) out.push_back(tbl[(n >> 6) & 63]);
        if (i + 2 < len) out.push_back(tbl[n & 63]);
    }
    return out; // no padding (url-safe)
}

std::string base64urlStr(const std::string &s)
{
    return base64url(reinterpret_cast<const unsigned char *>(s.data()), s.size());
}

std::string base64urlDecode(const std::string &in)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    std::string out;
    int buf = 0, bits = 0;
    for (char c : in)
    {
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::string hmac(const EVP_MD *md, const std::string &key, const std::string &msg)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(md, key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char *>(msg.data()), msg.size(), out, &len);
    return std::string(reinterpret_cast<char *>(out), len);
}

std::string base32Decode(const std::string &in)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a';
        if (c >= '2' && c <= '7') return c - '2' + 26;
        return -1;
    };
    std::string out;
    int buf = 0, bits = 0;
    for (char c : in)
    {
        if (c == '=' || c == ' ') continue;
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 5) | v;
        bits += 5;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}
} // namespace

// -------------------------------------------------------------- envelopes
HttpResponsePtr envelope(HttpStatusCode code,
                         const std::string &status,
                         const std::string &message,
                         const Json::Value &data)
{
    Json::Value root(Json::objectValue);
    root["status"] = status;
    if (!message.empty()) root["message"] = message;
    root["data"] = data;
    auto resp = drogon::HttpResponse::newHttpJsonResponse(root);
    resp->setStatusCode(code);
    return resp;
}

HttpResponsePtr ok(const std::string &message, const Json::Value &data)
{
    return envelope(drogon::k200OK, "success", message, data);
}
HttpResponsePtr ok(const std::string &message)
{
    return envelope(drogon::k200OK, "success", message);
}
HttpResponsePtr fail(HttpStatusCode code, const std::string &status, const std::string &message)
{
    return envelope(code, status, message);
}

Json::Value bodyJson(const HttpRequestPtr &req)
{
    auto ptr = req->getJsonObject();
    if (ptr) return *ptr;
    return Json::Value(Json::objectValue);
}

// -------------------------------------------------------------- passwords
std::string hashPassword(const std::string &password)
{
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));
    const int iterations = 100000;
    unsigned char key[32];
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt,
                      sizeof(salt), iterations, EVP_sha256(), sizeof(key), key);
    return "pbkdf2$" + std::to_string(iterations) + "$" + toHex(salt, sizeof(salt)) +
           "$" + toHex(key, sizeof(key));
}

bool verifyPassword(const std::string &password, const std::string &stored)
{
    // format: pbkdf2$<iter>$<salthex>$<hashhex>
    size_t p1 = stored.find('$');
    size_t p2 = stored.find('$', p1 + 1);
    size_t p3 = stored.find('$', p2 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos)
        return false;
    int iterations = std::stoi(stored.substr(p1 + 1, p2 - p1 - 1));
    std::string salt = fromHex(stored.substr(p2 + 1, p3 - p2 - 1));
    std::string expected = stored.substr(p3 + 1);
    unsigned char key[32];
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                      reinterpret_cast<const unsigned char *>(salt.data()),
                      static_cast<int>(salt.size()), iterations, EVP_sha256(),
                      sizeof(key), key);
    std::string got = toHex(key, sizeof(key));
    if (got.size() != expected.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < got.size(); ++i) diff |= got[i] ^ expected[i];
    return diff == 0;
}

std::string randomToken(int bytes)
{
    std::string buf(bytes, '\0');
    RAND_bytes(reinterpret_cast<unsigned char *>(buf.data()), bytes);
    return toHex(reinterpret_cast<const unsigned char *>(buf.data()), bytes);
}

// -------------------------------------------------------------- JWT (HS256)
std::string signJwt(int64_t userId, const std::string &type, int ttlSeconds)
{
    Json::Value header(Json::objectValue);
    header["alg"] = "HS256";
    header["typ"] = "JWT";
    Json::Value payload(Json::objectValue);
    payload["sub"] = static_cast<Json::Int64>(userId);
    payload["type"] = type;
    payload["exp"] = static_cast<Json::Int64>(std::time(nullptr) + ttlSeconds);

    std::string signingInput =
        base64urlStr(compactJson(header)) + "." + base64urlStr(compactJson(payload));
    std::string sig = hmac(EVP_sha256(), jwtSecret(), signingInput);
    return signingInput + "." +
           base64url(reinterpret_cast<const unsigned char *>(sig.data()), sig.size());
}

std::optional<int64_t> verifyJwt(const std::string &token, const std::string &type)
{
    size_t d1 = token.find('.');
    size_t d2 = token.rfind('.');
    if (d1 == std::string::npos || d1 == d2) return std::nullopt;
    std::string signingInput = token.substr(0, d2);
    std::string sig = token.substr(d2 + 1);
    std::string expected = hmac(EVP_sha256(), jwtSecret(), signingInput);
    std::string expectedB64 =
        base64url(reinterpret_cast<const unsigned char *>(expected.data()), expected.size());
    if (sig != expectedB64) return std::nullopt;

    std::string payloadJson = base64urlDecode(token.substr(d1 + 1, d2 - d1 - 1));
    Json::CharReaderBuilder rb;
    Json::Value payload;
    std::string err;
    auto reader = std::unique_ptr<Json::CharReader>(rb.newCharReader());
    if (!reader->parse(payloadJson.data(), payloadJson.data() + payloadJson.size(),
                       &payload, &err))
        return std::nullopt;
    if (payload["type"].asString() != type) return std::nullopt;
    if (payload["exp"].asInt64() < std::time(nullptr)) return std::nullopt;
    return payload["sub"].asInt64();
}

// -------------------------------------------------------------- TOTP
std::string generateBase32Secret()
{
    static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned char raw[20];
    RAND_bytes(raw, sizeof(raw));
    std::string out;
    int buf = 0, bits = 0;
    for (unsigned char b : raw)
    {
        buf = (buf << 8) | b;
        bits += 8;
        while (bits >= 5)
        {
            bits -= 5;
            out.push_back(alphabet[(buf >> bits) & 31]);
        }
    }
    if (bits > 0) out.push_back(alphabet[(buf << (5 - bits)) & 31]);
    return out;
}

std::string otpauthUrl(const std::string &username, const std::string &base32Secret)
{
    return "otpauth://totp/CLIuno:" + username + "?secret=" + base32Secret +
           "&issuer=CLIuno&algorithm=SHA1&digits=6&period=30";
}

bool verifyTotp(const std::string &base32Secret, const std::string &code)
{
    if (code.empty()) return false;
    std::string key = base32Decode(base32Secret);
    int64_t counter = std::time(nullptr) / 30;
    for (int w = -1; w <= 1; ++w)
    {
        int64_t c = counter + w;
        unsigned char msg[8];
        for (int i = 7; i >= 0; --i)
        {
            msg[i] = static_cast<unsigned char>(c & 0xFF);
            c >>= 8;
        }
        std::string h = hmac(EVP_sha1(), key, std::string(reinterpret_cast<char *>(msg), 8));
        int offset = h[h.size() - 1] & 0x0F;
        uint32_t bin = ((h[offset] & 0x7F) << 24) | ((h[offset + 1] & 0xFF) << 16) |
                       ((h[offset + 2] & 0xFF) << 8) | (h[offset + 3] & 0xFF);
        char buf[7];
        std::snprintf(buf, sizeof(buf), "%06u", bin % 1000000);
        if (code == buf) return true;
    }
    return false;
}

// -------------------------------------------------------------- auth
std::optional<int64_t> currentUserId(const HttpRequestPtr &req)
{
    std::string auth = req->getHeader("Authorization");
    const std::string prefix = "Bearer ";
    if (auth.size() <= prefix.size() || auth.compare(0, prefix.size(), prefix) != 0)
        return std::nullopt;
    return verifyJwt(auth.substr(prefix.size()), "access");
}

Json::Value userToJson(const drogon::orm::Row &row)
{
    Json::Value u(Json::objectValue);
    u["id"] = row["id"].as<int64_t>();
    u["username"] = row["username"].as<std::string>();
    u["first_name"] = row["first_name"].isNull() ? "" : row["first_name"].as<std::string>();
    u["last_name"] = row["last_name"].isNull() ? "" : row["last_name"].as<std::string>();
    u["email"] = row["email"].as<std::string>();
    u["phone"] = row["phone"].isNull() ? "" : row["phone"].as<std::string>();
    u["avatar_url"] = row["avatar_url"].isNull() ? "" : row["avatar_url"].as<std::string>();
    u["role_id"] = row["role_id"].isNull() ? 0 : row["role_id"].as<int64_t>();
    u["is_verified"] = row["is_verified"].as<int>() != 0;
    u["is_otp_enabled"] = row["is_otp_enabled"].as<int>() != 0;
    u["created_at"] = row["created_at"].isNull() ? "" : row["created_at"].as<std::string>();
    return u;
}
} // namespace cliuno
