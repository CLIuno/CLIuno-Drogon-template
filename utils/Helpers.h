#pragma once

#include <drogon/HttpController.h>
#include <json/json.h>

#include <optional>
#include <string>

// Shared helpers for the CLIuno contract: JSON envelopes, password hashing,
// JWT (HS256), RFC 6238 TOTP, and Bearer authentication.
namespace cliuno
{
using drogon::HttpRequestPtr;
using drogon::HttpResponsePtr;
using drogon::HttpStatusCode;

// ---- response envelopes: every response is { status, message?, data } ----
HttpResponsePtr envelope(HttpStatusCode code,
                         const std::string &status,
                         const std::string &message,
                         const Json::Value &data = Json::Value(Json::objectValue));

HttpResponsePtr ok(const std::string &message, const Json::Value &data);
HttpResponsePtr ok(const std::string &message);
HttpResponsePtr fail(HttpStatusCode code, const std::string &status, const std::string &message);

// Parse a JSON request body; returns objectValue (possibly empty) never null.
Json::Value bodyJson(const HttpRequestPtr &req);

// ---- crypto ----
std::string hashPassword(const std::string &password);
bool verifyPassword(const std::string &password, const std::string &stored);
std::string randomToken(int bytes = 20); // hex token for reset/verify links

// JWT HS256. Payload carries the user id and a type ("access" | "refresh").
std::string signJwt(int64_t userId, const std::string &type, int ttlSeconds);
// Returns the user id if the token is valid, of the requested type, and unexpired.
std::optional<int64_t> verifyJwt(const std::string &token, const std::string &type);

// ---- TOTP (sha1 / 6 digits / 30s) ----
std::string generateBase32Secret();
std::string otpauthUrl(const std::string &username, const std::string &base32Secret);
bool verifyTotp(const std::string &base32Secret, const std::string &code);

// ---- auth ----
// Extracts and validates the Bearer access token; returns the authenticated
// user id, or std::nullopt when missing/invalid.
std::optional<int64_t> currentUserId(const HttpRequestPtr &req);

// Serialises a user row (from `SELECT * FROM users`) into the contract shape,
// omitting secret columns.
Json::Value userToJson(const drogon::orm::Row &row);
} // namespace cliuno
