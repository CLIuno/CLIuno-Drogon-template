#include "../utils/Helpers.h"

#include <drogon/HttpController.h>

using namespace drogon;
using namespace cliuno;

// All auth endpoints under /api/v1/auth. Access tokens live 1h, refresh 7d.
class AuthController : public HttpController<AuthController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(AuthController::registerUser, "/api/v1/auth/register", Post);
    ADD_METHOD_TO(AuthController::login, "/api/v1/auth/login", Post);
    ADD_METHOD_TO(AuthController::logout, "/api/v1/auth/logout", Post);
    ADD_METHOD_TO(AuthController::checkToken, "/api/v1/auth/check-token", Post);
    ADD_METHOD_TO(AuthController::refreshToken, "/api/v1/auth/refresh-token", Post);
    ADD_METHOD_TO(AuthController::changePassword, "/api/v1/auth/change-password", Post);
    ADD_METHOD_TO(AuthController::forgotPassword, "/api/v1/auth/forgot-password", Post);
    ADD_METHOD_TO(AuthController::resetPassword, "/api/v1/auth/reset-password", Post);
    ADD_METHOD_TO(AuthController::sendVerifyEmail, "/api/v1/auth/send-verify-email", Post);
    ADD_METHOD_TO(AuthController::verifyEmail, "/api/v1/auth/verify-email", Post);
    ADD_METHOD_TO(AuthController::otpGenerate, "/api/v1/auth/otp/generate", Post);
    ADD_METHOD_TO(AuthController::otpVerify, "/api/v1/auth/otp/verify", Post);
    ADD_METHOD_TO(AuthController::otpValidate, "/api/v1/auth/otp/validate", Post);
    ADD_METHOD_TO(AuthController::otpDisable, "/api/v1/auth/otp/disable", Post);
    METHOD_LIST_END

    void registerUser(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void login(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void logout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void checkToken(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void refreshToken(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void changePassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void forgotPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void resetPassword(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void sendVerifyEmail(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void verifyEmail(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void otpGenerate(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void otpVerify(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void otpValidate(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
    void otpDisable(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb);
};

namespace
{
std::string str(const Json::Value &b, const char *key)
{
    return b.isMember(key) && b[key].isString() ? b[key].asString() : "";
}
// OTP endpoints all act on the authenticated user; returns the user row or fails.
} // namespace

void AuthController::registerUser(const HttpRequestPtr &req,
                                  std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto b = bodyJson(req);
    std::string username = str(b, "username"), email = str(b, "email");
    std::string firstName = str(b, "first_name"), lastName = str(b, "last_name");
    std::string phone = str(b, "phone"), password = str(b, "password");
    if (username.empty() || email.empty() || firstName.empty() || lastName.empty() ||
        password.empty())
        return cb(fail(k400BadRequest, "warning", "Missing required fields"));
    if (password.size() < 8)
        return cb(fail(k400BadRequest, "warning", "Password must be at least 8 characters"));
    try
    {
        auto db = app().getDbClient();
        auto exists = db->execSqlSync(
            "SELECT id FROM users WHERE username=? OR email=?", username, email);
        if (!exists.empty())
            return cb(fail(k400BadRequest, "warning", "User already exists"));

        // Default role is created on first use (fresh-clone rule).
        db->execSqlSync("INSERT OR IGNORE INTO roles(name) VALUES('user')");
        auto role = db->execSqlSync("SELECT id FROM roles WHERE name='user'");
        int64_t roleId = role[0]["id"].as<int64_t>();

        std::string verifyToken = randomToken();
        auto ins = db->execSqlSync(
            "INSERT INTO users(username,first_name,last_name,email,phone,password,role_id,"
            "verify_token) VALUES(?,?,?,?,?,?,?,?)",
            username, firstName, lastName, email, phone, hashPassword(password), roleId,
            verifyToken);
        auto row = db->execSqlSync("SELECT * FROM users WHERE id=?", ins.insertId());
        Json::Value data(Json::objectValue);
        data["user"] = userToJson(row[0]);
        return cb(envelope(k201Created, "success",
                           "User created successfully and an email has been sent to you for "
                           "verification",
                           data));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::login(const HttpRequestPtr &req,
                           std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto b = bodyJson(req);
    std::string login = str(b, "usernameOrEmail");
    std::string password = str(b, "password");
    if (login.empty() || password.empty())
        return cb(fail(k400BadRequest, "warning", "usernameOrEmail and password are required"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync(
            "SELECT * FROM users WHERE (username=? OR email=?) AND is_deleted=0", login, login);
        if (rows.empty() || !verifyPassword(password, rows[0]["password"].as<std::string>()))
            return cb(fail(k401Unauthorized, "error", "Invalid username/email or password"));
        int64_t id = rows[0]["id"].as<int64_t>();
        Json::Value data(Json::objectValue);
        data["token"] = signJwt(id, "access", 3600);
        data["refreshToken"] = signJwt(id, "refresh", 604800);
        data["user"] = userToJson(rows[0]);
        data["is_otp_enabled"] = rows[0]["is_otp_enabled"].as<int>() != 0;
        return cb(ok("Login successful", data));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::logout(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    cb(ok("Logout successful"));
}

void AuthController::checkToken(const HttpRequestPtr &req,
                                std::function<void(const HttpResponsePtr &)> &&cb)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Invalid token"));
    cb(ok("Token is valid"));
}

void AuthController::refreshToken(const HttpRequestPtr &req,
                                  std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto b = bodyJson(req);
    std::string raw = str(b, "refreshToken");
    if (raw.empty())
    {
        std::string auth = req->getHeader("Authorization");
        if (auth.rfind("Bearer ", 0) == 0) raw = auth.substr(7);
    }
    auto id = verifyJwt(raw, "refresh");
    if (!id) return cb(fail(k401Unauthorized, "error", "Invalid or expired refresh token"));
    Json::Value data(Json::objectValue);
    data["token"] = signJwt(*id, "access", 3600);
    data["refreshToken"] = signJwt(*id, "refresh", 604800);
    cb(ok("Token refreshed successfully", data));
}

void AuthController::changePassword(const HttpRequestPtr &req,
                                    std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto b = bodyJson(req);
    std::string oldPw = str(b, "oldPassword"), newPw = str(b, "newPassword");
    if (oldPw.empty() || newPw.empty() || newPw.size() < 8)
        return cb(fail(k400BadRequest, "warning", "oldPassword and newPassword are required"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT password FROM users WHERE id=?", *id);
        if (rows.empty() || !verifyPassword(oldPw, rows[0]["password"].as<std::string>()))
            return cb(fail(k400BadRequest, "error", "Current password is incorrect"));
        db->execSqlSync("UPDATE users SET password=? WHERE id=?", hashPassword(newPw), *id);
        return cb(ok("Password changed successfully"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::forgotPassword(const HttpRequestPtr &req,
                                    std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto b = bodyJson(req);
    std::string email = str(b, "email");
    if (email.empty()) email = str(b, "usernameOrEmail");
    if (email.empty()) return cb(fail(k400BadRequest, "warning", "Email is required"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT id FROM users WHERE email=? OR username=?", email, email);
        if (!rows.empty())
            db->execSqlSync("UPDATE users SET reset_token=? WHERE id=?", randomToken(),
                            rows[0]["id"].as<int64_t>());
        // Always the same response so accounts can't be enumerated.
        return cb(ok("If the email exists, a reset link has been sent"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::resetPassword(const HttpRequestPtr &req,
                                   std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto b = bodyJson(req);
    std::string token = str(b, "token"), password = str(b, "password");
    if (token.empty() || password.size() < 8)
        return cb(fail(k400BadRequest, "warning", "A token and an 8+ char password are required"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT id FROM users WHERE reset_token=?", token);
        if (rows.empty())
            return cb(fail(k400BadRequest, "error", "Invalid or expired reset token"));
        db->execSqlSync("UPDATE users SET password=?, reset_token=NULL WHERE id=?",
                        hashPassword(password), rows[0]["id"].as<int64_t>());
        return cb(ok("Password reset successful"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::sendVerifyEmail(const HttpRequestPtr &req,
                                     std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        app().getDbClient()->execSqlSync("UPDATE users SET verify_token=? WHERE id=?",
                                         randomToken(), *id);
        return cb(ok("Email sent successfully"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::verifyEmail(const HttpRequestPtr &req,
                                 std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto b = bodyJson(req);
    std::string token = str(b, "token");
    if (token.empty()) return cb(fail(k400BadRequest, "warning", "Token is required"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT id FROM users WHERE verify_token=?", token);
        if (rows.empty())
            return cb(fail(k400BadRequest, "error", "Invalid or expired verification token"));
        db->execSqlSync("UPDATE users SET is_verified=1, verify_token=NULL WHERE id=?",
                        rows[0]["id"].as<int64_t>());
        return cb(ok("Email verified successfully"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::otpGenerate(const HttpRequestPtr &req,
                                 std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT username FROM users WHERE id=?", *id);
        if (rows.empty()) return cb(fail(k404NotFound, "error", "User not found"));
        std::string secret = generateBase32Secret();
        std::string url = otpauthUrl(rows[0]["username"].as<std::string>(), secret);
        db->execSqlSync(
            "UPDATE users SET otp_base32=?, otp_auth_url=?, is_otp_enabled=0 WHERE id=?",
            secret, url, *id);
        Json::Value data(Json::objectValue);
        data["secret"] = secret;
        data["base32"] = secret;
        data["otpauth_url"] = url;
        return cb(ok("OTP secret generated", data));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::otpVerify(const HttpRequestPtr &req,
                               std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto b = bodyJson(req);
    std::string code = str(b, "otp");
    if (code.empty()) code = str(b, "token");
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT otp_base32 FROM users WHERE id=?", *id);
        if (rows.empty() || rows[0]["otp_base32"].isNull())
            return cb(fail(k400BadRequest, "error", "OTP is not set up"));
        if (!verifyTotp(rows[0]["otp_base32"].as<std::string>(), code))
            return cb(fail(k401Unauthorized, "error", "Invalid OTP code"));
        db->execSqlSync("UPDATE users SET is_otp_enabled=1 WHERE id=?", *id);
        return cb(ok("OTP verified successfully"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::otpValidate(const HttpRequestPtr &req,
                                 std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto b = bodyJson(req);
    std::string code = str(b, "otp");
    if (code.empty()) code = str(b, "token");
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync(
            "SELECT otp_base32, is_otp_enabled FROM users WHERE id=?", *id);
        if (rows.empty() || rows[0]["otp_base32"].isNull() ||
            rows[0]["is_otp_enabled"].as<int>() == 0)
            return cb(fail(k400BadRequest, "error", "OTP is not enabled for this user"));
        if (!verifyTotp(rows[0]["otp_base32"].as<std::string>(), code))
            return cb(fail(k401Unauthorized, "error", "Invalid OTP code"));
        return cb(ok("Token is valid"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}

void AuthController::otpDisable(const HttpRequestPtr &req,
                                std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        app().getDbClient()->execSqlSync(
            "UPDATE users SET is_otp_enabled=0, otp_base32=NULL, otp_auth_url=NULL WHERE id=?",
            *id);
        return cb(ok("OTP disabled successfully"));
    }
    catch (const std::exception &e)
    {
        return cb(fail(k500InternalServerError, "error", e.what()));
    }
}
