#include "../utils/Helpers.h"

#include <drogon/HttpController.h>

using namespace drogon;
using namespace cliuno;

// /api/v1/users. GET /users is authenticated (not admin); PATCH/DELETE /users/:id
// are admin-gated (403 for normal users is a valid contract).
class UserController : public HttpController<UserController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(UserController::list, "/api/v1/users", Get);
    ADD_METHOD_TO(UserController::current, "/api/v1/users/current", Get);
    ADD_METHOD_TO(UserController::updateCurrent, "/api/v1/users/current", Patch);
    ADD_METHOD_TO(UserController::deleteCurrent, "/api/v1/users/current", Delete);
    ADD_METHOD_TO(UserController::byUsername, "/api/v1/users/username/{name}", Get);
    ADD_METHOD_TO(UserController::posts, "/api/v1/users/{id}/posts", Get);
    ADD_METHOD_TO(UserController::roles, "/api/v1/users/{id}/roles", Get);
    ADD_METHOD_TO(UserController::byId, "/api/v1/users/{id}", Get);
    ADD_METHOD_TO(UserController::update, "/api/v1/users/{id}", Patch);
    ADD_METHOD_TO(UserController::remove, "/api/v1/users/{id}", Delete);
    METHOD_LIST_END

    void list(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void current(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void updateCurrent(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void deleteCurrent(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void byUsername(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void posts(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void roles(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void byId(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void update(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void remove(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
};

namespace
{
bool isAdmin(const orm::DbClientPtr &db, int64_t userId)
{
    auto rows = db->execSqlSync(
        "SELECT r.name FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?", userId);
    return !rows.empty() && rows[0]["name"].as<std::string>() == "admin";
}
std::string strv(const Json::Value &b, const char *k)
{
    return b.isMember(k) && b[k].isString() ? b[k].asString() : "";
}
} // namespace

void UserController::list(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto db = app().getDbClient();
    auto rows = db->execSqlSync("SELECT * FROM users WHERE is_deleted=0 ORDER BY id");
    Json::Value users(Json::arrayValue);
    for (auto &r : rows) users.append(userToJson(r));
    Json::Value data(Json::objectValue);
    data["users"] = users;
    cb(ok("Users fetched successfully", data));
}

void UserController::current(const HttpRequestPtr &req,
                             std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto rows = app().getDbClient()->execSqlSync("SELECT * FROM users WHERE id=?", *id);
    if (rows.empty()) return cb(fail(k404NotFound, "error", "User not found"));
    Json::Value data(Json::objectValue);
    data["user"] = userToJson(rows[0]);
    cb(ok("", data));
}

void UserController::updateCurrent(const HttpRequestPtr &req,
                                   std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto b = bodyJson(req);
    auto db = app().getDbClient();
    db->execSqlSync(
        "UPDATE users SET first_name=COALESCE(?,first_name), last_name=COALESCE(?,last_name),"
        "phone=COALESCE(?,phone) WHERE id=?",
        strv(b, "first_name"), strv(b, "last_name"), strv(b, "phone"), *id);
    auto rows = db->execSqlSync("SELECT * FROM users WHERE id=?", *id);
    Json::Value data(Json::objectValue);
    data["user"] = userToJson(rows[0]);
    cb(ok("User updated", data));
}

void UserController::deleteCurrent(const HttpRequestPtr &req,
                                   std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto db = app().getDbClient();
    db->execSqlSync("UPDATE users SET is_deleted=1 WHERE id=?", *id);
    auto rows = db->execSqlSync("SELECT * FROM users WHERE id=?", *id);
    Json::Value data(Json::objectValue);
    data["user"] = userToJson(rows[0]);
    cb(ok("User deleted", data));
}

void UserController::byUsername(const HttpRequestPtr &req,
                                std::function<void(const HttpResponsePtr &)> &&cb,
                                std::string name)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto rows = app().getDbClient()->execSqlSync(
        "SELECT * FROM users WHERE username=?", name);
    if (rows.empty()) return cb(fail(k404NotFound, "warning", "User not found"));
    Json::Value data(Json::objectValue);
    data["user"] = userToJson(rows[0]);
    cb(ok("", data));
}

void UserController::posts(const HttpRequestPtr &req,
                           std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT * FROM posts WHERE user_id=? ORDER BY id DESC", std::stoll(id));
        Json::Value posts(Json::arrayValue);
        for (auto &r : rows)
        {
            Json::Value p(Json::objectValue);
            p["id"] = r["id"].as<int64_t>();
            p["user_id"] = r["user_id"].as<int64_t>();
            p["title"] = r["title"].as<std::string>();
            p["content"] = r["content"].isNull() ? "" : r["content"].as<std::string>();
            p["image_url"] = r["image_url"].isNull() ? "" : r["image_url"].as<std::string>();
            posts.append(p);
        }
        Json::Value data(Json::objectValue);
        data["posts"] = posts;
        cb(ok("Posts", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void UserController::roles(const HttpRequestPtr &req,
                           std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT r.id, r.name FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?",
            std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "User not found"));
        Json::Value role(Json::objectValue);
        role["id"] = rows[0]["id"].as<int64_t>();
        role["name"] = rows[0]["name"].as<std::string>();
        Json::Value data(Json::objectValue);
        data["role"] = role;
        cb(ok("Role found", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void UserController::byId(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT * FROM users WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "User not found"));
        Json::Value data(Json::objectValue);
        data["user"] = userToJson(rows[0]);
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void UserController::update(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto db = app().getDbClient();
    if (!isAdmin(db, *uid))
        return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    try
    {
        auto b = bodyJson(req);
        db->execSqlSync(
            "UPDATE users SET first_name=COALESCE(?,first_name),last_name=COALESCE(?,last_name),"
            "phone=COALESCE(?,phone) WHERE id=?",
            strv(b, "first_name"), strv(b, "last_name"), strv(b, "phone"), std::stoll(id));
        auto rows = db->execSqlSync("SELECT * FROM users WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "User not found"));
        Json::Value data(Json::objectValue);
        data["user"] = userToJson(rows[0]);
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void UserController::remove(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto db = app().getDbClient();
    if (!isAdmin(db, *uid))
        return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    try
    {
        db->execSqlSync("UPDATE users SET is_deleted=1 WHERE id=?", std::stoll(id));
        auto rows = db->execSqlSync("SELECT * FROM users WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "User not found"));
        Json::Value data(Json::objectValue);
        data["user"] = userToJson(rows[0]);
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}
