#include "../utils/Helpers.h"

#include <drogon/HttpController.h>

using namespace drogon;
using namespace cliuno;

// /api/v1/roles — admin only. Frontends don't call these directly, but the
// contract defines them; non-admins get 403.
class RoleController : public HttpController<RoleController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(RoleController::list, "/api/v1/roles", Get);
    ADD_METHOD_TO(RoleController::create, "/api/v1/roles", Post);
    ADD_METHOD_TO(RoleController::usersOf, "/api/v1/roles/{id}/users", Get);
    ADD_METHOD_TO(RoleController::show, "/api/v1/roles/{id}", Get);
    ADD_METHOD_TO(RoleController::update, "/api/v1/roles/{id}", Patch);
    ADD_METHOD_TO(RoleController::remove, "/api/v1/roles/{id}", Delete);
    METHOD_LIST_END

    void list(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void create(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void show(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void update(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void remove(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void usersOf(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
};

namespace
{
// Returns the caller's user id if they are an admin, else empty.
std::optional<int64_t> requireAdmin(const HttpRequestPtr &req)
{
    auto uid = currentUserId(req);
    if (!uid) return std::nullopt;
    auto rows = app().getDbClient()->execSqlSync(
        "SELECT r.name FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?", *uid);
    if (rows.empty() || rows[0]["name"].as<std::string>() != "admin") return std::nullopt;
    return uid;
}
Json::Value roleJson(const orm::Row &r)
{
    Json::Value j(Json::objectValue);
    j["id"] = r["id"].as<int64_t>();
    j["name"] = r["name"].as<std::string>();
    return j;
}
std::string strv(const Json::Value &b, const char *k)
{
    return b.isMember(k) && b[k].isString() ? b[k].asString() : "";
}
} // namespace

void RoleController::list(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb)
{
    if (!requireAdmin(req)) return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    auto rows = app().getDbClient()->execSqlSync("SELECT * FROM roles ORDER BY id");
    Json::Value arr(Json::arrayValue);
    for (auto &r : rows) arr.append(roleJson(r));
    Json::Value data(Json::objectValue);
    data["roles"] = arr;
    cb(ok("Roles fetched", data));
}

void RoleController::create(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb)
{
    if (!requireAdmin(req)) return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    auto b = bodyJson(req);
    std::string name = strv(b, "name");
    if (name.empty()) return cb(fail(k400BadRequest, "warning", "Name is required"));
    auto db = app().getDbClient();
    auto ins = db->execSqlSync("INSERT INTO roles(name) VALUES(?)", name);
    auto rows = db->execSqlSync("SELECT * FROM roles WHERE id=?", ins.insertId());
    Json::Value data(Json::objectValue);
    data["role"] = roleJson(rows[0]);
    cb(envelope(k201Created, "success", "Role created", data));
}

void RoleController::show(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!requireAdmin(req)) return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync("SELECT * FROM roles WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Role not found"));
        Json::Value data(Json::objectValue);
        data["role"] = roleJson(rows[0]);
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Role not found"));
    }
}

void RoleController::update(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!requireAdmin(req)) return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    try
    {
        auto b = bodyJson(req);
        auto db = app().getDbClient();
        db->execSqlSync("UPDATE roles SET name=COALESCE(?,name) WHERE id=?", strv(b, "name"),
                        std::stoll(id));
        auto rows = db->execSqlSync("SELECT * FROM roles WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Role not found"));
        Json::Value data(Json::objectValue);
        data["role"] = roleJson(rows[0]);
        cb(ok("Role updated", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Role not found"));
    }
}

void RoleController::remove(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!requireAdmin(req)) return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    try
    {
        app().getDbClient()->execSqlSync("DELETE FROM roles WHERE id=?", std::stoll(id));
        cb(ok("Role deleted"));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Role not found"));
    }
}

void RoleController::usersOf(const HttpRequestPtr &req,
                             std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!requireAdmin(req)) return cb(fail(k403Forbidden, "error", "Forbidden: Permission denied"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT * FROM users WHERE role_id=? AND is_deleted=0", std::stoll(id));
        Json::Value arr(Json::arrayValue);
        for (auto &r : rows) arr.append(userToJson(r));
        Json::Value data(Json::objectValue);
        data["users"] = arr;
        cb(ok("Users fetched", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Role not found"));
    }
}
