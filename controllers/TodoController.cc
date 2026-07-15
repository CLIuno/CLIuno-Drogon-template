#include "../utils/Helpers.h"

#include <drogon/HttpController.h>

using namespace drogon;
using namespace cliuno;

// /api/v1/todos — all scoped to the authenticated owner.
class TodoController : public HttpController<TodoController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(TodoController::currentUser, "/api/v1/todos/current-user", Get);
    ADD_METHOD_TO(TodoController::list, "/api/v1/todos", Get);
    ADD_METHOD_TO(TodoController::create, "/api/v1/todos", Post);
    ADD_METHOD_TO(TodoController::toggle, "/api/v1/todos/{id}/toggle", Patch);
    ADD_METHOD_TO(TodoController::show, "/api/v1/todos/{id}", Get);
    ADD_METHOD_TO(TodoController::update, "/api/v1/todos/{id}", Patch);
    ADD_METHOD_TO(TodoController::remove, "/api/v1/todos/{id}", Delete);
    METHOD_LIST_END

    void list(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void currentUser(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void create(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void show(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void update(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void toggle(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void remove(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
};

namespace
{
Json::Value todoJson(const orm::Row &r)
{
    Json::Value t(Json::objectValue);
    t["id"] = r["id"].as<int64_t>();
    t["user_id"] = r["user_id"].as<int64_t>();
    t["title"] = r["title"].as<std::string>();
    t["description"] = r["description"].isNull() ? "" : r["description"].as<std::string>();
    t["is_completed"] = r["is_completed"].as<int>() != 0;
    t["created_at"] = r["created_at"].isNull() ? "" : r["created_at"].as<std::string>();
    return t;
}
std::string strv(const Json::Value &b, const char *k)
{
    return b.isMember(k) && b[k].isString() ? b[k].asString() : "";
}
} // namespace

void TodoController::list(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto rows = app().getDbClient()->execSqlSync(
        "SELECT * FROM todos WHERE user_id=? ORDER BY id DESC", *id);
    Json::Value arr(Json::arrayValue);
    for (auto &r : rows) arr.append(todoJson(r));
    Json::Value data(Json::objectValue);
    data["todos"] = arr;
    cb(ok("Todos fetched", data));
}

void TodoController::currentUser(const HttpRequestPtr &req,
                                 std::function<void(const HttpResponsePtr &)> &&cb)
{
    list(req, std::move(cb));
}

void TodoController::create(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto b = bodyJson(req);
    std::string title = strv(b, "title");
    if (title.empty()) return cb(fail(k400BadRequest, "warning", "Title is required"));
    auto db = app().getDbClient();
    auto ins = db->execSqlSync(
        "INSERT INTO todos(user_id,title,description) VALUES(?,?,?)", *id, title,
        strv(b, "description"));
    auto rows = db->execSqlSync("SELECT * FROM todos WHERE id=?", ins.insertId());
    Json::Value data(Json::objectValue);
    data["todo"] = todoJson(rows[0]);
    cb(envelope(k201Created, "success", "Todo created", data));
}

void TodoController::show(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT * FROM todos WHERE id=? AND user_id=?", std::stoll(id), *uid);
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Todo not found"));
        Json::Value data(Json::objectValue);
        data["todo"] = todoJson(rows[0]);
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Todo not found"));
    }
}

void TodoController::update(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto b = bodyJson(req);
        auto db = app().getDbClient();
        db->execSqlSync(
            "UPDATE todos SET title=COALESCE(?,title), description=COALESCE(?,description) "
            "WHERE id=? AND user_id=?",
            strv(b, "title"), strv(b, "description"), std::stoll(id), *uid);
        auto rows = db->execSqlSync("SELECT * FROM todos WHERE id=? AND user_id=?",
                                    std::stoll(id), *uid);
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Todo not found"));
        Json::Value data(Json::objectValue);
        data["todo"] = todoJson(rows[0]);
        cb(ok("Todo updated", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Todo not found"));
    }
}

void TodoController::toggle(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        db->execSqlSync(
            "UPDATE todos SET is_completed=1-is_completed WHERE id=? AND user_id=?",
            std::stoll(id), *uid);
        auto rows = db->execSqlSync("SELECT * FROM todos WHERE id=? AND user_id=?",
                                    std::stoll(id), *uid);
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Todo not found"));
        Json::Value data(Json::objectValue);
        data["todo"] = todoJson(rows[0]);
        cb(ok("Todo toggled", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Todo not found"));
    }
}

void TodoController::remove(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT * FROM todos WHERE id=? AND user_id=?",
                                    std::stoll(id), *uid);
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Todo not found"));
        Json::Value data(Json::objectValue);
        data["todo"] = todoJson(rows[0]);
        db->execSqlSync("DELETE FROM todos WHERE id=? AND user_id=?", std::stoll(id), *uid);
        cb(ok("Todo deleted", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Todo not found"));
    }
}
