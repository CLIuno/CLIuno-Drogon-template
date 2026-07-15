#include "../utils/Helpers.h"

#include <drogon/HttpController.h>

using namespace drogon;
using namespace cliuno;

// /api/v1/posts — posts carry their author (data.post.user) and comments.
class PostController : public HttpController<PostController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(PostController::currentUser, "/api/v1/posts/current-user", Get);
    ADD_METHOD_TO(PostController::list, "/api/v1/posts", Get);
    ADD_METHOD_TO(PostController::create, "/api/v1/posts", Post);
    ADD_METHOD_TO(PostController::postUser, "/api/v1/posts/{id}/user", Get);
    ADD_METHOD_TO(PostController::show, "/api/v1/posts/{id}", Get);
    ADD_METHOD_TO(PostController::update, "/api/v1/posts/{id}", Patch);
    ADD_METHOD_TO(PostController::remove, "/api/v1/posts/{id}", Delete);
    METHOD_LIST_END

    void list(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void currentUser(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void create(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void show(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void update(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void remove(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void postUser(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
};

// Shared by PostController and CommentController.
namespace cliuno
{
Json::Value postJson(const orm::DbClientPtr &db, const orm::Row &r)
{
    int64_t pid = r["id"].as<int64_t>();
    int64_t uid = r["user_id"].as<int64_t>();
    Json::Value p(Json::objectValue);
    p["id"] = pid;
    p["user_id"] = uid;
    p["title"] = r["title"].as<std::string>();
    p["content"] = r["content"].isNull() ? "" : r["content"].as<std::string>();
    p["image_url"] = r["image_url"].isNull() ? "" : r["image_url"].as<std::string>();
    p["created_at"] = r["created_at"].isNull() ? "" : r["created_at"].as<std::string>();

    auto us = db->execSqlSync("SELECT * FROM users WHERE id=?", uid);
    if (!us.empty()) p["user"] = userToJson(us[0]);

    auto cs = db->execSqlSync(
        "SELECT * FROM comments WHERE post_id=? ORDER BY id", pid);
    Json::Value comments(Json::arrayValue);
    for (auto &c : cs)
    {
        Json::Value cj(Json::objectValue);
        cj["id"] = c["id"].as<int64_t>();
        cj["post_id"] = c["post_id"].as<int64_t>();
        cj["user_id"] = c["user_id"].as<int64_t>();
        cj["content"] = c["content"].as<std::string>();
        auto cu = db->execSqlSync("SELECT * FROM users WHERE id=?", c["user_id"].as<int64_t>());
        if (!cu.empty()) cj["user"] = userToJson(cu[0]);
        comments.append(cj);
    }
    p["comments"] = comments;
    return p;
}
} // namespace cliuno

namespace
{
std::string strv(const Json::Value &b, const char *k)
{
    return b.isMember(k) && b[k].isString() ? b[k].asString() : "";
}
} // namespace

void PostController::list(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto db = app().getDbClient();
    auto rows = db->execSqlSync("SELECT * FROM posts ORDER BY id DESC");
    Json::Value arr(Json::arrayValue);
    for (auto &r : rows) arr.append(postJson(db, r));
    Json::Value data(Json::objectValue);
    data["posts"] = arr;
    cb(ok("Posts fetched", data));
}

void PostController::currentUser(const HttpRequestPtr &req,
                                 std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto db = app().getDbClient();
    auto rows = db->execSqlSync("SELECT * FROM posts WHERE user_id=? ORDER BY id DESC", *id);
    Json::Value arr(Json::arrayValue);
    for (auto &r : rows) arr.append(postJson(db, r));
    Json::Value data(Json::objectValue);
    data["posts"] = arr;
    cb(ok("Posts fetched", data));
}

void PostController::create(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto b = bodyJson(req);
    std::string title = strv(b, "title");
    if (title.empty()) return cb(fail(k400BadRequest, "warning", "Title is required"));
    auto db = app().getDbClient();
    auto ins = db->execSqlSync(
        "INSERT INTO posts(user_id,title,content,image_url) VALUES(?,?,?,?)", *id, title,
        strv(b, "content"), strv(b, "image_url"));
    auto rows = db->execSqlSync("SELECT * FROM posts WHERE id=?", ins.insertId());
    Json::Value data(Json::objectValue);
    data["post"] = postJson(db, rows[0]);
    cb(envelope(k201Created, "success", "Post created", data));
}

void PostController::show(const HttpRequestPtr &req,
                          std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT * FROM posts WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Post not found"));
        Json::Value data(Json::objectValue);
        data["post"] = postJson(db, rows[0]);
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Post not found"));
    }
}

void PostController::update(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto b = bodyJson(req);
        auto db = app().getDbClient();
        db->execSqlSync(
            "UPDATE posts SET title=COALESCE(?,title), content=COALESCE(?,content), "
            "image_url=COALESCE(?,image_url) WHERE id=? AND user_id=?",
            strv(b, "title"), strv(b, "content"), strv(b, "image_url"), std::stoll(id), *uid);
        auto rows = db->execSqlSync("SELECT * FROM posts WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Post not found"));
        Json::Value data(Json::objectValue);
        data["post"] = postJson(db, rows[0]);
        cb(ok("Post updated", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Post not found"));
    }
}

void PostController::remove(const HttpRequestPtr &req,
                            std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync("SELECT * FROM posts WHERE id=?", std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Post not found"));
        Json::Value data(Json::objectValue);
        data["post"] = postJson(db, rows[0]);
        db->execSqlSync("DELETE FROM comments WHERE post_id=?", std::stoll(id));
        db->execSqlSync("DELETE FROM posts WHERE id=? AND user_id=?", std::stoll(id), *uid);
        cb(ok("Post deleted", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Post not found"));
    }
}

void PostController::postUser(const HttpRequestPtr &req,
                              std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync(
            "SELECT u.* FROM posts p JOIN users u ON p.user_id=u.id WHERE p.id=?",
            std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Post not found"));
        Json::Value data(Json::objectValue);
        data["user"] = userToJson(rows[0]);
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Post not found"));
    }
}
