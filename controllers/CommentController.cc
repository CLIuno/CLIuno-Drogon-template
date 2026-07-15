#include "../utils/Helpers.h"

#include <drogon/HttpController.h>

using namespace drogon;
using namespace cliuno;

// Comments nested under /api/v1/posts/{id}/comments.
class CommentController : public HttpController<CommentController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(CommentController::list, "/api/v1/posts/{id}/comments", Get);
    ADD_METHOD_TO(CommentController::create, "/api/v1/posts/{id}/comments", Post);
    ADD_METHOD_TO(CommentController::update, "/api/v1/posts/{id}/comments/{commentId}", Patch);
    ADD_METHOD_TO(CommentController::remove, "/api/v1/posts/{id}/comments/{commentId}", Delete);
    METHOD_LIST_END

    void list(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void create(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void update(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string, std::string);
    void remove(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string, std::string);
};

namespace
{
Json::Value commentJson(const orm::DbClientPtr &db, const orm::Row &c)
{
    Json::Value cj(Json::objectValue);
    cj["id"] = c["id"].as<int64_t>();
    cj["post_id"] = c["post_id"].as<int64_t>();
    cj["user_id"] = c["user_id"].as<int64_t>();
    cj["content"] = c["content"].as<std::string>();
    cj["created_at"] = c["created_at"].isNull() ? "" : c["created_at"].as<std::string>();
    auto u = db->execSqlSync("SELECT * FROM users WHERE id=?", c["user_id"].as<int64_t>());
    if (!u.empty()) cj["user"] = userToJson(u[0]);
    return cj;
}
std::string strv(const Json::Value &b, const char *k)
{
    return b.isMember(k) && b[k].isString() ? b[k].asString() : "";
}
} // namespace

void CommentController::list(const HttpRequestPtr &req,
                             std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync(
            "SELECT * FROM comments WHERE post_id=? ORDER BY id", std::stoll(id));
        Json::Value arr(Json::arrayValue);
        for (auto &c : rows) arr.append(commentJson(db, c));
        Json::Value data(Json::objectValue);
        data["comments"] = arr;
        cb(ok("Comments fetched", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Post not found"));
    }
}

void CommentController::create(const HttpRequestPtr &req,
                               std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    auto b = bodyJson(req);
    std::string content = strv(b, "content");
    if (content.empty()) return cb(fail(k400BadRequest, "warning", "Content is required"));
    try
    {
        auto db = app().getDbClient();
        auto post = db->execSqlSync("SELECT id FROM posts WHERE id=?", std::stoll(id));
        if (post.empty()) return cb(fail(k404NotFound, "warning", "Post not found"));
        auto ins = db->execSqlSync(
            "INSERT INTO comments(post_id,user_id,content) VALUES(?,?,?)", std::stoll(id),
            *uid, content);
        auto rows = db->execSqlSync("SELECT * FROM comments WHERE id=?", ins.insertId());
        Json::Value data(Json::objectValue);
        data["comment"] = commentJson(db, rows[0]);
        cb(envelope(k201Created, "success", "Comment created", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Post not found"));
    }
}

void CommentController::update(const HttpRequestPtr &req,
                               std::function<void(const HttpResponsePtr &)> &&cb,
                               std::string id, std::string commentId)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto b = bodyJson(req);
        auto db = app().getDbClient();
        db->execSqlSync(
            "UPDATE comments SET content=COALESCE(?,content) WHERE id=? AND post_id=? AND user_id=?",
            strv(b, "content"), std::stoll(commentId), std::stoll(id), *uid);
        auto rows = db->execSqlSync("SELECT * FROM comments WHERE id=?", std::stoll(commentId));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Comment not found"));
        Json::Value data(Json::objectValue);
        data["comment"] = commentJson(db, rows[0]);
        cb(ok("Comment updated", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Comment not found"));
    }
}

void CommentController::remove(const HttpRequestPtr &req,
                               std::function<void(const HttpResponsePtr &)> &&cb,
                               std::string id, std::string commentId)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto db = app().getDbClient();
        auto rows = db->execSqlSync(
            "SELECT * FROM comments WHERE id=? AND post_id=?", std::stoll(commentId),
            std::stoll(id));
        if (rows.empty()) return cb(fail(k404NotFound, "warning", "Comment not found"));
        Json::Value data(Json::objectValue);
        data["comment"] = commentJson(db, rows[0]);
        db->execSqlSync("DELETE FROM comments WHERE id=? AND user_id=?", std::stoll(commentId),
                        *uid);
        cb(ok("Comment deleted", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "Comment not found"));
    }
}
