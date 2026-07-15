#include "../utils/Helpers.h"

#include <drogon/HttpController.h>

using namespace drogon;
using namespace cliuno;

// /api/v1/follows/{id}/... — {id} is the target user; the Bearer user is the actor.
class FollowController : public HttpController<FollowController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(FollowController::follow, "/api/v1/follows/{id}/follow", Post);
    ADD_METHOD_TO(FollowController::unfollow, "/api/v1/follows/{id}/follow", Delete);
    ADD_METHOD_TO(FollowController::followers, "/api/v1/follows/{id}/followers", Get);
    ADD_METHOD_TO(FollowController::following, "/api/v1/follows/{id}/following", Get);
    ADD_METHOD_TO(FollowController::isFollowing, "/api/v1/follows/{id}/is-following", Get);
    METHOD_LIST_END

    void follow(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void unfollow(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void followers(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void following(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
    void isFollowing(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
};

void FollowController::follow(const HttpRequestPtr &req,
                              std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        int64_t target = std::stoll(id);
        if (target == *uid) return cb(fail(k400BadRequest, "warning", "You cannot follow yourself"));
        app().getDbClient()->execSqlSync(
            "INSERT OR IGNORE INTO follows(follower_id,following_id) VALUES(?,?)", *uid, target);
        cb(ok("Followed successfully"));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void FollowController::unfollow(const HttpRequestPtr &req,
                                std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        app().getDbClient()->execSqlSync(
            "DELETE FROM follows WHERE follower_id=? AND following_id=?", *uid, std::stoll(id));
        cb(ok("Unfollowed successfully"));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void FollowController::followers(const HttpRequestPtr &req,
                                 std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT u.* FROM follows f JOIN users u ON f.follower_id=u.id WHERE f.following_id=?",
            std::stoll(id));
        Json::Value arr(Json::arrayValue);
        for (auto &r : rows) arr.append(userToJson(r));
        Json::Value data(Json::objectValue);
        data["followers"] = arr;
        cb(ok("Followers fetched", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void FollowController::following(const HttpRequestPtr &req,
                                 std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    if (!currentUserId(req)) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT u.* FROM follows f JOIN users u ON f.following_id=u.id WHERE f.follower_id=?",
            std::stoll(id));
        Json::Value arr(Json::arrayValue);
        for (auto &r : rows) arr.append(userToJson(r));
        Json::Value data(Json::objectValue);
        data["following"] = arr;
        cb(ok("Following fetched", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}

void FollowController::isFollowing(const HttpRequestPtr &req,
                                   std::function<void(const HttpResponsePtr &)> &&cb, std::string id)
{
    auto uid = currentUserId(req);
    if (!uid) return cb(fail(k401Unauthorized, "error", "Unauthorized"));
    try
    {
        auto rows = app().getDbClient()->execSqlSync(
            "SELECT 1 FROM follows WHERE follower_id=? AND following_id=?", *uid, std::stoll(id));
        Json::Value data(Json::objectValue);
        data["isFollowing"] = !rows.empty();
        cb(ok("", data));
    }
    catch (...)
    {
        cb(fail(k404NotFound, "warning", "User not found"));
    }
}
