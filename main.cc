#include <drogon/drogon.h>

#include <cstdlib>
#include <string>
#include <vector>

using namespace drogon;

// The CLIuno demo app on Drogon (C++). Serves the shared REST contract under
// /api/v1 on SQLite. Schema is created on first boot, so a fresh clone works
// against an empty database with no seed step.
int main()
{
    const char *portEnv = std::getenv("PORT");
    const uint16_t port = portEnv ? static_cast<uint16_t>(std::stoi(portEnv)) : 3000;
    const char *dbEnv = std::getenv("DB_FILE");
    const std::string dbFile = dbEnv ? dbEnv : "cliuno.db";

    app().addListener("0.0.0.0", port);
    app().setThreadNum(1); // one worker keeps the single sqlite connection simple
    app().createDbClient("sqlite3", "", 0, "", "", "", 1, dbFile, "default");

    app().registerBeginningAdvice([]() {
        auto db = app().getDbClient();
        const std::vector<std::string> schema = {
            "CREATE TABLE IF NOT EXISTS roles ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)",

            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "username TEXT UNIQUE NOT NULL, first_name TEXT, last_name TEXT,"
            "email TEXT UNIQUE NOT NULL, phone TEXT, password TEXT NOT NULL,"
            "avatar_url TEXT,"
            "role_id INTEGER,"
            "is_verified INTEGER NOT NULL DEFAULT 0,"
            "is_deleted INTEGER NOT NULL DEFAULT 0,"
            "is_otp_enabled INTEGER NOT NULL DEFAULT 0,"
            "reset_token TEXT, verify_token TEXT, otp_base32 TEXT, otp_auth_url TEXT,"
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))",

            "CREATE TABLE IF NOT EXISTS todos ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,"
            "title TEXT NOT NULL, description TEXT,"
            "is_completed INTEGER NOT NULL DEFAULT 0,"
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))",

            "CREATE TABLE IF NOT EXISTS posts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,"
            "title TEXT NOT NULL, content TEXT, image_url TEXT,"
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))",

            "CREATE TABLE IF NOT EXISTS comments ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL,"
            "user_id INTEGER NOT NULL, content TEXT NOT NULL,"
            "created_at TEXT NOT NULL DEFAULT (datetime('now')))",

            "CREATE TABLE IF NOT EXISTS follows ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, follower_id INTEGER NOT NULL,"
            "following_id INTEGER NOT NULL,"
            "created_at TEXT NOT NULL DEFAULT (datetime('now')),"
            "UNIQUE(follower_id, following_id))"};
        for (const auto &sql : schema) db->execSqlSync(sql);
        // Databases created before avatar_url existed: add it, ignore "duplicate column".
        try
        {
            db->execSqlSync("ALTER TABLE users ADD COLUMN avatar_url TEXT");
        }
        catch (const std::exception &)
        {
        }
        LOG_INFO << "CLIuno Drogon schema ready";
    });

    LOG_INFO << "CLIuno Drogon listening on :" << port;
    app().run();
    return 0;
}
