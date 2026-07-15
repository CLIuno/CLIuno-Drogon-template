# CLIuno Drogon template

The CLIuno demo app as a **Drogon (C++17)** REST API — auth (JWT with refresh, reset,
email verification, OTP), users, todos, posts + comments, follows and roles — serving the
shared CLIuno contract under `/api/v1` on SQLite. Registering the first user creates the
`user` role automatically, so a fresh clone works against an empty database.

## Build & run

Drogon and its toolchain are easiest to get from the official image:

```bash
# build
docker run --rm -v "$PWD":/app -w /app -e CC=gcc-11 -e CXX=g++-11 \
  drogonframework/drogon:latest \
  bash -lc "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc)"

# run (serves http://localhost:3000/api/v1)
docker run --rm -v "$PWD":/app -w /app -p 3000:3000 \
  drogonframework/drogon:latest bash -lc "./build/cliuno_drogon"
```

Or, with Drogon installed locally (`cmake`, `drogon`, `sqlite3`, `openssl`, `jsoncpp`):

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
PORT=3000 ./build/cliuno_drogon
```

`PORT`, `DB_FILE`, and `JWT_SECRET_KEY` are read from the environment (see `.env.example`).

## Layout

- `main.cc` — listener + SQLite schema creation on startup.
- `utils/Helpers.{h,cc}` — JSON envelopes, PBKDF2 password hashing, HS256 JWTs,
  RFC 6238 TOTP, and Bearer authentication (all on OpenSSL).
- `controllers/` — one Drogon `HttpController` per resource (Auth, User, Todo, Post,
  Comment, Follow, Role), routes declared with `ADD_METHOD_TO("/api/v1/...")`.

## The API contract

Login sends `{usernameOrEmail, password}` and returns `data.token` (+ `data.refreshToken`).
Every response is `{status, message, data}` with the exact keys CLIuno frontends
destructure (`data.users/user/todos/todo/posts/post/followers/following/isFollowing`).
Request keys are camelCase; resource fields are snake_case. Any CLIuno frontend template
works against this backend.
