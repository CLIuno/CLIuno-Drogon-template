# CLIuno Drogon template

Drogon (C++17) REST API serving the CLIuno contract under `/api/v1` on SQLite: JWT auth
(refresh, reset, email verification, OTP), users, todos, posts+comments, follows, roles.

## Commands

Build/run via the official Drogon image (no local Drogon needed). The image ships
`gcc-11`/`clang-14` **without** the unversioned `g++`/`gcc` symlinks, so pass `CC`/`CXX`:

```bash
docker run --rm -v "$PWD":/app -w /app -e CC=gcc-11 -e CXX=g++-11 \
  drogonframework/drogon:latest \
  bash -lc "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j\$(nproc)"

docker run --rm -v "$PWD":/app -w /app -p 3000:3000 -e PORT=3000 \
  drogonframework/drogon:latest bash -lc "./build/cliuno_drogon"
```

`PORT` (default 3000), `DB_FILE` (default `cliuno.db`), `JWT_SECRET_KEY` come from the env.

## Structure

- `main.cc` — `app().addListener` + `createDbClient("sqlite3", …)` + a
  `registerBeginningAdvice` that runs `CREATE TABLE IF NOT EXISTS` for every table.
  `setThreadNum(1)` keeps the single sqlite connection simple.
- `utils/Helpers.{h,cc}` — everything crypto/JSON:
  - `envelope/ok/fail` build the `{status, message, data}` responses.
  - `hashPassword`/`verifyPassword` = PBKDF2-HMAC-SHA256 (`pbkdf2$iter$salt$hash`).
  - `signJwt`/`verifyJwt` = HS256 with OpenSSL HMAC + base64url, payload `{sub,type,exp}`;
    `type` is `access` (1h) or `refresh` (7d).
  - `generateBase32Secret`/`verifyTotp` = RFC 6238 TOTP (sha1/6/30s, ±1 window).
  - `currentUserId(req)` pulls the Bearer access token → user id; `userToJson` omits
    secret columns.
- `controllers/*.cc` — each is a self-contained `HttpController<T>` with `METHOD_LIST` +
  `ADD_METHOD_TO(func, "/api/v1/...", Method)`. Path params arrive as trailing
  `std::string` args (converted with `std::stoll`). DB access is
  `app().getDbClient()->execSqlSync("... ?", args...)` (sqlite `?` placeholders).

## Contract rules this codebase follows

- Responses `{status, message, data}` with the exact destructured keys; login returns
  `data.token` + `data.refreshToken` + `data.user`.
- Request keys camelCase (`usernameOrEmail`, `refreshToken`, `oldPassword`/`newPassword`,
  `otp`); `forgot-password` takes `email`.
- One-time tokens live on the user row (`reset_token`, `verify_token`) and are looked up
  **by token**; registration stores the verify token.
- The `user` role is created on first registration (`INSERT OR IGNORE INTO roles`).
- OTP endpoints act on the authenticated user; `GET /users` is auth-not-admin;
  `PATCH/DELETE /users/:id` are admin-gated (403 for normal users).

## Notes

- Route matching: static segments (`/todos/current-user`, `/users/current`) are
  registered alongside `/{id}` params; Drogon prefers the static match.
- `createDbClient` is deprecated in newer Drogon (warning only) — the build stays green.
- CI builds inside `drogonframework/drogon` on an `ubuntu-latest` runner (checkout on the
  host, `docker run` for the compile) and smoke-tests register + login.

## AI agents (Claude Code and friends)

- **Check the CLIuno skills first**: `npx cliuno@latest skills status` — if any is
  `missing`/`outdated`, run `npx cliuno@latest skills install` (adds `.claude/skills/cliuno-*`:
  the generator workflow, the scaffold guide, and the shared REST contract).
- **Generate resources, don't hand-write them**:
  `npx cliuno@latest make:resource Product --fields name:string,price:number,inStock:boolean`
  creates `controllers/ProductController.cc` and registers it in `main.cc`, following this
  template's conventions and the `{status, message, data}` contract. `--dry-run` previews,
  re-running never duplicates registrations, `--force` overwrites.
- Single pieces: `make:controller`. `npx cliuno@latest make` lists them.
- Then edit fields/business logic only, and run the gates above.
