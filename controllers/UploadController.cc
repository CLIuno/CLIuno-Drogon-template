#include "../utils/Helpers.h"

#include <drogon/HttpController.h>
#include <drogon/MultiPart.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <random>
#include <sstream>

using namespace drogon;
using namespace cliuno;

// /api/v1/uploads/image plus the public, unversioned GET /uploads/{filename}.
class UploadController : public HttpController<UploadController>
{
  public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(UploadController::image, "/api/v1/uploads/image", Post);
    ADD_METHOD_TO(UploadController::serve, "/uploads/{filename}", Get);
    METHOD_LIST_END

    void image(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&);
    void serve(const HttpRequestPtr &, std::function<void(const HttpResponsePtr &)> &&, std::string);
};

namespace
{
// 5 MB — matches every other CLIuno backend template.
constexpr size_t kMaxUploadBytes = 5 * 1024 * 1024;

// Uploaded files live at the repo root and are served back from /uploads.
std::filesystem::path uploadDir()
{
    auto dir = std::filesystem::current_path() / "uploads";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

// The extension comes from the detected mime, never from the client's filename.
const std::map<std::string, std::string> &allowedImageTypes()
{
    static const std::map<std::string, std::string> types = {{"image/png", ".png"},
                                                             {"image/jpeg", ".jpg"},
                                                             {"image/webp", ".webp"},
                                                             {"image/gif", ".gif"}};
    return types;
}

std::string uuidLikeName()
{
    static std::mt19937_64 rng{std::random_device{}()};
    std::ostringstream out;
    out << std::hex << rng() << rng();
    return out.str();
}

// Drogon reports the extension without a leading dot; normalise to ".png" form.
std::string normalisedExtension(std::string_view raw)
{
    std::string ext(raw);
    for (auto &c : ext) c = static_cast<char>(::tolower(c));
    if (!ext.empty() && ext.front() != '.') ext.insert(ext.begin(), '.');
    if (ext == ".jpeg") ext = ".jpg";
    return ext;
}
} // namespace

// Stores the bytes and hands back a URL. Attaching it to a user or a post is the
// caller's job (PATCH /users/current, POST /posts) — upload mutates nothing.
void UploadController::image(const HttpRequestPtr &req,
                             std::function<void(const HttpResponsePtr &)> &&cb)
{
    auto id = currentUserId(req);
    if (!id) return cb(fail(k401Unauthorized, "error", "Unauthorized"));

    MultiPartParser parser;
    if (parser.parse(req) != 0 || parser.getFiles().empty())
    {
        return cb(fail(k400BadRequest, "warning", "No image file provided"));
    }

    const auto &file = parser.getFiles()[0];

    // Only the extension is taken from the client, and only if it is one we allow;
    // the stored filename itself is always generated.
    const std::string ext = normalisedExtension(file.getFileExtension());
    const auto &types = allowedImageTypes();
    const bool allowed = std::any_of(types.begin(), types.end(), [&ext](const auto &entry) {
        return entry.second == ext;
    });
    if (!allowed)
    {
        return cb(fail(k400BadRequest, "error", "Unsupported image type: " + ext));
    }

    if (file.fileLength() > kMaxUploadBytes)
    {
        return cb(fail(k413RequestEntityTooLarge, "error", "Image exceeds the 5 MB limit"));
    }

    const std::string filename = uuidLikeName() + ext;
    const auto target = uploadDir() / filename;
    std::ofstream out(target, std::ios::binary);
    out.write(file.fileData(), static_cast<std::streamsize>(file.fileLength()));
    out.close();

    // Absolute so a frontend on another origin can use it straight as an image source.
    const char *configured = std::getenv("PUBLIC_BASE_URL");
    std::string base;
    if (configured && *configured)
    {
        base = configured;
    }
    else
    {
        base = "http://" + req->getHeader("host");
    }
    while (!base.empty() && base.back() == '/') base.pop_back();

    Json::Value data(Json::objectValue);
    data["url"] = base + "/uploads/" + filename;
    data["filename"] = filename;
    cb(envelope(k201Created, "success", "Image uploaded", data));
}

// Public and unauthenticated: the bytes back out.
void UploadController::serve(const HttpRequestPtr &,
                             std::function<void(const HttpResponsePtr &)> &&cb,
                             std::string filename)
{
    // Reject anything that isn't a plain generated filename — no traversal, no nesting.
    if (filename.find('/') != std::string::npos || filename.find("..") != std::string::npos)
    {
        return cb(fail(k404NotFound, "warning", "Not found"));
    }

    const auto target = uploadDir() / filename;
    if (!std::filesystem::exists(target))
    {
        return cb(fail(k404NotFound, "warning", "Not found"));
    }

    cb(HttpResponse::newFileResponse(target.string()));
}
