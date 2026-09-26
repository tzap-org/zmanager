#include "rar.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr int ZMU_UNRAR_ABORTED = -1000;
constexpr int ZMU_UNRAR_DESTINATION_TOO_LONG = -1001;
constexpr std::uint64_t ZMU_UNRAR_MAX_LARGE_DICTIONARY_KB = 512ULL * 1024ULL;
constexpr std::size_t ZMU_UNRAR_WIDE_BUFFER_CHARS = 32768;

// Events reported through `ExtractEventCallback` while a selected entry is
// being written. Returning a negative value from the callback aborts the
// extraction.
constexpr int ZMU_UNRAR_EVENT_DATA = 1;
constexpr int ZMU_UNRAR_EVENT_ENTRY_DONE = 2;

using ExtractEventCallback = int (*)(void *user, int event,
                                     std::uint64_t value);

struct BridgeContext {
  const char *password;
  void *user;
  ExtractEventCallback event_callback;
};

using ListCallback = int (*)(void *user, const char *path, std::uint64_t size,
                            std::uint64_t dictionary_size, unsigned int flags,
                            unsigned int redir_type, const char *redir_target,
                            std::uint32_t file_attr, std::uint64_t mtime);

using ExtractCallback = int (*)(void *user, const char *path,
                               std::uint64_t size, unsigned int flags,
                               unsigned int redir_type, const char *redir_target,
                               std::uint32_t file_attr, std::uint64_t mtime,
                               char *destination, std::size_t destination_size);

struct HeaderBuffers {
  std::vector<wchar_t> file_name;
  std::vector<wchar_t> redir_name;
  RARHeaderDataEx header;

  HeaderBuffers()
      : file_name(ZMU_UNRAR_WIDE_BUFFER_CHARS),
        redir_name(ZMU_UNRAR_WIDE_BUFFER_CHARS), header{} {}

  RARHeaderDataEx *prepare() {
    header = RARHeaderDataEx{};
    file_name[0] = 0;
    redir_name[0] = 0;
    header.FileNameEx = file_name.data();
    header.FileNameExSize = static_cast<unsigned int>(file_name.size());
    header.RedirName = redir_name.data();
    header.RedirNameSize = static_cast<unsigned int>(redir_name.size());
    return &header;
  }
};

std::uint64_t unpacked_size(const RARHeaderDataEx &header) {
  return (static_cast<std::uint64_t>(header.UnpSizeHigh) << 32) |
         static_cast<std::uint64_t>(header.UnpSize);
}

std::uint64_t dictionary_size(const RARHeaderDataEx &header) {
  return static_cast<std::uint64_t>(header.DictSize) * 1024ULL;
}

bool large_dictionary_allowed(std::uint64_t dict_size_kb) {
  return dict_size_kb <= ZMU_UNRAR_MAX_LARGE_DICTIONARY_KB;
}

std::string wide_to_utf8(const wchar_t *value) {
  if (value == nullptr || value[0] == 0) {
    return {};
  }
  std::string converted;
  WideToUtf(std::wstring(value), converted);
  return converted;
}

std::string file_name_utf8(const RARHeaderDataEx &header) {
  if (header.FileNameEx != nullptr && header.FileNameEx[0] != 0) {
    return wide_to_utf8(header.FileNameEx);
  }
  return wide_to_utf8(header.FileNameW);
}

std::string redir_name_utf8(const RARHeaderDataEx &header) {
  if (header.RedirType == FSREDIR_NONE || header.RedirName == nullptr ||
      header.RedirName[0] == 0) {
    return {};
  }
  return wide_to_utf8(header.RedirName);
}

int CALLBACK unrar_callback(UINT msg, LPARAM user_data, LPARAM p1, LPARAM p2) {
  auto *context = reinterpret_cast<BridgeContext *>(user_data);
  if (msg == UCM_NEEDPASSWORD) {
    if (context == nullptr || context->password == nullptr ||
        context->password[0] == '\0') {
      return -1;
    }

    auto *buffer = reinterpret_cast<char *>(p1);
    std::size_t buffer_size = static_cast<std::size_t>(p2);
    if (buffer == nullptr || buffer_size == 0) {
      return -1;
    }

    std::strncpy(buffer, context->password, buffer_size - 1);
    buffer[buffer_size - 1] = '\0';
    return 1;
  }

  if (msg == UCM_NEEDPASSWORDW) {
    if (context == nullptr || context->password == nullptr ||
        context->password[0] == '\0') {
      return -1;
    }

    auto *buffer = reinterpret_cast<wchar_t *>(p1);
    std::size_t buffer_size = static_cast<std::size_t>(p2);
    if (buffer == nullptr || buffer_size == 0) {
      return -1;
    }

    return CharToWide(context->password, buffer, buffer_size) ? 1 : -1;
  }

  if (msg == UCM_CHANGEVOLUME || msg == UCM_CHANGEVOLUMEW) {
    // This bridge has no interactive volume picker.  Returning the unchanged
    // name for an ASK callback makes UnRAR retry a missing volume forever;
    // abort the operation so the caller receives ERAR_EOPEN instead.
    return p2 == RAR_VOL_ASK ? -1 : 1;
  }

  if (msg == UCM_LARGEDICT) {
    return large_dictionary_allowed(static_cast<std::uint64_t>(p1)) ? 1 : 0;
  }

  if (msg == UCM_PROCESSDATA) {
    // UnRAR reports every decoded chunk of an entry it is extracting (not of
    // skipped entries). Returning -1 makes UnRAR stop with a user break, which
    // is how cancellation interrupts a single large entry.
    if (context != nullptr && context->event_callback != nullptr &&
        context->event_callback(context->user, ZMU_UNRAR_EVENT_DATA,
                                static_cast<std::uint64_t>(p2)) < 0) {
      return -1;
    }
    return 1;
  }

  return 1;
}

RAROpenArchiveDataEx open_request(const char *archive, BridgeContext *context,
                                  std::wstring *archive_wide) {
  RAROpenArchiveDataEx request{};
  request.ArcName = const_cast<char *>(archive);
  // Rust paths are serialized as UTF-8.  CharToWide uses CP_ACP on Windows,
  // so using it here would corrupt non-ASCII archive paths before UnRAR sees
  // them.  Keep the C ABI input explicit about its encoding.
  if (archive_wide != nullptr && UtfToWide(archive, *archive_wide) &&
      !archive_wide->empty()) {
    request.ArcNameW = const_cast<wchar_t *>(archive_wide->c_str());
  }
  request.OpenMode = RAR_OM_EXTRACT;
  request.Callback = unrar_callback;
  request.UserData = reinterpret_cast<LPARAM>(context);
  return request;
}

} // namespace

extern "C" int zmu_unrar_list(const char *archive, const char *password,
                              void *user, ListCallback callback) {
  if (archive == nullptr || callback == nullptr) {
    return ERAR_EOPEN;
  }

  BridgeContext context{password, user, nullptr};
  std::wstring archive_wide;
  RAROpenArchiveDataEx request = open_request(archive, &context, &archive_wide);
  HANDLE handle = RAROpenArchiveEx(&request);
  if (handle == nullptr) {
    return request.OpenResult == ERAR_SUCCESS ? ERAR_EOPEN : request.OpenResult;
  }
  if (password != nullptr && password[0] != '\0') {
    RARSetPassword(handle, const_cast<char *>(password));
  }

  HeaderBuffers buffers;
  int code = ERAR_SUCCESS;
  while ((code = RARReadHeaderEx(handle, buffers.prepare())) == ERAR_SUCCESS) {
    const RARHeaderDataEx &header = buffers.header;
    // UnRAR exposes the continuation header for a file that spans volumes
    // after RAR_SKIP advances to the next part. It is not a second archive
    // entry, so reporting it would make callers reject a valid multipart
    // archive as a duplicate path.
    if ((header.Flags & RHDF_SPLITBEFORE) == 0) {
      std::string path = file_name_utf8(header);
      std::string redir_target = redir_name_utf8(header);
      std::uint64_t mtime = ((std::uint64_t)header.MtimeHigh << 32) | header.MtimeLow;
      int callback_code =
          callback(user, path.c_str(), unpacked_size(header),
                   dictionary_size(header), header.Flags, header.RedirType,
                   redir_target.empty() ? nullptr : redir_target.c_str(),
                   header.FileAttr, mtime);
      if (callback_code < 0) {
        RARCloseArchive(handle);
        return ZMU_UNRAR_ABORTED;
      }
    }

    int process_code = RARProcessFile(handle, RAR_SKIP, nullptr, nullptr);
    if (process_code != ERAR_SUCCESS) {
      RARCloseArchive(handle);
      return process_code;
    }
  }

  int close_code = RARCloseArchive(handle);
  if (code == ERAR_END_ARCHIVE) {
    return close_code == ERAR_SUCCESS ? ERAR_SUCCESS : close_code;
  }
  return code;
}

extern "C" int zmu_unrar_extract(const char *archive, const char *password,
                                 void *user, ExtractCallback callback,
                                 ExtractEventCallback event_callback) {
  if (archive == nullptr || callback == nullptr) {
    return ERAR_EOPEN;
  }

  BridgeContext context{password, user, event_callback};
  std::wstring archive_wide;
  RAROpenArchiveDataEx request = open_request(archive, &context, &archive_wide);
  HANDLE handle = RAROpenArchiveEx(&request);
  if (handle == nullptr) {
    return request.OpenResult == ERAR_SUCCESS ? ERAR_EOPEN : request.OpenResult;
  }
  if (password != nullptr && password[0] != '\0') {
    RARSetPassword(handle, const_cast<char *>(password));
  }

  HeaderBuffers buffers;
  int code = ERAR_SUCCESS;
  while ((code = RARReadHeaderEx(handle, buffers.prepare())) == ERAR_SUCCESS) {
    const RARHeaderDataEx &header = buffers.header;
    std::string path = file_name_utf8(header);
    std::string redir_target = redir_name_utf8(header);
    char destination[8192]{};
    std::uint64_t mtime = ((std::uint64_t)header.MtimeHigh << 32) | header.MtimeLow;
    int callback_code = callback(
        user, path.c_str(), unpacked_size(header), header.Flags,
        header.RedirType, redir_target.empty() ? nullptr : redir_target.c_str(),
        header.FileAttr, mtime,
        destination, sizeof(destination));
    if (callback_code < 0) {
      RARCloseArchive(handle);
      return callback_code == -2 ? ZMU_UNRAR_DESTINATION_TOO_LONG
                                 : ZMU_UNRAR_ABORTED;
    }

    int operation = callback_code == 1 ? RAR_EXTRACT : RAR_SKIP;
    std::wstring destination_wide;
    wchar_t *destination_arg = nullptr;
    if (callback_code == 1) {
      // `destination` came from Rust as UTF-8.  On Windows CharToWide treats
      // it as the ANSI code page, which makes extraction fail for otherwise
      // valid Unicode members such as `こんにちは.txt`.
      if (!UtfToWide(destination, destination_wide) ||
          destination_wide.empty()) {
        RARCloseArchive(handle);
        return ZMU_UNRAR_ABORTED;
      }
      destination_arg = const_cast<wchar_t *>(destination_wide.c_str());
    }
    int process_code =
        RARProcessFileW(handle, operation, nullptr, destination_arg);
    if (process_code != ERAR_SUCCESS) {
      RARCloseArchive(handle);
      return process_code;
    }
    if (operation == RAR_EXTRACT && event_callback != nullptr &&
        event_callback(user, ZMU_UNRAR_EVENT_ENTRY_DONE, 0) < 0) {
      RARCloseArchive(handle);
      return ZMU_UNRAR_ABORTED;
    }
  }

  int close_code = RARCloseArchive(handle);
  if (code == ERAR_END_ARCHIVE) {
    return close_code == ERAR_SUCCESS ? ERAR_SUCCESS : close_code;
  }
  return code;
}

extern "C" int zmu_unrar_large_dictionary_allowed(std::uint64_t dict_size_kb) {
  return large_dictionary_allowed(dict_size_kb) ? 1 : 0;
}
