#ifndef ZMANAGER_FFI_H
#define ZMANAGER_FFI_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ZManagerFfiStatus {
  ZMANAGER_FFI_OK = 0,
  ZMANAGER_FFI_NULL_ARGUMENT = 1,
  ZMANAGER_FFI_INVALID_UTF8 = 2
} ZManagerFfiStatus;

typedef struct ZManagerFfiJob ZManagerFfiJob;

bool zmanager_ffi_healthcheck(void);

ZManagerFfiStatus zmanager_ffi_start_zip_create(
  const char *source,
  const char *destination,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_zip_create_encrypted(
  const char *source,
  const char *destination,
  const char *password,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_zip_create_many(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_zip_create_many_encrypted(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  const char *password,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_clean_source_create(
  const char *source,
  const char *destination,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_clean_source_create_many(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_extract_archive(
  const char *archive_path,
  const char *destination,
  ZManagerFfiJob **out_job
);

char *zmanager_ffi_plan_clean_source(const char *source);
char *zmanager_ffi_list_archive(const char *archive_path);
char *zmanager_ffi_extract_archive_entry(
  const char *archive_path,
  const char *entry_path,
  const char *destination
);
char *zmanager_ffi_preview_archive_entry(
  const char *archive_path,
  const char *entry_path
);
char *zmanager_ffi_poll_events(ZManagerFfiJob *job);
void zmanager_ffi_job_cancel(ZManagerFfiJob *job);
bool zmanager_ffi_job_is_finished(const ZManagerFfiJob *job);
void zmanager_ffi_job_free(ZManagerFfiJob *job);
void zmanager_ffi_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
