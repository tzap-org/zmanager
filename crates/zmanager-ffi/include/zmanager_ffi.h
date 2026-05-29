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
  ZMANAGER_FFI_INVALID_UTF8 = 2,
  ZMANAGER_FFI_INVALID_ARGUMENT = 3
} ZManagerFfiStatus;

typedef struct ZManagerFfiJob ZManagerFfiJob;

#define ZMANAGER_FFI_ARCHIVE_FORMAT_TAR_ZST 0
#define ZMANAGER_FFI_ARCHIVE_FORMAT_ZIP 1
#define ZMANAGER_FFI_ARCHIVE_FORMAT_7Z 2
#define ZMANAGER_FFI_ARCHIVE_FORMAT_TZAP 3

#define ZMANAGER_FFI_OVERWRITE_REFUSE 0
#define ZMANAGER_FFI_OVERWRITE_REPLACE 1
#define ZMANAGER_FFI_OVERWRITE_RENAME 2

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

ZManagerFfiStatus zmanager_ffi_start_zip_create_with_options(
  const char *source,
  const char *destination,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
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

ZManagerFfiStatus zmanager_ffi_start_zip_create_many_with_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_clean_source_create(
  const char *source,
  const char *destination,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_clean_source_create_with_options(
  const char *source,
  const char *destination,
  int32_t compression_level,
  bool replace_existing,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_clean_source_create_many(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_clean_source_create_many_with_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t compression_level,
  bool replace_existing,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_archive_create_many_with_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t archive_format,
  bool clean_source,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_archive_create_many_with_exclusions(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t archive_format,
  bool clean_source,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  const char *const *exclude_archive_paths,
  size_t exclude_archive_path_count,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_archive_create_many_with_exclusions_and_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t archive_format,
  bool clean_source,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  bool encrypt_file_names,
  const char *const *exclude_archive_paths,
  size_t exclude_archive_path_count,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_archive_create_many_with_exclusions_and_advanced_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t archive_format,
  bool clean_source,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  bool encrypt_file_names,
  // Zero creates a normal archive. Non-zero splits ZIP into .z01/.zip sets,
  // TZAP into .tzap.000 sets, and 7z into .7z.001 sets.
  uint64_t volume_size,
  const char *const *exclude_archive_paths,
  size_t exclude_archive_path_count,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t archive_format,
  bool clean_source,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  bool encrypt_file_names,
  uint64_t volume_size,
  uint8_t tzap_recovery_percentage,
  uint8_t tzap_volume_loss_tolerance,
  const char *const *exclude_archive_paths,
  size_t exclude_archive_path_count,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_signing_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t archive_format,
  bool clean_source,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  bool encrypt_file_names,
  uint64_t volume_size,
  uint8_t tzap_recovery_percentage,
  uint8_t tzap_volume_loss_tolerance,
  const char *const *exclude_archive_paths,
  size_t exclude_archive_path_count,
  const char *tzap_signing_cert,
  const char *tzap_signing_private_key,
  const char *const *tzap_signing_chain,
  size_t tzap_signing_chain_count,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_archive_create_many_with_exclusions_and_tzap_identity_options(
  const char *const *sources,
  size_t source_count,
  const char *destination,
  int32_t archive_format,
  bool clean_source,
  const char *password,
  int32_t compression_level,
  bool replace_existing,
  bool encrypt_file_names,
  uint64_t volume_size,
  uint8_t tzap_recovery_percentage,
  uint8_t tzap_volume_loss_tolerance,
  const char *const *exclude_archive_paths,
  size_t exclude_archive_path_count,
  const char *tzap_signing_cert,
  const char *tzap_signing_private_key,
  const char *const *tzap_signing_chain,
  size_t tzap_signing_chain_count,
  const char *tzap_signing_identity_p12,
  const char *tzap_signing_identity_password,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_extract_archive(
  const char *archive_path,
  const char *destination,
  ZManagerFfiJob **out_job
);

ZManagerFfiStatus zmanager_ffi_start_extract_archive_with_options(
  const char *archive_path,
  const char *destination,
  const char *password,
  bool replace_existing,
  ZManagerFfiJob **out_job
);
ZManagerFfiStatus zmanager_ffi_start_extract_archive_with_policy(
  const char *archive_path,
  const char *destination,
  const char *password,
  uint32_t overwrite_mode,
  size_t strip_components,
  ZManagerFfiJob **out_job
);

char *zmanager_ffi_plan_clean_source(const char *source);
char *zmanager_ffi_plan_archive(const char *source, bool clean_source);
char *zmanager_ffi_plan_archive_many_with_exclusions(
  const char *const *sources,
  size_t source_count,
  bool clean_source,
  const char *const *exclude_archive_paths,
  size_t exclude_archive_path_count
);
char *zmanager_ffi_list_archive(const char *archive_path);
char *zmanager_ffi_list_archive_with_options(
  const char *archive_path,
  const char *password
);
char *zmanager_ffi_verify_tzap_x509(
  const char *archive_path,
  const char *password,
  const char *const *trusted_ca_certs,
  size_t trusted_ca_cert_count,
  bool trusted_system_roots
);
char *zmanager_ffi_verify_tzap_x509_public_no_key(
  const char *archive_path,
  const char *const *trusted_ca_certs,
  size_t trusted_ca_cert_count,
  bool trusted_system_roots
);
char *zmanager_ffi_extract_archive_entry(
  const char *archive_path,
  const char *entry_path,
  const char *destination
);
char *zmanager_ffi_extract_archive_entry_with_options(
  const char *archive_path,
  const char *entry_path,
  const char *destination,
  const char *password,
  bool replace_existing
);
char *zmanager_ffi_extract_archive_entry_with_policy(
  const char *archive_path,
  const char *entry_path,
  const char *destination,
  const char *password,
  uint32_t overwrite_mode,
  size_t strip_components
);
char *zmanager_ffi_preview_archive_entry(
  const char *archive_path,
  const char *entry_path
);
char *zmanager_ffi_preview_archive_entry_with_options(
  const char *archive_path,
  const char *entry_path,
  const char *password
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
