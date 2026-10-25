// Copyright 2026 Ardia. Apache-2.0.

#ifndef CHROME_BROWSER_ARDIA_PUBLIC_AC_ENGINE_H_
#define CHROME_BROWSER_ARDIA_PUBLIC_AC_ENGINE_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AC_ENGINE_EXPORT __attribute__((visibility("default")))

#define AC_ENGINE_ABI_VERSION 2

typedef void (*ac_engine_reply_t)(void* context, const char* json);
typedef void (*ac_engine_call_t)(const char* profile_dir,
                                 const char* args_json,
                                 ac_engine_reply_t reply,
                                 void* context);
typedef void (*ac_engine_event_t)(void* context,
                                  const char* topic,
                                  const char* json);

typedef int (*ac_engine_abi_version_t)(void);
typedef void (*ac_engine_set_event_sink_t)(ac_engine_event_t sink,
                                           void* context);

typedef int (*ac_passwords_sync_authorized_t)(void* context);
typedef struct {
  const char* origin;
  size_t origin_size;
  const char* username;
  size_t username_size;
  const char* password;
  size_t password_size;
  int has_created;
  double created_ms;
} ac_passwords_sync_login;
typedef void (*ac_passwords_sync_login_t)(void* context,
                                         const ac_passwords_sync_login* login);
typedef void (*ac_passwords_sync_done_t)(void* context, int success);
typedef void (*ac_passwords_sync_read_t)(
    const char* profile_dir,
    ac_passwords_sync_authorized_t authorized,
    ac_passwords_sync_login_t login,
    ac_passwords_sync_done_t done,
    void* context);
typedef void (*ac_passwords_sync_compare_and_set_t)(
    const char* profile_dir,
    const char* args_json,
    ac_passwords_sync_authorized_t authorized,
    ac_passwords_sync_done_t done,
    void* context);

AC_ENGINE_EXPORT void ac_passwords_sync_read(
    const char* profile_dir,
    ac_passwords_sync_authorized_t authorized,
    ac_passwords_sync_login_t login,
    ac_passwords_sync_done_t done,
    void* context);
AC_ENGINE_EXPORT void ac_passwords_sync_compare_and_set(
    const char* profile_dir,
    const char* args_json,
    ac_passwords_sync_authorized_t authorized,
    ac_passwords_sync_done_t done,
    void* context);

#ifdef __cplusplus
}
#endif

#endif
