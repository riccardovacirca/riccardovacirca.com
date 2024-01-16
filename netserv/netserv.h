
#ifndef NETSERV_H
#define NETSERV_H

#include "apr.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_escape.h"
#include "apr_md5.h"
#include "apr_base64.h"
#include "apr_crypto.h"
#include "apr_time.h"
#include "apr_env.h"
#include "apr_time.h"
#include "apr_date.h"
#include "apr_getopt.h"
#include "apr_thread_mutex.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_time.h"
#include "apr_dbd.h"

#include "errno.h"
#include "time.h"
#include "syscall.h"
#include "unistd.h"
#include "stdlib.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "sys/file.h"
#include "string.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NS_MAX_READ_BUFFER 16384

#define NS_LOG_MAX_FILE_SIZE 500 * 1024 * 1024 /* (10MB) */
#define NS_LOG_MAX_MSG_SIZE 512
#define NS_LOG_MSG_FMT "[%s] [%s] [%05d] %s\r\n"

#define NS_ERROR_TIMESTAMP (-1)

// Stato di fallimento o successo
typedef enum ns_status_t {
  NS_FAILURE = 0,
  NS_SUCCESS
} ns_status_t;

// Interfaccia con il logger
typedef struct ns_logger_t {
  apr_pool_t *pool;
  apr_file_t *fh;
  const char *fname;
  apr_thread_mutex_t *mutex;
  apr_size_t max_size;
} ns_logger_t;

// Interfaccia con il server di database
typedef struct ns_dbd_t {
  const char *er_msg;
  const apr_dbd_driver_t *drv;
  apr_dbd_t *hdl;
  apr_dbd_transaction_t *trx;
} ns_dbd_t;

typedef struct ns_request_t {
  int client_port;
  const char *method;
  const char *body;
  const char *query;
  const char *uri;
  const char *http_version;
  const char *client_ip;
  const char *prev_method;
  const char *prev_uri;
  const char *session_id;
  apr_table_t *headers;
  apr_table_t *args;
  apr_table_t *parsed_uri;
  apr_table_t *cookies;
} ns_request_t;

typedef struct ns_response_t {
  int status;
  apr_table_t *headers;
  void *body;
} ns_response_t;

int ns_rand(int l, int h);
int ns_is_empty(const char *s);
int ns_is_int(const char *s);
int ns_is_double(const char *s);
int ns_in_string(const char *s, const char *sub);
char* ns_buffer(apr_pool_t *mp, const char *s, apr_size_t *bf_size);
char* ns_str(apr_pool_t *mp, const char *s, apr_size_t sz);
const char* ns_trim(apr_pool_t *mp, const char *s);
const char* ns_strip_char(apr_pool_t *mp, const char *s, char c);
char* ns_slice(apr_pool_t *mp, const char *s, apr_size_t i, apr_size_t l);
const char* ns_str_replace(apr_pool_t *mp, const char *s, const char *f, const char *r);
const char* ns_replace_char(apr_pool_t *mp, const char *s, char f, char r);
char* ns_empty_string_make(apr_pool_t *mp);
apr_array_header_t* ns_split(apr_pool_t *mp, const char *s, const char *sp);
char* ns_join(apr_pool_t *mp, apr_array_header_t *a, const char *sp);
char* ns_md5(apr_pool_t *mp, const char *s);
char* ns_base64_encode(apr_pool_t *mp, const char *s);
char* ns_base64_decode(apr_pool_t* mp, const char* s);
apr_table_t* ns_args_to_table(apr_pool_t *mp, const char *q);
int ns_table_nelts(apr_table_t *t);
apr_table_entry_t* ns_table_elt(apr_table_t *t, int i);
char* ns_datetime(apr_pool_t *mp, apr_time_t t, const char *f);
char* ns_datetime_local(apr_pool_t *mp, apr_time_t t, const char *f);
char* ns_datetime_utc(apr_pool_t *mp, apr_time_t t, const char *f);
int ns_is_dir(const char *d, apr_pool_t *mp);
int ns_is_file(const char *f, apr_pool_t *mp);
apr_status_t ns_file_open(apr_file_t **fd, const char *f, apr_int32_t fl, apr_pool_t *mp);
apr_status_t ns_file_open_read(apr_file_t **fd, const char *f, apr_pool_t *mp);
apr_status_t ns_file_open_append(apr_file_t **fd, const char *f, apr_pool_t *mp);
apr_status_t ns_file_open_truncate(apr_file_t **fd, const char *f, apr_pool_t *mp);
apr_size_t ns_file_write(apr_file_t *fd, const char *buf, apr_size_t l);
apr_size_t ns_file_read(apr_pool_t *mp, apr_file_t *fd, void **buf);
apr_status_t ns_file_close(apr_file_t *fd);
apr_time_t ns_timestamp(int year, int month, int day, int hour, int minute, int second);
apr_time_t ns_now();
void ns_log_rotate(ns_logger_t *l);
ns_logger_t* ns_log_alloc(apr_pool_t *mp, apr_thread_mutex_t *m, const char *f, apr_size_t sz);
void ns_log_destroy(ns_logger_t *l);
void ns_daemonize();
char* ns_ppipein(apr_pool_t *mp);
ns_request_t* ns_request_alloc(apr_pool_t *mp);

#define ns_log_write(l, t, m) do {\
  if (l != NULL && t != NULL && m != NULL) {\
    char _log[NS_LOG_MAX_MSG_SIZE], _ts[APR_CTIME_LEN];\
    apr_time_t _now = apr_time_now();\
    apr_ctime(_ts, _now);\
    apr_snprintf(_log, sizeof(_log), NS_LOG_MSG_FMT, _ts, t, __LINE__, m);\
    size_t _len = strlen(_log);\
    if (_len > 0 && _len < (sizeof(_log)-1) && _log[_len-1] == '\n') {\
      apr_thread_mutex_lock(l->mutex);\
      apr_file_printf(l->fh, "%s", _log);\
      apr_file_flush(l->fh);\
      ns_log_rotate(l);\
      apr_thread_mutex_unlock(l->mutex);\
    }\
  }\
} while (0)

void daemonize();

ns_request_t* ns_request_alloc(apr_pool_t *mp);

#ifdef __cplusplus
}
#endif
#endif /* NETSERV_H */
