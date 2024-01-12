
#ifndef NETSERV_H
#define NETSERV_H

#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_dbd.h"

#include "stdio.h"
#include "errno.h"
#include "time.h"
#include "syscall.h"
#include "unistd.h"
#include "stdlib.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "sys/file.h"
#include "string.h"

#define APRX_MAX_READ_BUFFER 16384

#define APRX_LOG_MAX_FILE_SIZE 500 * 1024 * 1024 /* (10MB) */
#define APRX_LOG_MAX_MSG_SIZE 512
#define APRX_LOG_MSG_FMT "[%s] [%s] [%05d] %s\r\n"

#define ERROR_TIMESTAMP -1

// Interfaccia con il logger
typedef struct logger_t {
  // Puntatore al pool di memoria del servizio
  apr_pool_t *pool;
  // Handler del file di log
  apr_file_t *fh;
  // Nome del file di log
  const char *fname;
  // Mutex associato al logger
  apr_thread_mutex_t *mutex;
  apr_size_t max_size;

} logger_t;

// Interfaccia con il server di database
typedef struct dbd_t {
  // Descrizione dell'ultimo errore occorso
  const char *er_msg;
  // Driver di database
  const apr_dbd_driver_t *drv;
  // Handler della connessione con il server di database
  apr_dbd_t *hdl;
  // Stato della transazione
  apr_dbd_transaction_t *trx;
} dbd_t;

typedef struct ns_request_t {
  const char *method;
  const char *body;
  const char *query;
  const char *uri;
  apr_table_t *headers;
  apr_table_t *args;
  apr_table_t *parsed_uri;
} ns_request_t;

typedef struct ns_response_t {
  int status;
  apr_table_t *headers;
  void *body;
} ns_response_t;

apr_time_t timestamp(int year, int month, int day, int hour, int minute, int second);
apr_time_t now();

void log_rotate(logger_t *l);
logger_t* log_alloc(apr_pool_t *mp, apr_thread_mutex_t *m, const char *f, apr_size_t sz);
void log_destroy(logger_t *l);

#define log_write(l, t, m) do {\
  if (l != NULL && t != NULL && m != NULL) {\
    char _log[APRX_LOG_MAX_MSG_SIZE], _ts[APR_CTIME_LEN];\
    apr_time_t _now = apr_time_now();\
    apr_ctime(_ts, _now);\
    apr_snprintf(_log, sizeof(_log), APRX_LOG_MSG_FMT, _ts, t, __LINE__, m);\
    size_t _len = strlen(_log);\
    if (_len > 0 && _len < (sizeof(_log)-1) && _log[_len-1] == '\n') {\
      apr_thread_mutex_lock(l->mutex);\
      apr_file_printf(l->fh, "%s", _log);\
      apr_file_flush(l->fh);\
      log_rotate(l);\
      apr_thread_mutex_unlock(l->mutex);\
    }\
  }\
} while (0)

void daemonize();

ns_request_t* ns_request_alloc(apr_pool_t *mp);

#endif
