
#ifndef APRX_H
#define APRX_H

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

#define APRX_MAX_READ_BUFFER 16384

#define APRX_LOG_MAX_FILE_SIZE 500 * 1024 * 1024 /* (10MB) */
#define APRX_LOG_MAX_MSG_SIZE 512
#define APRX_LOG_MSG_FMT "[%s] [%s] [%05d] %s\r\n"

int aprx_rand(int l, int h);
int aprx_isempty(const char *s);
int aprx_isint(const char *s);
int aprx_isdouble(const char *s);
int aprx_instr(const char *s, const char *sub);
char* aprx_pbuff(apr_pool_t *mp, const char *s, apr_size_t *bf_size);
char* aprx_pstr(apr_pool_t *mp, const char *s, apr_size_t sz);
const char* aprx_ptrim(apr_pool_t *mp, const char *s);
const char* aprx_pstripc(apr_pool_t *mp, const char *s, char c);
char* aprx_pslice(apr_pool_t *mp, const char *s, apr_size_t i, apr_size_t l);
const char* aprx_pstrrep(apr_pool_t *mp, const char *s, const char *f, const char *r);
const char* aprx_prepc(apr_pool_t *mp, const char *s, char f, char r);
char* aprx_strempty(apr_pool_t *mp);
apr_array_header_t* aprx_psplit(apr_pool_t *mp, const char *s, const char *sp);
char* aprx_pjoin(apr_pool_t *mp, apr_array_header_t *a, const char *sp);
char* aprx_pmd5(apr_pool_t *mp, const char *s);
char* aprx_pbase64encode(apr_pool_t *mp, const char *s);
char* aprx_pbase64decode(apr_pool_t* mp, const char* s);
int aprx_table_nelts(apr_table_t *t);
apr_table_entry_t* aprx_table_elt(apr_table_t *t, int i);
char* aprx_pdatetime(apr_pool_t *mp, apr_time_t t, const char *f);
char* aprx_pdatetime_local(apr_pool_t *mp, apr_time_t t, const char *f);
char* aprx_pdatetime_utc(apr_pool_t *mp, apr_time_t t, const char *f);
int aprx_isdir(const char *d, apr_pool_t *mp);
int aprx_isfile(const char *f, apr_pool_t *mp);
apr_status_t aprx_pfopen(apr_file_t **fd, const char *f, apr_int32_t fl, apr_pool_t *mp);
apr_status_t aprx_pfopen_read(apr_file_t **fd, const char *f, apr_pool_t *mp);
apr_status_t aprx_pfopen_append(apr_file_t **fd, const char *f, apr_pool_t *mp);
apr_status_t aprx_pfopen_truncate(apr_file_t **fd, const char *f, apr_pool_t *mp);
apr_size_t aprx_fwrite(apr_file_t *fd, const char *buf, apr_size_t l);
apr_size_t aprx_pfread(apr_pool_t *mp, apr_file_t *fd, void **buf);
apr_status_t aprx_fclose(apr_file_t *fd);
char* aprx_env(const char *e, apr_pool_t *mp);
char* aprx_ppipein(apr_pool_t *mp);
void aprx_daemonize();
apr_time_t aprx_timestamp(apr_pool_t *mp, const char *d, const char *f);

// -----------------------------------------------------------------------------
// LOGS
// -----------------------------------------------------------------------------

typedef struct aprx_logger_t {
  apr_pool_t *pool;
  apr_file_t *fh;
  const char *fname;
  apr_thread_mutex_t *mutex;
  apr_size_t max_size;
} aprx_logger_t;

void aprx_log_rotate(aprx_logger_t *l);
aprx_logger_t* aprx_log_init(apr_pool_t *mp, apr_thread_mutex_t *m, const char *f, apr_size_t sz);
void aprx_log_rotate(aprx_logger_t *l);

#define aprx_log(l, t, m) do {\
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
      aprx_log_rotate(l);\
      apr_thread_mutex_unlock(l->mutex);\
    }\
  }\
} while (0)

void aprx_log_close(aprx_logger_t *l);



#ifdef HLP_JSON_H

typedef enum hlp_json_type_t
{
  HLP_JSON_T_ZERO       = 0x00000000,
  HLP_JSON_T_NULL       = 0x00000001,
  HLP_JSON_T_BOOLEAN    = 0x00000002,
  HLP_JSON_T_PAIR       = 0x00000004,
  HLP_JSON_T_INT16      = 0x00000008,
  HLP_JSON_T_UINT16     = 0x00000010,
  HLP_JSON_T_INT32      = 0x00000020,
  HLP_JSON_T_UINT32     = 0x00000040,
  HLP_JSON_T_INT64      = 0x00000080,
  HLP_JSON_T_UINT64     = 0x00000100,
  HLP_JSON_T_FLOAT      = 0x00000200,
  HLP_JSON_T_DOUBLE     = 0x00000400,
  HLP_JSON_T_STRING     = 0x00000800,
  HLP_JSON_T_OBJECT     = 0x00001000,
  HLP_JSON_T_ARRAY      = 0x00002000,
  HLP_JSON_T_DATE       = 0x00004000,
  HLP_JSON_T_NUMBER     = 0x00008000,
  HLP_JSON_T_TABLE      = 0x00010000,
  HLP_JSON_T_TIMESTAMP  = 0x00020000,
  HLP_JSON_T_JSON       = 0x00040000,
  HLP_JSON_T_DBD_SCHEMA = 0x00080000,
  HLP_JSON_T_VECTOR     = 0x00100000
} hlp_json_type_t;
typedef struct hlp_json_pair_t {
  const char *key;
  void *val;
  hlp_json_type_t type;  
} hlp_json_pair_t;
typedef apr_array_header_t hlp_json_object_t;
hlp_json_object_t* hlp_json_decode(apr_pool_t *mp, const char *s);
const char* hlp_json_encode(apr_pool_t *mp, const void *obj, hlp_json_type_t t);

#endif /* hlp_JSON_H */

// -----------------------------------------------------------------------------
// MEMCACHE
// -----------------------------------------------------------------------------

#ifdef HLP_MEMCACHE_H

#define HLP_MEMCACHE_TIMEOUT  360

apr_memcache_t* hlp_memcache_init(apr_pool_t *mp, const char *host, int port);
apr_size_t hlp_memcache_get(apr_memcache_t *mc, apr_pool_t *mp, const char *k, char **v);
apr_status_t hlp_memcache_set(apr_memcache_t *mc, const char *k, char *v);
apr_status_t hlp_memcache_delete();

#endif /* HLP_MEMCACHE_H */

// -----------------------------------------------------------------------------
// DBD
// -----------------------------------------------------------------------------

#ifdef HLP_DBD_H

typedef struct hlp_dbd_t {
  int cod;
  const char *err;
  const apr_dbd_driver_t *drv;
  apr_dbd_t *hdl;
  apr_dbd_transaction_t *trx;
} hlp_dbd_t;

hlp_dbd_t* hlp_dbd_init(apr_pool_t *mp);
int hlp_dbd_open(apr_pool_t *mp, hlp_dbd_t *dbd, const char *drv, const char *con);
const char* hlp_dbd_escape(apr_pool_t *mp, hlp_dbd_t *dbd, const char *s);
int hlp_dbd_query(apr_pool_t *mp, hlp_dbd_t *dbd, const char *sql);
apr_array_header_t* hlp_dbd_select(apr_pool_t *mp, hlp_dbd_t *dbd, const char *sql);
int hlp_dbd_transaction_start(apr_pool_t *mp, hlp_dbd_t *dbd);
int hlp_dbd_transaction_end(apr_pool_t *mp, hlp_dbd_t *dbd);
//int hlp_dbd_prepared_query(apr_pool_t *mp, hlp_dbd_t *dbd, const char *sql, const char **args, int sz);
int hlp_dbd_prepared_query(apr_pool_t *mp, hlp_dbd_t *dbd, const char *sql, apr_table_t *args);
apr_array_header_t* hlp_dbd_prepared_select(apr_pool_t *mp, hlp_dbd_t *dbd, const char *sql, apr_table_t *args);
int hlp_dbd_num_records(apr_array_header_t *rset);
int hlp_dbd_num_columns(apr_array_header_t *rset);
apr_array_header_t* hlp_dbd_column_names(apr_pool_t *mp, apr_array_header_t *rset);
apr_table_t* hlp_dbd_record(apr_array_header_t *rset, int idx);
const char* hlp_dbd_field_value(apr_array_header_t *rset, int idx, const char*key);
int hlp_dbd_field_set(apr_array_header_t *rset, int idx, const char *key, const char *val);
int hlp_dbd_close(hlp_dbd_t *dbd);
const char* hlp_dbd_driver_name(hlp_dbd_t *dbd);
const char* hlp_dbd_error(hlp_dbd_t *dbd);

#endif /* HLP_DBD_H */

// -----------------------------------------------------------------------------
// COOKIES
// -----------------------------------------------------------------------------
#ifdef HLP_COOKIES_H

void hlp_cookie_set(request_rec *r, const char *k, const char *v, const char *p);
const char* hlp_cookie_get(request_rec *r, const char *k, const char *v, const char *p);

#endif /* HLP_COOKIES_H */

// -----------------------------------------------------------------------------
// AUTH
// -----------------------------------------------------------------------------

#ifdef HLP_AUTH

const char* tmp_authz(apr_pool_t *mp);
int hlp_http_authorize(apr_pool_t *mp, const char *authz_s, const char *authz_file);
int hlp_http_authenticate_token(apr_pool_t *mp, char **authz_s, const char *uri, const char *meth, const char *authn_s, const char *date, const char *authn_file);
int hlp_http_authenticate_credentials(apr_pool_t *mp, char **authz_s,const char*f, const char *u, const char *p);

#define hlp_mg_authorize(ctx) do {\
  /* Flag di autenticazione e autorizzazione */\
  int is_authn = 0, is_authz = 0;\
  /* Se il file di autorizzazione non esiste restituisco HTTP 403 */\
  /* Il file di autorizzazione conserva le sessioni */\
  if (!hlp_file_exists(ctx->pool, ctx->serv_ctx->authz_file)) {\
    hlp_log(ctx->serv_ctx->logger, "ERROR", "Authorization file does not exists");\
    return 403;\
  }\
  /* Se il file di autenticazione non esiste restituisco HTTP 403 */\
  /* Il file di autenticazione conserva le credenziale utente */\
  if (!hlp_file_exists(ctx->pool, ctx->serv_ctx->authn_file)) {\
    hlp_log(ctx->serv_ctx->logger, "ERROR", "Authentication file does not exists");\
    return 403;\
  }\
  /* Provo ad eseguire l'autorizzazione */\
  /* Recupero il valore del parametro authz dal cookie nella request HTTP */\
  const char *authz_s = hlp_mg_request_cookie_get(ctx, "authz");\
  /* Se l'autorizzazione ha successo la normale esecuzione non viene alterata */\
  /* Provo ad autorizzare il valore estratto dal cookie */\
  is_authz = hlp_http_authorize(ctx->pool, authz_s, ctx->serv_ctx->authz_file);\
  if (!is_authz) {\
    /* In caso di fallimento provo ad eseguire l'autenticazione */\
    const char *user = NULL, *pass = NULL, *uri, *method, *authn_s, *date, *authz_cookie;\
    /* Estraggo il metodo della request HTTP */\
    method = hlp_str(ctx->pool, ctx->ht_request->method.ptr, ctx->ht_request->method.len);\
    /* Estraggo lo URI della request HTTP */\
    uri = hlp_str(ctx->pool, ctx->ht_request->uri.ptr, ctx->ht_request->uri.len);\
    /* Estraggo il digest HMAC del client dagli headers dalla request HTTP */\
    authn_s = hlp_mg_request_header_get(ctx, "Authentication");\
    /* Estarggo la data del client dagli headers della request HTTP*/\
    date = hlp_mg_request_header_get(ctx, "Date");\
    /* Se gli headers di autenticazione non sono presenti restituisco HTTP 403 */\
    if (authn_s == NULL || date == NULL) {\
      user = hlp_mg_request_var_get(ctx, "user", 32);\
      pass = hlp_mg_request_var_get(ctx, "pass", 32);\
      if (user == NULL || pass == NULL) {\
        hlp_log(ctx->serv_ctx->logger, "ERROR", "Invalid credentials.");\
        return 403;\
      }\
    }\
    char *authz_s, *authz_file, *er;\
    /* Eseguo l'autenticazione */\
    /* In caso di successo un token di autorizzazione viene settato in authz_s */\
    /* e viene restituito un valore true*/\
    if ((user != NULL) && (pass != NULL)) {\
      is_authn = hlp_http_authenticate_credentials(ctx->pool, &authz_s, ctx->serv_ctx->authn_file, user, pass);\
    } else {\
      is_authn = hlp_http_authenticate_token(ctx->pool, &authz_s, uri, method, authn_s, date, ctx->serv_ctx->authn_file);\
    }\
    /* Se il digest generato e quello ricevuto non coincidono restituisco HTTP 403 */\
    if (!is_authn) {\
      hlp_log(ctx->serv_ctx->logger, "ERROR", "hlp_http_authenticate_token() failed");\
      return 403;\
    }\
    /* Se l'autenticazione ha successo genero il token per il cookie */\
    authz_cookie = apr_psprintf(ctx->pool, "authz=%s; Path=/", authz_s);\
    /* Registro il token in un file sul server insieme a uno unix timestamp */\
    /* che ne mantiene la validità per il tempo configurato */\
    authz_file = apr_psprintf(ctx->pool, "%s\n", authz_s);\
    /* Scrivo il token nel file di autorizzazione */\
    hlp_file_write(ctx->pool, ctx->serv_ctx->authz_file, authz_file, strlen(authz_file), 1, 0, &er);\
    /* Restituisco il cookie con il token */\
    hlp_mg_response_header_set(ctx, "Set-Cookie", authz_cookie);\
  }\
} while (0)

#endif/* HLP_AUTH */



#ifdef HLP_OBSERVER_H

int hlp_observer_notify(apr_pool_t *p);

#endif /* HLP_OBSERVER_H */








#ifdef HLP_REQUEST_H

typedef struct hlp_http_request_t hlp_http_request_t;
hlp_http_request_t* hlp_http_request_init(apr_pool_t *mp);
void hlp_http_request_method_set(hlp_http_request_t *r, const char *m, apr_size_t sz);
void hlp_http_request_uri_set(hlp_http_request_t *r, const char *u, apr_size_t sz);
void hlp_http_request_query_set(hlp_http_request_t *r, const char *q, apr_size_t sz);
void hlp_http_request_body_set(hlp_http_request_t *r, const char *u, apr_size_t sz);
void hlp_http_request_headers_set(hlp_http_request_t *r, apr_table_t *v);
void hlp_http_request_args_set(hlp_http_request_t *r, apr_table_t *v);
void hlp_http_request_vars_set(hlp_http_request_t *r, apr_table_t *v);
void hlp_http_request_cookies_set(hlp_http_request_t *r, apr_table_t *v);
const char* hlp_http_request_method_get(hlp_http_request_t *r);
const char* hlp_http_request_uri_get(hlp_http_request_t *r);
const char* hlp_http_request_query_get(hlp_http_request_t *r);
const char* hlp_http_request_body_get(hlp_http_request_t *r);
apr_size_t hlp_http_request_body_size_get(hlp_http_request_t *r);
apr_table_t* hlp_http_request_headers_get(hlp_http_request_t *r);
apr_table_t* hlp_http_request_args_get(hlp_http_request_t *r);
apr_table_t* hlp_http_request_vars_get(hlp_http_request_t *r);
apr_table_t* hlp_http_request_cookies_get(hlp_http_request_t *r);
apr_table_t* hlp_http_parse_formdata(request_rec *r);
size_t hlp_http_parse_rawdata(request_rec *r, const char **rbuf);

#endif /* HLP_REQUEST_H */


#ifdef HLP_SCHEMA_H

apr_array_header_t* hlp_dbd_schema(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tab);

#endif /* HLP_SCHEMA_H */





#ifdef HLP_SESSION_H

/*

enable module:
session_cookie.load
session.load
session_crypto.load
*/

#include "httpd.h"
#include "mod_session.h"

typedef int (*hlp_session_load_t)(request_rec *r, session_rec **z);
typedef int (*hlp_session_save_t)(request_rec *r, session_rec *z);
typedef apr_status_t(*hlp_session_get_t)(request_rec *r, session_rec *z, const char *key, const char **value);
typedef apr_status_t(*hlp_session_set_t)(request_rec *r, session_rec *z, const char *key, const char *value);

typedef struct hlp_session_t {
  int is_active;
  session_rec *ssn;
  hlp_session_get_t get;
  hlp_session_set_t set;
  hlp_session_save_t save;
} hlp_session_t;

hlp_session_t* hlp_session_start(request_rec *r);
int hlp_session_destroy(request_rec *r, hlp_session_t *s);
int hlp_session_set(request_rec *r, hlp_session_t *s, const char *k, const char *v);
int hlp_session_get(request_rec *r, hlp_session_t *s, const char *k, const char **v);
apr_table_t* hlp_session_entries(hlp_session_t *s);
int hlp_session_num_entries(hlp_session_t *s);
int hlp_session_save(request_rec *r, hlp_session_t *s, int force);

#endif /* HLP_SESSION_H */


#ifdef HLP_SIGNALS_H

typedef void(*hlp_sighd_t)(int s);
void hlp_sighd(struct sigaction *sa, hlp_sighd_t sighd_fn);

#endif /* HLP_SIGNALS_H */

#ifdef HLP_SSL_H

const char* hlp_ssl_hash(apr_pool_t *mp, const char*, const char*);
const char* hlp_ssl_hmac(apr_pool_t *mp, const unsigned char *ps, const char *usr, const char *n, const char *mh, const char *u, const char *d);

#endif /* HLP_SSL_H */



#ifdef HLP_TCL_H
#include "tcl.h"

const char* hlp_tcl_parse_script(apr_pool_t *mp, hlp_http_request_t *r, const char *s);

#endif /* HLP_TCL_H */


#ifdef MOD_HELLO_API_H

#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_optional.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "greetings.h"

APR_DECLARE_OPTIONAL_FN(const char*, say_hello, (apr_pool_t *mp));
APR_DECLARE_OPTIONAL_FN(const char*, say_goodbye, (apr_pool_t *mp));

#endif /* MOD_HELLO_API_H */






#ifdef __cplusplus
}
#endif
#endif /* APRX_H */
