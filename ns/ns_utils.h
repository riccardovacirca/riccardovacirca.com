
#ifndef WM_UTILS_H
#define WM_UTILS_H

#include "apr.h"
#include "apr_pools.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_escape.h"
#include "apr_md5.h"
#include "apr_base64.h"
#include "apr_crypto.h"
#include "apr_thread_mutex.h"
#include "apr_file_io.h"
#include "apr_file_info.h"
#include "apr_time.h"
#include "apr_env.h"
#include "apr_time.h"
#include "apr_date.h"
#include "apr_getopt.h"
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

#define ns_ctoi(c) ((int)c-48)
#define ns_strarr(mp, n) ((const char**)apr_palloc(mp, sizeof(const char*)*n))
#define ns_strarr_set(mp, a, i, s) do {a[i]=apr_pstrdup(mp,s);} while(0)
#define ns_strarr_setn(mp, a, i, s) do {a[i]=s;} while(0)
int ns_random(int l, int h);
int ns_is_empty(const char *s);
int ns_is_integer(const char *s);
int ns_is_float(const char *s);
int ns_in_string(const char *s, const char *f);
const char* ns_trim(apr_pool_t *mp, const char *s);
const char* ns_strip_char(apr_pool_t *mp, const char *s, char c);
const char* ns_slice(apr_pool_t *mp, const char *s, apr_size_t i, apr_size_t l);
const char* ns_replace(apr_pool_t *mp, const char *s, const char *f, const char *r);
const char* ns_replace_char(apr_pool_t *mp, const char *s, char f, char r);
apr_array_header_t* ns_split(apr_pool_t *mp, const char *s, const char *sep);
const char* ns_join(apr_pool_t *mp, apr_array_header_t *a, const char *sep);
const char* ns_md5(apr_pool_t *mp, const char *s);
const char* ns_base64_encode(apr_pool_t *mp, const char *str);
const char* ns_base64_decode(apr_pool_t *mp, const char *str);
char* ns_bufferize(apr_pool_t *mp, const char *s, apr_size_t *bf_size);
char* ns_str(apr_pool_t *mp, const char *s, apr_size_t sz);
apr_table_entry_t* ns_table_entry(apr_table_t *t, int i);
apr_time_t ns_timestamp(apr_pool_t *mp, const char *dt, const char *fmt);
const char* ns_datetime(apr_pool_t *mp, apr_time_t t, const char *fmt);
const char* ns_datetime_local(apr_pool_t *mp, apr_time_t t, const char *f);
const char* ns_datetime_utc(apr_pool_t *mp, apr_time_t t, const char *fmt);
int ns_is_dir(apr_pool_t *mp, const char *dpath);
int ns_is_file(apr_pool_t *mp, const char*fpath);
apr_size_t ns_file_write(apr_pool_t *mp, const char *fname, const char *buf, apr_size_t sz, int a, int lk, char**er);
apr_size_t ns_file_read(apr_pool_t *mp, const char *fname, void **buf, int lk, char **er);
int ns_file_exists(apr_pool_t *mp, const char *f);
apr_file_t* ns_file_open_append(apr_pool_t *mp, const char *f, char **er);
apr_file_t* ns_file_open_truncate(apr_pool_t *mp, const char *f, char **er);
apr_file_t* ns_file_open_read(apr_pool_t *mp, const char *f, char **er);
const char* ns_env(apr_pool_t *mp, const char *e);
const char* ns_pipein(apr_pool_t *mp);
void ns_daemonize();

#ifdef __cplusplus
}
#endif

#endif /* WM_UTILS_H */
