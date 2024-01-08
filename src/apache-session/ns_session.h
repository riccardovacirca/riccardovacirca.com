
#ifndef ns_SESSION
#define ns_SESSION

/*enable module:
session_cookie.load
session.load
session_crypto.load
*/

#include "mod_session.h"

typedef int (*ns_session_load_t)(request_rec *r, session_rec **z);
typedef int (*ns_session_save_t)(request_rec *r, session_rec *z);
typedef apr_status_t(*ns_session_get_t)(request_rec *r, session_rec *z, const char *key, const char **value);
typedef apr_status_t(*ns_session_set_t)(request_rec *r, session_rec *z, const char *key, const char *value);
typedef struct ns_session_t {
  int is_active;
  session_rec *ssn;
  ns_session_get_t get;
  ns_session_set_t set;
  ns_session_save_t save;
} ns_session_t;
ns_session_t* ns_session_start(request_rec *r);
int ns_session_destroy(request_rec *r, ns_session_t *s);
int ns_session_set(request_rec *r, ns_session_t *s, const char *k, const char *v);
int ns_session_get(request_rec *r, ns_session_t *s, const char *k, const char **v);
apr_table_t* ns_session_entries(ns_session_t *s);
int ns_session_num_entries(ns_session_t *s);
int ns_session_save(request_rec *r, ns_session_t *s, int force);

#endif /* ns_SESSION */
