#ifdef _ZET_HAS_SESSION



/*


enable module:
session_cookie.load
session.load
session_crypto.load
*/


#include "mod_session.h"
typedef int (*z_session_load_t)(request_rec *r, session_rec **z);
typedef int (*z_session_save_t)(request_rec *r, session_rec *z);
typedef apr_status_t(*z_session_get_t)(request_rec *r, session_rec *z, const char *key, const char **value);
typedef apr_status_t(*z_session_set_t)(request_rec *r, session_rec *z, const char *key, const char *value);
typedef struct z_session_t {
  int is_active;
  session_rec *ssn;
  z_session_get_t get;
  z_session_set_t set;
  z_session_save_t save;
} z_session_t;
z_session_t* z_session_start(request_rec *r);
int z_session_destroy(request_rec *r, z_session_t *s);
int z_session_set(request_rec *r, z_session_t *s, const char *k, const char *v);
int z_session_get(request_rec *r, z_session_t *s, const char *k, const char **v);
apr_table_t* z_session_entries(z_session_t *s);
int z_session_num_entries(z_session_t *s);
int z_session_save(request_rec *r, z_session_t *s, int force);

#endif /* _ZET_HAS_SESSION */
