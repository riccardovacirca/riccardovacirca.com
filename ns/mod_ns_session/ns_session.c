
#include "ns_session.h"

ns_session_t* ns_session_start(request_rec *r) {
  apr_status_t rv;
  ns_session_t *s = NULL;
  ns_session_load_t session_load;
  session_load = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
  if (session_load != NULL) {
    s = (ns_session_t*)apr_palloc(r->pool, sizeof(ns_session_t));
  }
  if (s != NULL) {
    s->is_active = 0;
    s->save = APR_RETRIEVE_OPTIONAL_FN(ap_session_save);
    s->get = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
    s->set = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);
  }
  if (s->save != NULL && s->get != NULL && s->set != NULL) {
    rv = session_load(r, &(s->ssn));
    if (rv == APR_SUCCESS) {
      s->is_active = 1;
    }
  }
  return s;
}

int ns_session_destroy(request_rec* r, ns_session_t* s) {
  apr_status_t rv = !APR_SUCCESS;
  if ((s != NULL) && s->is_active) {
    s->is_active = 0;
    s->ssn->maxage = 1; /* Set max age to 1 second */
    rv = s->save(r, s->ssn);
  }
  return (rv == APR_SUCCESS);
}

int ns_session_set(request_rec *r, ns_session_t *s, const char *k, const char *v) {
  apr_status_t rv = !APR_SUCCESS;
  if ((s != NULL) && s->is_active) {
    rv = s->set(r, s->ssn, k, v);
  }
  return (rv == APR_SUCCESS);
}
int ns_session_get(request_rec *r, ns_session_t *s, const char *k, const char **v) {
  apr_status_t rv = !APR_SUCCESS;
  if ((s != NULL) && s->is_active) {
    rv = s->get(r, s->ssn, k, v);
  }
  return rv == APR_SUCCESS;
};

int ns_session_save(request_rec *r, ns_session_t *s, int force) {
  apr_status_t rv = !APR_SUCCESS;
  if (s->is_active) {
    if (force == 1) s->ssn->dirty = 1;
    rv = s->save(r, s->ssn);
  }
  return (rv == APR_SUCCESS);
}

apr_table_t* ns_session_entries(ns_session_t *s) {
  return (s != NULL) && (s->ssn != NULL) && !apr_is_empty_table(s->ssn->entries)
    ? s->ssn->entries : NULL;
}

int ns_session_num_entries(ns_session_t *s) {
  apr_table_t *entries = ns_session_entries(s);
  return entries != NULL ? apr_table_elts(entries)->nelts : 0;
}
