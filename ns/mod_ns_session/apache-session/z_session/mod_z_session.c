
#include "mod_z_session.h"

module AP_MODULE_DECLARE_DATA z_session_module;

int z_session_request_handler(request_rec *r) {
  apr_table_t *entries;
  if (strcmp(r->handler, "session")) return DECLINED;
  z_session_t *s = z_session_start(r);
  if (s == NULL || !s->is_active) {
    ap_rprintf(r, "Sessione non attiva\n");
  } else {
    int num_entries = z_session_num_entries(s);
    if (num_entries > 0) {
      entries = z_session_entries(s);
      for (int i = 0; i < num_entries; i++) {
        apr_table_entry_t *e = z_table_entry(entries, i);
        ap_rprintf(r, "%s: %s\n", e->key, e->val);
      }
    } else {
      z_session_set(r, s, "key_1", "value_1");
      z_session_set(r, s, "key_2", "value_2");
      z_session_set(r, s, "key_3", "value_3");
      z_session_save(r, s, 1);
      ap_rprintf(r, "Dati aggiunti alla sessione\n");
    }
  }
  return OK;
}

void z_session_register_hooks(apr_pool_t *mp) {
  ap_hook_handler(z_session_request_handler, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA z_session_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  z_session_register_hooks
};
