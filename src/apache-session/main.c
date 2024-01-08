
#include "httpd.h"
#include "http_protocol.h"
#include "http_config.h"
#include "ns_session.h"
#include "ns_utils.h"

static int ns_session_handler(request_rec *r) {

  int result = DECLINED;

  struct state_t {
    int handler, input, method, session, session_active, session_entries;
  } state = {0, 0, 0, 0, 0, 0};

  do {
    
    // Verifico il valore del request handler
    state.handler = r->handler && strcmp(r->handler, "ssn") == 0;
    if (!state.handler)
      break;

    // Verifico lo stato dell'input
    state.input = r != NULL;
    if (!state.input)
      break;

    // Verifico il metodo HTTP
    state.method = r->method_number == M_GET;
    if (!state.method) {
      ap_rprintf(r, "No method\n");
      break;
    }

    // Istanzio una nuova sessione
    ns_session_t *s = ns_session_start(r);
    state.session = s != NULL && s->is_active;
    if (!state.session)
      break;

    // Ottengo il numero degli inserimenti in sessione
    int num_entries = ns_session_num_entries(s);

    // Se la sessione è vuota
    if (num_entries <= 0) {
      // Registro tre valori di esempio in sessione
      ns_session_set(r, s, "key_1", "value_1");
      ns_session_set(r, s, "key_2", "value_2");
      ns_session_set(r, s, "key_3", "value_3");
      // Salvo lo stato della sessione con i valori inseriti
      ns_session_save(r, s, 1);
      // Setto il valore di ritorno
      result = OK;
      break;
    }

    // Estraggo gli inserimenti in una tabella
    apr_table_t *session_entries = ns_session_entries(s);
    state.session_entries = session_entries != NULL;
    if (!state.session_entries)
      break;

    // Setto il Content-Type HTTP
    ap_set_content_type(r, "text/plain;charset=ascii");

    // Se esistono inserimenti
    if (num_entries > 0) {
      // Stampo le relative coppie chiave/valore
      for (int i = 0; i < num_entries; i++) {
        apr_table_entry_t *e = ns_table_entry(session_entries, i);
        ap_rprintf(r, "%s: %s\n", e->key, e->val);
      }
    } else {
      ap_rprintf(r, "Session is empty\n");
    }

    result = OK;

  } while (0);

  if (result != OK) {
    if (!state.method) {
      result = OK;
    }
    else if (!state.session) {
      ap_rprintf(r, "Error: Invalid session status\n");
      result = OK;
    }
    else if (!state.session_entries) {
      ap_rprintf(r, "Error: Invalid session entries\n");
      result = OK;
    }
  }

  return result;
}

static void ns_session_register_hooks(apr_pool_t *p) {
  ap_hook_handler(ns_session_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ns_session_module = {
  STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL,
  ns_session_register_hooks
};
