
#ifndef _ZET_RELEASE
#define _ZET_HAS_JSON
#define _ZET_HAS_SSL
#define _ZET_HAS_AUTH
#define _ZET_HAS_APACHE
#endif

#include "zet.h"

module AP_MODULE_DECLARE_DATA z_cookies_module;

int z_cookies_request_handler(request_rec *r) {
  if (strcmp(r->handler, "cookies")) return DECLINED;
  Z_APACHE_AUTHORIZE(r, &z_cookies_module);

  char *cookie_value;
  const char *cookie_name = "example_cookie";
  
  // Legge il cookie dalla richiesta
  cookie_value = (char*)apr_table_get(r->headers_in, "Cookie");
  
  if (cookie_value && strstr(cookie_value, cookie_name)) {
      // Se il cookie esiste, lo rimuove dalla richiesta
      apr_table_unset(r->headers_in, "Cookie");
  } else {
      // Se il cookie non esiste, lo imposta nella risposta
      apr_table_add(r->headers_out, "Set-Cookie", apr_psprintf(r->pool, "%s=%s; path=/", cookie_name, "example_value"));
  }
  
  // Restituisce la risposta
  ap_set_content_type(r, "text/plain");
  ap_rputs("Hello, world!", r);
  return OK;
}

void z_cookies_register_hooks(apr_pool_t *mp) {
  ap_hook_handler(z_cookies_request_handler, NULL, NULL, APR_HOOK_LAST);
}

void* z_cookies_conf_make(apr_pool_t *m, server_rec *s) {
  return (void*)apr_table_make(m, 1);
}

const char* z_cookies_conf_set(cmd_parms *p, void *c, const char *v) {
  void *cfg = ap_get_module_config(p->server->module_config, &z_cookies_module);
  apr_table_setn((apr_table_t*)cfg, p->cmd->name, v);
  return NULL;
}

const command_rec z_cookies_conf[] = {
  AP_INIT_TAKE1("ZAuthType", z_cookies_conf_set, NULL, OR_OPTIONS, ""),
  AP_INIT_TAKE1("ZAuthFile", z_cookies_conf_set, NULL, OR_OPTIONS, ""),
  {NULL}
};

module AP_MODULE_DECLARE_DATA z_cookies_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  z_cookies_conf_make,
  NULL,
  z_cookies_conf,
  z_cookies_register_hooks
};
