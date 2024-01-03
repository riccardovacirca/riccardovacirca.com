
#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"


#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>

static int ns_cookies_handler(request_rec *r) {
  
  int result = DECLINED;
  
  struct state_t {
    int handler, input, method;
  } state = {0, 0, 0};
  
  do {
    
    state.handler = r->handler && strcmp(r->handler, "cookies") == 0;
    if (!state.handler)
      break;
    
    state.input = r != NULL;
    if (!state.input)
      break;
    
    state.method = r->method_number == M_GET;
    if (!state.method)
      break;
    

    char *cookie_value;
    const char *cookie_name = "example_cookie";

    // Leggo i cookies dallo header HTTP
    cookie_value = (char*)apr_table_get(r->headers_in, "Cookie");

    // Estraggo example_cookie dai cookies
    if (cookie_value && strstr(cookie_value, cookie_name)) {
      // Se example_cookie esiste, lo rimuove dalla richiesta
      apr_table_unset(r->headers_in, "Cookie");
    } else {
      // Se il cookie non esiste, lo imposta nella risposta
      char *cookies = apr_psprintf(r->pool, "%s=%s; path=/", cookie_name, "example_value");
      apr_table_add(r->headers_out, "Set-Cookie", apr_psprintf(r->pool, "%s=%s; path=/", cookie_name, "example_value"));
    }



    ap_set_content_type(r, "text/html;charset=ascii");
    ap_rputs("Hello, World!", r);
    
    result = OK;
  
  } while (0);
  
  if (result != OK) {
    if (!state.method) {
      result = HTTP_METHOD_NOT_ALLOWED;
    }
  }
  
  return result;
}

static void ns_cookies_register_hooks(apr_pool_t *p) {
  ap_hook_handler(ns_cookies_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ns_cookies_module = {
  STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL,
  ns_cookies_register_hooks
};
