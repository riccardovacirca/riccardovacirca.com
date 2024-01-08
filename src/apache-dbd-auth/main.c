
#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>

static int ns_auth_handler(request_rec *r) {
  
  int result = DECLINED;
  
  struct state_t {
    int handler, input, method;
  } state = {0, 0, 0};
  
  do {
    
    state.handler = r->handler && strcmp(r->handler, "auth") == 0;
    if (!state.handler)
      break;
    
    state.input = r != NULL;
    if (!state.input)
      break;
    
    state.method = r->method_number == M_GET;
    if (!state.method)
      break;
    
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

static void ns_auth_register_hooks(apr_pool_t *p) {
  ap_hook_handler(ns_auth_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA ns_auth_module = {
  STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL,
  ns_auth_register_hooks
};
