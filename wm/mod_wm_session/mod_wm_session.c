#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>

static int wm_session_handler(request_rec *r) {
  if (!r->handler || strcmp(r->handler, "ssn")) {
    return DECLINED;
  }

  if (r->method_number != M_GET) {
    return HTTP_METHOD_NOT_ALLOWED;
  }

  ap_set_content_type(r, "text/html;charset=ascii");
  ap_rputs("Hello, World!", r);
  return OK;
}

static void wm_session_register_hooks(apr_pool_t *p) {
  ap_hook_handler(wm_session_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA wm_session_module = {
  STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL,
  wm_session_register_hooks
};
