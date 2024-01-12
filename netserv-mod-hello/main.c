void ns_http_handler(ns_mg_service_t *ctx) {
  ns_mg_handler_register(ctx, "GET", "/api/test", GetHelloMessage);
  ns_mg_handler_register(ctx, "POST", "/api/test", GetSigninMessage);
}
