
#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_dbd.h"

#include "mongoose.h"

#include "stdio.h"
#include "errno.h"
#include "time.h"
#include "syscall.h"
#include "unistd.h"
#include "stdlib.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "sys/file.h"
#include "string.h"
#include "signal.h"

typedef struct dbd_t {
  const char *err;
  const apr_dbd_driver_t *drv;
  apr_dbd_t *hdl;
  apr_dbd_transaction_t *trx;
} dbd_t;

typedef struct logger_t {
  apr_pool_t *pool;
  apr_file_t *fh;
  const char *fname;
  apr_thread_mutex_t *mutex;
} logger_t;

typedef struct context_t {
  apr_pool_t *pool;
  const char *host;
  const char *port;
  const char *addr;
  const char *timeout;
  const char *max_threads;
  const char *log_file;
  const char *dbd_driver;
  const char *dbd_conn_s;
  const char *upload_dir;
  logger_t *logger;
} context_t;

volatile sig_atomic_t server_run = 1;

context_t* context_alloc(apr_pool_t *mp) {
  context_t *res = (context_t*)apr_palloc(mp, sizeof(context_t));
  if (res != NULL) {
    res->pool = mp;
    res->host = NULL;
    res->port = NULL;
    res->timeout = NULL;
    res->max_threads = NULL;
    res->log_file = NULL;
    res->logger = NULL;
    res->dbd_driver = NULL;
    res->dbd_conn_s = NULL;
    res->upload_dir = NULL;
    res->addr = NULL;
  }
  return res;
}

void context_destroy(context_t *ctx) {
  if (ctx->logger != NULL) {
    if (ctx->logger->mutex != NULL) {
      apr_thread_mutex_destroy(ctx->logger->mutex);
    }
    if (ctx->logger->fh != NULL) {
      apr_file_close(ctx->logger->fh);
    }
  }
}

void signal_cb(int signum) {
  if (signum == SIGTERM || signum == SIGINT) {
    server_run = 0;
  }
}

typedef void(*sighd_t)(int s);

void signal_handler(struct sigaction *sa, sighd_t signal_cb) {
  sa->sa_handler = signal_cb;
  sigemptyset(&sa->sa_mask);
  sa->sa_flags = 0;
  sigaction(SIGTERM, sa, NULL);
  sigaction(SIGINT, sa, NULL);
}

void daemonize() {
  pid_t pid, sid;
  pid = fork();
  if (pid < 0) {
    perror("Fork failed");
    exit(1);
  }
  if (pid > 0) {
    exit(0);
  }
  sid = setsid();
  if (sid < 0) {
    perror("Error creating new session");
    exit(1);
  }
  pid = fork();
  if (pid < 0) {
    perror("Second fork failed");
    exit(1);
  }
  if (pid > 0) {
    exit(0);
  }
  if (chdir("/") < 0) {
    perror("Error changing working directory");
    exit(1);
  }
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

void request_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {

  int err = 0;
  apr_pool_t *mp;
  const char ctype[] = "Content-Type: text/plain\r\n";
  context_t *ctx;
  struct mg_http_message *hm;
  apr_status_t rv;
  
  struct state_t {
    int context, init, pool;
  } st = {0, 0, 0};
  
  do {
    if (ev == MG_EV_HTTP_MSG) {
      
      err = 1;
      
      hm = (struct mg_http_message*)ev_data;
      
      if (strncmp(hm->uri.ptr, "/api/hello", 10) != 0) {
        break;
      }
      
      ctx = (context_t*)fn_data;
      st.context = ctx != NULL;
      if (!st.context) {
        break;
      }
      
      rv = apr_initialize();
      st.init = rv == APR_SUCCESS;
      if (!st.init) {
        break;
      }
      
      rv = apr_pool_create(&mp, NULL);
      st.pool = rv == APR_SUCCESS;
      if (!st.pool) {
        break;
      }
      
      mg_http_reply(c, 200, ctype, "Hello, World!\n");

      err = 0;
    }
  } while (0);
  
  if (err) {
    if (!st.context) {
      mg_http_reply(c, 500, ctype, "Context error.\n");
    } else if (!st.init) {
      mg_http_reply(c, 500, ctype, "APR initialization error.\n");
    } else if (!st.pool) {
      mg_http_reply(c, 500, ctype, "APR memory error.\n");
    } else {
      mg_http_reply(c, 500, ctype, "General error.\n");
    }
  }

  if (st.pool) {
    apr_pool_destroy(mp);
  }
  if(st.init) {
    apr_terminate();
  }

  (void)fn_data;
}

int parse_args(context_t *ctx, int argc, char *argv[], char **err) {
  
  int res = 0;
  
  struct state_t {
    int input, args_format, host, port, log_file;
  } st = {0, 0, 0, 0, 0};
  
  do {
    st.input = ctx != NULL && argv != NULL && argc > 1 && ((argc - 1) % 2) == 0;
    if (!st.input) {
      break;
    }
    
    for (int i = 1; i < argc; i += 2) {
      
      st.args_format = strlen(argv[i]) == 2;
      if (!st.args_format) {
        break;
      }
      
      if (argv[i][1] == 'h') {
        ctx->host = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'p') {
        ctx->port = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 't') {
        ctx->timeout = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'T') {
        ctx->max_threads = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'l') {
        ctx->log_file = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'd') {
        ctx->dbd_driver = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'D') {
        ctx->dbd_conn_s = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'u') {
        ctx->upload_dir = apr_psprintf(ctx->pool, argv[i+1]);
      }
    }
    
    if (!st.args_format) {
      break;
    }
    
    st.host = ctx->host != NULL;
    if (!st.host) {
      break;
    }
    
    st.port = ctx->port != NULL;
    if (!st.port) {
      break;
    }
    
    st.log_file = ctx->log_file != NULL;
    if (!st.log_file) {
      break;
    }
    
    res = 1;
  
  } while (0);

  if (!res) {
    if (!st.input) {
      *err = apr_psprintf(ctx->pool, "%s: Invalid input.", __FUNCTION__);
    } else if (!st.args_format) {
      *err = apr_psprintf(ctx->pool, "%s: Invalid arguments format.", __FUNCTION__);
    } else if (!st.host) {
      *err = apr_psprintf(ctx->pool, "%s: Invalid host address.", __FUNCTION__);
    } else if (!st.port) {
      *err = apr_psprintf(ctx->pool, "%s: Invalid port number.", __FUNCTION__);
    } else if (!st.log_file) {
      *err = apr_psprintf(ctx->pool, "%s: Invalid log file.", __FUNCTION__);
    } else {
      *err = apr_psprintf(ctx->pool, "%s: General error.", __FUNCTION__);
    }
  }
  
  return res;
}


int context_init(apr_pool_t *mp, context_t **ctx, int argc, char *argv[], char **err) {

  int res = 0;

  apr_status_t rv;
  apr_thread_mutex_t *log_mutex;
  
  struct state_t {
    int input, context, args, addr, mutex, logger;
  } st = {0, 0, 0, 0, 0, 0};
  
  do {
    
    st.input = mp != NULL && *ctx != NULL && argv != NULL && argc > 1;
    if (!st.input) {
      break;
    }
    
    st.args = parse_args(*ctx, argc, argv, err);
    if (!st.args) {
      ctx = NULL;
      break;
    }

    (*ctx)->addr = apr_psprintf(mp, "%s:%s", (*ctx)->host, (*ctx)->port);
    st.addr = (*ctx)->addr != NULL;
    if (!st.addr) {
      break;
    }

    // rv = apr_thread_mutex_create(&log_mutex, APR_THREAD_MUTEX_DEFAULT, mp);
    // st.mutex = rv == APR_SUCCESS;
    // if (!st.mutex) {
    //   break;
    // }

    // (*ctx)->logger = log_init(mp, (*ctx)->log_file, log_mutex);
    // st.logger = (*ctx)->logger != NULL;
    // if (!st.logger) {
    //   break;
    // }

    res = 1;

  } while (0);

  if (!res) {
    if (!st.input) {
      *err = apr_psprintf(mp, "%s: Invalid input", __FUNCTION__);
    } else if(!st.args) {
      if (err == NULL) {
        *err = apr_psprintf(mp, "%s: Invalid arguments", __FUNCTION__);
      }
    } else {
      *err = apr_psprintf(mp, "%s: General error", __FUNCTION__);
    }
  }

  return res;
}

int main(int argc, char **argv) {

  // Inizializzazione del valore di ritorno

  int res = 1;

  // Inizializzazione delle variabili globali

  apr_pool_t *mp;
  apr_status_t rv;
  char *err = NULL;
  struct sigaction sa;
  context_t *ctx;
  struct mg_mgr mgr;

  // Inizializzazione dello stato

  struct state_t {
    int init, pool, context;
  } st = {0, 0, 0};

  // Logica applicativa

  do {

    signal_handler(&sa, signal_cb);

    rv = apr_initialize();
    st.init = rv == APR_SUCCESS;
    if (!st.init) {
      break;
    }

    rv = apr_pool_create(&mp, NULL);
    st.pool = rv == APR_SUCCESS;
    if (!st.pool) {
      break;
    }

    ctx = context_alloc(mp);
    st.context = ctx != NULL;
    if (!st.context) {
      break;
    }

    st.context = context_init(mp, &ctx, argc, argv, &err);
    if (!st.context) {
      break;
    }

    if (ctx->dbd_driver != NULL) {
      if (ctx->dbd_conn_s != NULL) {
        apr_dbd_init(mp);
      }
    }

    //daemonize();

    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, ctx->addr, request_handler, (void*)ctx);
    while (server_run) {
      mg_mgr_poll(&mgr, 1000);
    }
    sleep(2);
    mg_mgr_free(&mgr);
    
    context_destroy(ctx);
    
    res = 0;

  } while (0);

  // Gestione degli errori

  if (res) {
    if (!st.init) {
      printf("APR initialization error\n");
    } else if (!st.pool) {
      printf("APR memory error\n");
    } else if (!st.context) {
      if (err != NULL) {
        printf("%s.\n", err);
      } else {
        printf("Daemon context error\n");
      }
    } else {
      printf("Daemon general error\n");
    }
  }

  // Rilascio delle risorse allocate

  if (st.init) {
    if (st.pool) {
      apr_pool_destroy(mp);
    }
    apr_terminate();
  }

  // Valore di ritorno
  
  return res;
}
