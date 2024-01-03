
/* Copyright (c) 2024 Riccardo Vacirca
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
*/

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

#define APRX_MAX_READ_BUFFER 16384

#define APRX_LOG_MAX_FILE_SIZE 500 * 1024 * 1024 /* (10MB) */
#define APRX_LOG_MAX_MSG_SIZE 512
#define APRX_LOG_MSG_FMT "[%s] [%s] [%05d] %s\r\n"


// Interfaccia con il server di database
typedef struct dbd_t {
  // Descrizione dell'ultimo errore occorso
  const char *er_msg;
  // Driver di database
  const apr_dbd_driver_t *drv;
  // Handler della connessione con il server di database
  apr_dbd_t *hdl;
  // Stato della transazione
  apr_dbd_transaction_t *trx;
} dbd_t;

// Interfaccia con il logger
typedef struct logger_t {
  // Puntatore al pool di memoria del servizio
  apr_pool_t *pool;
  // Handler del file di log
  apr_file_t *fh;
  // Nome del file di log
  const char *fname;
  // Mutex associato al logger
  apr_thread_mutex_t *mutex;
  apr_size_t max_size;

} logger_t;

// Stato globale del servizio
typedef struct context_t {
  // Puntatore al pool di memoria del servizio
  apr_pool_t *pool;
  // Host del servizio
  const char *host;
  // Porta del servizio
  const char *port;
  // Host + Porta associati al servizio
  const char *addr;
  // Timeout
  const char *timeout;
  // Massimo numero di threads concorrenti
  const char *max_threads;
  // Nome del del file di log
  const char *log_file;
  // Nome del driver di database
  const char *dbd_driver;
  // Stringa di connessione con il server di database
  const char *dbd_conn_s;
  // Directory di upload dei file
  const char *upload_dir;
  // Puntatore al logger
  logger_t *logger;
} context_t;

// Stato di eseguzione del main loop del servizio
volatile sig_atomic_t server_run = 1;


apr_status_t aprx_pfopen(apr_file_t **fd, const char *f, apr_int32_t fl, apr_pool_t *mp) {
  apr_status_t rv = APR_EGENERAL;
  if (mp && f) {
    rv = apr_file_open(fd, f, fl, APR_OS_DEFAULT, mp);
  }
  return rv;
}

apr_status_t aprx_pfopen_read(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return aprx_pfopen(fd, f, APR_READ, mp);
}

apr_status_t aprx_pfopen_append(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return aprx_pfopen(fd, f, APR_WRITE | APR_CREATE | APR_APPEND, mp);
}

apr_status_t aprx_pfopen_truncate(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return aprx_pfopen(fd, f, APR_WRITE | APR_CREATE | APR_TRUNCATE, mp);
}

apr_size_t aprx_fwrite(apr_file_t *fd, const char *buf, apr_size_t l) {
  apr_size_t rv = 0;
  if (fd && buf && (l > 0)) {
    apr_status_t st = apr_file_write_full(fd, buf, l, &rv);
    if (st != APR_SUCCESS) {
      rv = 0;
    }
  }
  return rv;
}

apr_size_t aprx_pfread(apr_pool_t *mp, apr_file_t *fd, void **buf) {
  apr_size_t rv = 0;
  if (mp && fd && buf) {
    apr_finfo_t finfo;
    apr_status_t st = apr_file_info_get(&finfo, APR_FINFO_NORM, fd);
    apr_size_t fsize = 0;
    if (st == APR_SUCCESS) {
      fsize = (apr_size_t)finfo.size;
    }
    if (fsize <= 0) {
      *buf = NULL;
    } else {
      if (fsize > APRX_MAX_READ_BUFFER) {
        fsize = APRX_MAX_READ_BUFFER;
      }
      *buf = (void*)apr_palloc(mp, fsize);
      if (buf) {
        st = apr_file_read_full(fd, *buf, fsize, &rv);
      }
    }
  }
  return rv;
}

apr_status_t aprx_fclose(apr_file_t *fd) {
  return apr_file_close(fd);
}


#define ERROR_TIMESTAMP -1

apr_time_t aprx_timestamp(int year, int month, int day, int hour, int minute, int second) {
  if (year == 0 && month == 0 && day == 0 && hour == 0 && minute == 0 && second == 0) {
    return apr_time_now();
  }
  if (year < 1970 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31 ||
    hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
    return ERROR_TIMESTAMP;
  }
  apr_time_exp_t timeExp;
  apr_time_t currentTime = apr_time_now(); // Ottieni il tempo corrente
  apr_time_exp_gmt(&timeExp, currentTime); // Inizializza la struttura con il tempo corrente
  timeExp.tm_year = year - 1900;  // Anno - 1900
  timeExp.tm_mon = month - 1;    // Mese (da 0 a 11)
  timeExp.tm_mday = day;         // Giorno del mese
  timeExp.tm_hour = hour;        // Ora del giorno
  timeExp.tm_min = minute;       // Minuto
  timeExp.tm_sec = second;       // Secondo
  timeExp.tm_usec = 0;           // Microsecondo
  apr_time_t unixTime;
  apr_time_exp_gmt_get(&unixTime, &timeExp);
  return unixTime;
}

apr_time_t aprx_now() {
  return aprx_timestamp(0, 0, 0, 0, 0, 0);
}









void log_rotate(logger_t *l) {
  apr_finfo_t finfo;
  // Estraggo i metadati del file di log corrente
  apr_status_t rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, l->fh);
  if (rv != APR_SUCCESS) {
    return;
  }
  // Estraggo la dimensione del file di log corrente
  apr_off_t sz = finfo.size;
  // Se la dimensione del file corrente è inferiore a quella massima termino
  if (sz < l->max_size) {
    return;
  }
  // Genero un nome di file per il file di log originale
  // con il timestamp unix corrente per non sovrascrivere file precedenti
  apr_time_t ts = aprx_now(); //aprx_timestamp(l->pool, NULL, NULL);
  if (ts <= 0) {
    return;
  }
  const char *ts_s = apr_psprintf(l->pool, "%" APR_INT64_T_FMT, ts);
  if (ts_s == NULL) {
    return;
  }
  char *fname_old = apr_psprintf(l->pool, "%s_%s.old", l->fname, ts_s);
  if (fname_old == NULL) {
    return;
  }
  // Rinomino il file l->fname in fname_old
  // l->fh adesso punta al file fname_old pertanto le operazioni di
  // scrittura vengono registrate ancora sul file originale rinominato
  rv = apr_file_rename(l->fname, fname_old, l->pool);
  if (rv != APR_SUCCESS) {
    return;
  }
  // Apro un nuovo file con il nome l->fname
  // fh_new e l->fh non puntano allo stesso file
  apr_file_t *fh_new;
  rv = aprx_pfopen_truncate(&fh_new, l->fname, l->pool);
  if (rv != APR_SUCCESS) {
    // Provo a ripristinare il nome del file di ol originale
    apr_file_rename(fname_old, l->fname, l->pool);
    return;
  }
  // Scrivo '--log-rotate' sul file originale ancora puntato da l->fh
  int w_size = apr_file_printf(l->fh, "--log-rotate\r\n");
  if (w_size <= 0) {
    // Provo a ripristinare il nome del file di ol originale
    apr_file_rename(fname_old, l->fname, l->pool);
    return;
  }
  // Copio il descrittore di fh_new in l->fh
  // Da questo momento le oprazioni di scrittura usano sul nuovo file
  // l->fh e fh_new contengono 2 copie dello stesso descrittore
  rv = apr_file_dup2(l->fh, fh_new, l->pool);
  if (rv != APR_SUCCESS) {
    // Provo a ripristinare il nome del file di ol originale
    apr_file_rename(fname_old, l->fname, l->pool);
    return;
  }
  // Chiudo la copia del descrittore di file in fh_new
  apr_file_close(fh_new);
}

logger_t* log_init(apr_pool_t *mp, apr_thread_mutex_t *m, const char *f, apr_size_t sz) {
  logger_t *ret = (logger_t*)apr_palloc(mp, sizeof(logger_t));
  if (ret != NULL) {
    ret->pool = mp;
    ret->fname = f;
    ret->mutex = m;
    ret->max_size = sz ? sz : APRX_LOG_MAX_FILE_SIZE;
    apr_status_t st = aprx_pfopen_append(&(ret->fh), f, mp);
    if (st != APR_SUCCESS) {
      return NULL;
    }
    log_rotate(ret);
  }
  return ret;
}

void log_close(logger_t *l) {
  if (l != NULL) {
    if (l->fh != NULL) {
      apr_file_close(l->fh);
      l->fh = NULL;
    }
    l = NULL;
  }
}


#define log_write(l, t, m) do {\
  if (l != NULL && t != NULL && m != NULL) {\
    char _log[APRX_LOG_MAX_MSG_SIZE], _ts[APR_CTIME_LEN];\
    apr_time_t _now = apr_time_now();\
    apr_ctime(_ts, _now);\
    apr_snprintf(_log, sizeof(_log), APRX_LOG_MSG_FMT, _ts, t, __LINE__, m);\
    size_t _len = strlen(_log);\
    if (_len > 0 && _len < (sizeof(_log)-1) && _log[_len-1] == '\n') {\
      apr_thread_mutex_lock(l->mutex);\
      apr_file_printf(l->fh, "%s", _log);\
      apr_file_flush(l->fh);\
      log_rotate(l);\
      apr_thread_mutex_unlock(l->mutex);\
    }\
  }\
} while (0)


// Alloca e inizializza lo stato globale del servizio
context_t* context_alloc(apr_pool_t *mp)
{
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

// Rilascia le risorse allocate nello stato globale del servizio
void context_destroy(context_t *ctx)
{
  if (ctx->logger != NULL) {
    if (ctx->logger->mutex != NULL) {
      // Rilascio il mutex associato al logger
      apr_thread_mutex_destroy(ctx->logger->mutex);
    }
    if (ctx->logger->fh != NULL) {
      // Chiudo lo handler del file di log
      apr_file_close(ctx->logger->fh);
    }
  }
}

// Callback associata al segnale di terminazione del servizio
void signal_cb(int signum)
{
  // In presenza di un segnale di tipo SIGTERM (es. CTRL+C)
  if (signum == SIGTERM || signum == SIGINT) {
    // Falsifico la condizione di attività del main loop del servizio
    server_run = 0;
  }
}

// Tipo puntatore a funzione associato alla callback di terminazione
typedef void(*sighd_t)(int s);

// Signal handler
void signal_handler(struct sigaction *sig_action, sighd_t signal_cb)
{
  // Inizializzo la struttura dati per il signal handler
  // con la funzione di terminazione
  sig_action->sa_handler = signal_cb;
  sigemptyset(&sig_action->sa_mask);
  sig_action->sa_flags = 0;
  // Registro la funzione di callback
  sigaction(SIGTERM, sig_action, NULL);
  sigaction(SIGINT, sig_action, NULL);
}

// Esegue in background il servizio
void daemonize()
{
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

// Request handler associato al servizio
void req_hd(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
  struct state_t {
    struct flag_t {
      int input, uri, env, pool;
    } flag;
    int error;
    apr_pool_t *pool;
    context_t *context;
    struct mg_http_message *hm;
  } st = {
    .flag.input = 0, .flag.uri = 0, .flag.env = 0, .flag.pool = 0,
    .error = 0, .context = NULL
  };

  do {
    if (ev == MG_EV_HTTP_MSG) {

      apr_status_t rv;

      // Estraggo il messaggio associato all'evento
      st.hm = (struct mg_http_message*)ev_data;
      if (st.error = (st.hm == NULL)) {
        break;
      }
    
      // Estraggo lo URI della richiesta
      st.flag.uri = strncmp(st.hm->uri.ptr, "/api/hello", 10) == 0;
      if (st.error = !st.flag.uri) {
        break;
      }
      
      // Estraggo lo stato globale del servizio
      st.context = (context_t*)fn_data;
      if (st.error = (st.context == NULL)) {
        break;
      }
      
      // Inizializzo le strutture dati APR
      rv = apr_initialize();
      st.flag.env = (rv == APR_SUCCESS);
      if (st.error = !st.flag.env) {
        break;
      }
      
      // Alloco il pool di memoria
      rv = apr_pool_create(&st.pool, NULL);
      st.flag.pool = (rv == APR_SUCCESS);
      if (st.error = !st.flag.pool) {
        break;
      }

      mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Hello, World!\n");
    }
  } while (0);

  if (st.error) {
    if (st.hm == NULL) {
      mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Invalid event data.\n");
    } else if(!st.flag.uri) {
      mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Invalid URI.\n");
    } else if (st.context == NULL) {
      mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Invalid context data.\n");
    } else if (!st.flag.env) {
      mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "APR initialization error.\n");
    } else if (!st.flag.pool) {
      mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "APR memory pool error.\n");
    } else {
      mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "General error.\n");
    }
  }

  if (st.flag.env) {
    if (st.flag.pool) {
      apr_pool_destroy(st.pool);
    }
    apr_terminate();
  }

  (void)fn_data;
}

// Esegue il parsing degli argomenti della riga di comando
apr_status_t parse_args(context_t *ctx, int argc, char *argv[], char **er_msg)
{
  struct state_t {
    struct flag_t {
      int input, arg_format;
    } flag;
    int result, error;
  } st = {
    .flag.input = 0, .flag.arg_format = 0, .result = 0, .error = 0
  };

  do {
    *er_msg = NULL;

    // Eseguo la validazione dell'input
    st.flag.input = ctx != NULL && argv != NULL && argc > 1 && ((argc - 1) % 2) == 0;
    if (st.error = !st.flag.input) {
      break;
    }

    for (int i = 1; i < argc; i += 2) {

      // Eseguo la validazione del formato degli argomenti      
      st.flag.arg_format = strlen(argv[i]) == 2;
      if (st.error = !st.flag.arg_format) {
        break;
      }

      // Estraggo il valore degli argomenti
      if (argv[i][1] == 'h') {
        // Estraggo il nome host
        ctx->host = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'p') {
        // Estraggo il numero di porta
        ctx->port = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 't') {
        // Estraggo il valore di timeout
        ctx->timeout = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'T') {
        // Estraggo il numero massimo di threads concorrenti
        ctx->max_threads = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'l') {
        // Estraggo il nome del file di log
        ctx->log_file = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'd') {
        // Estraggo il nome del driver di database (es. mysql, pgsql, ...)
        ctx->dbd_driver = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'D') {
        // Estraggo ola stringa di connessione al server di database
        ctx->dbd_conn_s = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'u') {
        // Estraggo il nome del percorso di upload
        ctx->upload_dir = apr_psprintf(ctx->pool, argv[i+1]);
      }
    }
    
    // Il formato degli argomenti non è valido
    if (st.error) {
      break;
    }
    
    // L'host non è valido
    if (st.error = (ctx->host == NULL)) {
      break;
    }
    
    // La porta non è valida
    if (st.error = (ctx->port == NULL)) {
      break;
    }
    
    // Il nome del file di log non è valido
    if (st.error = (ctx->log_file == NULL)) {
      break;
    }
    
    // Setto lo stato di successo della funzione
    st.result = 1;
  
  } while (0);

  if (st.error) {
    if (!st.flag.input) {
      *er_msg = apr_psprintf(ctx->pool, "%s: Invalid input.", __FUNCTION__);
    } else if (!st.flag.arg_format) {
      *er_msg = apr_psprintf(ctx->pool, "%s: Invalid arguments format.", __FUNCTION__);
    } else if (ctx->host == NULL) {
      *er_msg = apr_psprintf(ctx->pool, "%s: Invalid host address.", __FUNCTION__);
    } else if (ctx->port == NULL) {
      *er_msg = apr_psprintf(ctx->pool, "%s: Invalid port number.", __FUNCTION__);
    } else if (ctx->log_file == NULL) {
      *er_msg = apr_psprintf(ctx->pool, "%s: Invalid log file.", __FUNCTION__);
    } else {
      *er_msg = apr_psprintf(ctx->pool, "%s: General error.", __FUNCTION__);
    }
  }

  return st.result ? APR_SUCCESS : APR_EGENERAL;
}

// Inizializza il contesto globale del servizio
apr_status_t context_init(apr_pool_t *mp, context_t **ctx, int argc, char *argv[], char **er_msg)
{
  struct state_t {
    struct flag_t {
      int input, args, addr, mutex, logger;
    } flag;
    int error, result;
    apr_status_t mutex;
    apr_thread_mutex_t *log_mutex;
  } st = {
    .flag.input = 0, .flag.args = 0, .flag.addr = 0, .flag.mutex = 0,
    .flag.logger = 0, .error = 0, .result = 0
  };

  do {
    *er_msg = NULL;
    apr_status_t rv;

    // Eseguo la validazione dell'input della funzione
    st.flag.input = mp != NULL && *ctx != NULL && argv != NULL && argc > 1;
    if (st.error = !st.flag.input) {
      break;
    }
    
    // Eseguo il parsing degli argomenti della riga di comando
    rv = parse_args(*ctx, argc, argv, er_msg);
    st.flag.args = rv == APR_SUCCESS;
    if (st.error = !st.flag.args) {
      break;
    }
    
    // Genero l'address di avvio del server
    (*ctx)->addr = apr_psprintf(mp, "%s:%s", (*ctx)->host, (*ctx)->port);
    st.flag.addr = (*ctx)->addr != NULL;
    if (st.error = !st.flag.addr) {
      break;
    }
    
    // Creo il mutex associato al logger
    rv = apr_thread_mutex_create(&st.log_mutex, APR_THREAD_MUTEX_DEFAULT, mp);
    st.flag.mutex = rv == APR_SUCCESS;
    if (st.error = !st.flag.mutex) {
      break;
    }
    
    // Inizializzo il logger
    (*ctx)->logger = log_init(mp, st.log_mutex, (*ctx)->log_file, 0);
    st.flag.logger = (*ctx)->logger != NULL;
    if (st.error = !st.flag.logger) {
      break;
    }
    
    // Setto lo stato di successo della funzione
    st.result = 1;

  } while (0);

  if (st.error) {
    if (!st.flag.input) {
      *er_msg = apr_psprintf(mp, "%s: Invalid input", __FUNCTION__);
    } else if (!st.flag.args) {
      if (*er_msg == NULL) {
        *er_msg = apr_psprintf(mp, "%s: Invalid arguments", __FUNCTION__);
      }
    } else if (!st.flag.args) {
      *er_msg = apr_psprintf(mp, "%s: Invalid address", __FUNCTION__);
    } else if (!st.flag.mutex) {
      *er_msg = apr_psprintf(mp, "%s: Logger mutex initialization error", __FUNCTION__);
    } else if (!st.flag.logger) {
      *er_msg = apr_psprintf(mp, "%s: Logger initialization error", __FUNCTION__);
    } else {
      *er_msg = apr_psprintf(mp, "%s: General error", __FUNCTION__);
    }
  }

  return st.result ? APR_SUCCESS : APR_EGENERAL;
}

int main(int argc, char **argv)
{
  struct state_t {
    struct flag_t {
      int env, pool, context, dbd;
    } flag;
    int error;
    context_t *context;
    char *er_msg;
    apr_pool_t *pool;
    struct mg_mgr mgr;
    struct sigaction sig_action;
  } st = {
    .flag.env = 0, .flag.pool = 0, .flag.context = 0, .flag.dbd = 0,
    .error = 0, .context = NULL, .er_msg = NULL
  };

  do {
    apr_status_t rv;
    // Inizializzo il signal handler
    signal_handler(&(st.sig_action), signal_cb);
    // Inizializzo le strutture dati APR
    rv = apr_initialize();
    st.flag.env = rv == APR_SUCCESS;
    if (st.error = !st.flag.env) {
      break;
    }

    // Alloco il pool di memoria
    rv = apr_pool_create(&(st.pool), NULL);
    st.flag.pool = rv == APR_SUCCESS;
    if (st.error = !st.flag.pool) {
      break;
    }
    
    // Alloco lo stato globale del servizio
    st.context = context_alloc(st.pool);
    if (st.error = (st.context == NULL)) {
      break;
    }

    // Inizializzo lo stato globale del servizio
    rv = context_init(st.pool, &(st.context), argc, argv, &(st.er_msg));
    st.flag.context = rv == APR_SUCCESS;
    if (st.error = !st.flag.context) {
      break;
    }

    // Inizializzo le strutture dati del driver DBD
    if ((st.context)->dbd_driver != NULL) {
      if ((st.context)->dbd_conn_s != NULL) {
        rv = apr_dbd_init(st.pool);
        st.flag.dbd = rv == APR_SUCCESS;
        if (st.error = !st.flag.dbd) {
          break;
        }
      }
    }

    // Eseguo il servizio in background
    //daemonize();

    mg_mgr_init(&(st.mgr));
    // Registro il request handler del servizio
    mg_http_listen(&(st.mgr), (st.context)->addr, req_hd, (void*)(st.context));
    // Eseguo il main loop del servizio
    while (server_run) {
      mg_mgr_poll(&(st.mgr), 1000);
    }
    sleep(2);
    mg_mgr_free(&(st.mgr));
    
    // Rilascio lo stato globale del servizio
    context_destroy(st.context);
  } while (0);

  if (st.error) {
    if (!st.flag.env) {
      printf("Environment initialization error\n");
    } else if (!st.flag.pool) {
      printf("Memory pool allocation error\n");
    } else if (st.context == NULL) {
      printf("Context allocation error\n");
    } else if (!st.flag.context) {
      if (st.er_msg != NULL) {
        printf("%s.\n", st.er_msg);
      } else {
        printf("Context initialization error\n");
      }
    } else if (!st.flag.dbd) {
      printf("DBD initialization error\n");
    } else {
      printf("General error\n");
    }
  }

  if (st.flag.env) {
    if (st.flag.pool) {
      apr_pool_destroy(st.pool);
    }
    apr_terminate();
  }

  return 0;
}
