
#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_dbd.h"

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

#include "netserv.h"
#include "mongoose.h"

/**
 * Stato globale del servizio
 */
typedef struct ns_context_t {
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
  ns_logger_t *logger;
} ns_context_t;

/**
 * Stato di esecuzione del main loop del servizio
 */
volatile sig_atomic_t ns_server_run = 1;

/**
 * Alloca e inizializza lo stato globale del servizio
 * @param mp Pool di memoria
 * @return Stato globale del server
 * @pre @p mp != NULL
*/
ns_context_t* ns_context_alloc(apr_pool_t *mp)
{
  ns_context_t *res = (ns_context_t*)apr_palloc(mp, sizeof(ns_context_t));
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

/**
 * Rilascia le risorse allocate nello stato globale del servizio
 * @param ctx Stato globale del daemon
 * @pre @p ctx != NULL
*/
void ns_context_destroy(ns_context_t *ctx)
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

/**
 * Callback associata al segnale di terminazione del servizio
 */
void ns_signal_cb(int signum)
{
  // In presenza di un segnale di tipo SIGTERM (es. CTRL+C)
  if (signum == SIGTERM || signum == SIGINT) {
    // Falsifico la condizione di attività del main loop del servizio
    ns_server_run = 0;
  }
}

/**
 * Tipo puntatore a funzione associato alla callback di terminazione
 * @param s Valore intero associato al segnale
*/
typedef void(*sighd_t)(int s);

/**
 * Inizializza la struttura dati per il signal handler
 * con la funzione di terminazione e registra la funzione di callback
 * @param sig_action Struttura dati associata al gestore del segnale
 * @param cb Callback di gestione del segnale
 * @pre @p sig_action != NULL, @p cb != NULL
*/
void ns_signal_handler(struct sigaction *sig_action, sighd_t cb)
{
  sig_action->sa_handler = cb;
  sigemptyset(&sig_action->sa_mask);
  sig_action->sa_flags = 0;
  sigaction(SIGTERM, sig_action, NULL);
  sigaction(SIGINT, sig_action, NULL);
}

/**
 * Inizializza la struttura dati della request HTTP
*/
ns_status_t ns_request_init(apr_pool_t *mp, ns_request_t **req, 
                            struct mg_http_message *hm, char **er_msg)
{
  /*
  STATE INITIALIZATION
  */
  struct state_t
  {
    struct flag_t
    {
      int ok_input;
    } flag;

    int error;
    ns_status_t result;

  } st = {
    .flag.ok_input = 0,
    .error = 0,
    .result = NS_FAILURE
  };
  
  /*
  APPLICATION LOGIC
  */
  do {
    /*
    Eseguo la validazione dell'input della funzione
    */
    st.flag.ok_input = mp != NULL && req != NULL && hm != NULL;
    if (st.error = !st.flag.ok_input) {
      break;
    }

    /*
    Setto lo stato di successo della funzione
    */
    st.result = NS_SUCCESS;

  } while (0);
  
  /*
  ERROR HANDLING
  L'errore viene restituito alla funzione chiamante in er_msg
  */
  if (st.error) {
    if (!st.flag.ok_input) {
      *er_msg = apr_pstrdup(mp, "Invalid input.");
    } else {
      *er_msg = apr_pstrdup(mp, "General error.");
    }
  }

  /*
  Restituisco APR_SUCCESS in caso di successo
  altrimenti APR_EGENERAL
  */
  return st.result;
}

/**
 * Request handler associato al servizio
 * @param c Stato della connessione
 * @param ev Evento associato alla connessione corrente
 * @param ev_data Dati associati all'evento
 * @param fn_data Dati utente
 */
void req_hd(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
  /*
  STATE INITIALIZATION
  */
  struct state_t
  {
    struct flag_t
    {
      int ok_input;
      int ok_apr_init;
      int ok_pool;
      int ok_request;
      int ok_response;
    } flag;

    int error;
    apr_pool_t *pool;
    ns_context_t *context;
    struct mg_http_message *hm;
    char *er_msg;

  } st = {
    .flag.ok_input = 0,
    .flag.ok_apr_init = 0,
    .flag.ok_pool = 0,
    .flag.ok_request = 0,
    .flag.ok_response = 0,
    .error = 0,
    .context = NULL,
    .er_msg = NULL
  };

  /*
  APPLICATION LOGIC
  */
  do {
    /*
    La logica applicativa del request handler viene eseguita
    in presenza di un messaggio HTTP valido
    */
    if (ev == MG_EV_HTTP_MSG) {

      apr_status_t rv;

      /*
      Estraggo il messaggio associato all'evento
      */
      st.hm = (struct mg_http_message*)ev_data;
      if (st.error = (st.hm == NULL)) {
        break;
      }

      /*
      Estraggo lo stato globale del servizio
      */
      st.context = (ns_context_t*)fn_data;
      if (st.error = (st.context == NULL)) {
        break;
      }

      /*
      Inizializzo le strutture dati del runtime APR associate al request handler
      */
      rv = apr_initialize();
      st.flag.ok_apr_init = (rv == APR_SUCCESS);
      if (st.error = !st.flag.ok_apr_init) {
        break;
      }

      /*
      Alloco il pool di memoria associato al request handler
      */
      rv = apr_pool_create(&st.pool, NULL);
      st.flag.ok_pool = (rv == APR_SUCCESS);
      if (st.error = !st.flag.ok_pool) {
        break;
      }

      /*
      Alloco la struttura dati della request HTTP
      */
      ns_request_t *req = ns_request_alloc(st.pool);
      st.flag.ok_request = req != NULL;
      if (st.error = !st.flag.ok_request) {
        break;
      }
      
      /*
      Inizializzo la struttura dati della request HTTP
      */
      rv = ns_request_init(st.pool, &req, st.hm, &(st.er_msg));
      st.flag.ok_request = rv = APR_SUCCESS;
      if (st.error = !st.flag.ok_request) {
        break;
      }

      // /*
      // Alloco la struttura dati della response HTTP
      // */
      // ns_response_t *res = ns_response_alloc(st.pool);
      // st.flag.ok_response = res != NULL;
      // if (st.error = !st.flag.ok_response) {
      //   break;
      // }


      mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "hello\n");
      // /*
      // Eseguo il servizio
      // */
      // ns_http_handler(st.pool, req, res);

      // /*
      // Estraggo il Content-Type degli headers della response
      // */
      // const char *ctype = apr_table_get(res->headers, "Content-Type");
      // if (ctype == NULL) {
      //   ctype = apr_pstrdup(st.pool, "text/plain");
      // }

      // /*
      // Restituisco al client il body della response HTTP
      // */
      // if (res->body != NULL) {
      //   mg_http_reply(c, res->status,
      //                 apr_psprintf(st.pool, "Content-Type: %s\r\n", ctype),
      //                 (const char*)res->body);
      // }
    }
  } while (0);

  /*
  ERROR HANDLING
  L'errore viene restituito al client HTTP
  */
  if (st.error) {
    const char ctype[] = "Content-Type: text/plain\r\n";
    if (st.hm == NULL) {
      mg_http_reply(c, 500, ctype, "Invalid event data.\n");
    } else if (st.context == NULL) {
      mg_http_reply(c, 500, ctype, "Invalid context data.\n");
    } else if (!st.flag.ok_apr_init) {
      mg_http_reply(c, 500, ctype, "APR initialization error.\n");
    } else if (!st.flag.ok_pool) {
      mg_http_reply(c, 500, ctype, "APR memory pool error.\n");
    } else {
      mg_http_reply(c, 500, ctype, "General error.\n");
    }
  }

  /*
  CLEANING
  */
  if (st.flag.ok_apr_init) {
    if (st.flag.ok_pool) {
      apr_pool_destroy(st.pool);
    }
    apr_terminate();
  }

  (void)fn_data;
}

/**
 * Esegue il parsing degli argomenti della riga di comando
 * @param argc Numero degli argomenti della riga di comando
 * @param argv Array degli argomenti della riga di comando
 * @param er_msg Messaggio di errore
 * @return APR_SUCCESS in caso di successo altrimenti APR_EGENERAL
*/
ns_status_t parse_args(ns_context_t *ctx, int argc, char *argv[], char **er_msg)
{
  /*
  STATE INITIALIZATION
  */
  struct state_t
  {
    struct flag_t
    {
      // Parametri di input
      int input;
      // Formato degli argomenti della riga di comando
      int arg_format;
    } flag;

    // Stato di successo della funzione
    int result;
    // Stato di errore della funzione
    int error;

  } st = {
    .flag.input = 0,
    .flag.arg_format = 0,
    .result = NS_FAILURE,
    .error = 0
  };

  /*
  APPLICATION LOGIC
  */
  do {

    *er_msg = NULL;

    /*
    Eseguo la validazione dell'input
    */
    st.flag.input = ctx != NULL && argv != NULL && argc > 1 && ((argc-1)%2) == 0;
    if (st.error = !st.flag.input) {
      break;
    }

    for (int i = 1; i < argc; i += 2) {

      /*
      Eseguo la validazione del formato degli argomenti
      */
      st.flag.arg_format = strlen(argv[i]) == 2;
      if (st.error = !st.flag.arg_format) {
        break;
      }

      /*
      Estraggo il valore degli argomenti della riga di comando
      */
      if (argv[i][1] == 'h') {
        // Nome host
        ctx->host = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'p') {
        // Numero di porta
        ctx->port = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 't') {
        // Valore di timeout
        ctx->timeout = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'T') {
        // Numero massimo di threads concorrenti
        ctx->max_threads = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'l') {
        // Nome del file di log
        ctx->log_file = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'd') {
        // Nome del driver di database (es. mysql, pgsql, ...)
        ctx->dbd_driver = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'D') {
        // Stringa di connessione al server di database
        ctx->dbd_conn_s = apr_psprintf(ctx->pool, argv[i+1]);
      } else if (argv[i][1] == 'u') {
        // Percorso di upload per i file
        ctx->upload_dir = apr_psprintf(ctx->pool, argv[i+1]);
      }
    }

    /*
    Verifico lo stato di errore dopo l'iterazione
    */
    if (st.error) {
      // Formato degli argomenti non valido
      break;
    } else if (st.error = (ctx->host == NULL)) {
      // Host non valido
      break;
    } else if (st.error = (ctx->port == NULL)) {
      // Porta non valida
      break;
    } else if (st.error = (ctx->log_file == NULL)) {
      // Nome del file di log non valido
      break;
    }

    /*
    Setto lo stato di successo della funzione
    */
    st.result = NS_SUCCESS;

  } while (0);

  /*
  ERROR HANDLING
  L'errore viene restituito alla funzione chiamante in er_msg
  */
  if (st.error) {
    if (!st.flag.input) {
      *er_msg = apr_pstrdup(ctx->pool, "Invalid input.");
    } else if (!st.flag.arg_format) {
      *er_msg = apr_pstrdup(ctx->pool, "Invalid arguments format.");
    } else if (ctx->host == NULL) {
      *er_msg = apr_pstrdup(ctx->pool, "Invalid host address.");
    } else if (ctx->port == NULL) {
      *er_msg = apr_pstrdup(ctx->pool, "Invalid port number.");
    } else if (ctx->log_file == NULL) {
      *er_msg = apr_pstrdup(ctx->pool, "Invalid log file.");
    } else {
      *er_msg = apr_pstrdup(ctx->pool, "General error.");
    }
  }

  /*
  Restituisco APR_SUCCESS in caso di successo
  altrimenti APR_EGENERAL
  */
  return st.result;
}

/**
 * Inizializza il contesto globale del daemon
 * @param mp Memory pool
 * @param ctx Stato globale del daemon
 * @param argc Numero degli argomenti della riga di comando
 * @param argv Argomenti della riga di comando
 * @param er_msg Messaggio di errore
 * @return APR_SUCCESS in caso di successo altrimenti APR_EGENERAL
 */
ns_status_t ns_context_init(apr_pool_t *mp, ns_context_t **ctx, int argc,
                            char *argv[], char **er_msg)
{
  /*
  STATE INITIALIZATION
  */
  struct state_t 
  {
    struct flag_t
    {
      int ok_input;
      int ok_args;
      int ok_addr;
      int ok_mutex;
      int ok_logger;
    } flag;
    
    int error;
    int result;
    apr_status_t mutex;
    apr_thread_mutex_t *log_mutex;

  } st = {
    .flag.ok_input = 0,
    .flag.ok_args = 0,
    .flag.ok_addr = 0,
    .flag.ok_mutex = 0,
    .flag.ok_logger = 0,
    .error = 0,
    .result = NS_FAILURE
  };

  /*
  APPLICATION LOGIC
  */
  do {

    *er_msg = NULL;
    apr_status_t rv;

    /*
    Eseguo la validazione dell'input della funzione
    */
    st.flag.ok_input = mp != NULL && *ctx != NULL && argv != NULL && argc > 1;
    if (st.error = !st.flag.ok_input) {
      break;
    }

    /*
    Eseguo il parsing degli argomenti della riga di comando
    */
    rv = parse_args(*ctx, argc, argv, er_msg);
    st.flag.ok_args = rv == APR_SUCCESS;
    if (st.error = !st.flag.ok_args) {
      break;
    }

    /*
    Genero l'address di avvio del server nel formato HOST:PORT
    */
    (*ctx)->addr = apr_psprintf(mp, "%s:%s", (*ctx)->host, (*ctx)->port);
    st.flag.ok_addr = (*ctx)->addr != NULL;
    if (st.error = !st.flag.ok_addr) {
      break;
    }

    /*
    Creo il mutex associato al logger
    */
    rv = apr_thread_mutex_create(&st.log_mutex, APR_THREAD_MUTEX_DEFAULT, mp);
    st.flag.ok_mutex = rv == APR_SUCCESS;
    if (st.error = !st.flag.ok_mutex) {
      break;
    }

    /*
    Inizializzo il logger
    */
    (*ctx)->logger = ns_log_alloc(mp, st.log_mutex, (*ctx)->log_file, 0);
    st.flag.ok_logger = (*ctx)->logger != NULL;
    if (st.error = !st.flag.ok_logger) {
      break;
    }

    /*
    Setto lo stato di successo della funzione
    */
    st.result = NS_SUCCESS;

  } while (0);

  /*
  ERROR HANDLING
  L'errore viene restituito alla funzione chiamante in er_msg
  */
  if (st.error) {
    if (!st.flag.ok_input) {
      *er_msg = apr_pstrdup(mp, "Invalid input");
    } else if (!st.flag.ok_args) {
      if (*er_msg == NULL) {
        *er_msg = apr_pstrdup(mp, "Invalid arguments");
      }
    } else if (!st.flag.ok_args) {
      *er_msg = apr_pstrdup(mp, "Invalid address");
    } else if (!st.flag.ok_mutex) {
      *er_msg = apr_pstrdup(mp, "Logger mutex initialization error");
    } else if (!st.flag.ok_logger) {
      *er_msg = apr_pstrdup(mp, "Logger initialization error");
    } else {
      *er_msg = apr_pstrdup(mp, "General error");
    }
  }

  /*
  Restituisco APR_SUCCESS in caso di successo
  altrimenti APR_EGENERAL
  */
  return st.result;
}

/**
 * Main function del daemon
 * @param argc Numero degli argomenti della riga di comando
 * @param argv Argomenti della riga di comando
*/
int main(int argc, char **argv)
{
  /*
  STATE INITIALIZATION
  */
  struct state_t
  {
    struct flag_t
    {
      int ok_apr_init;
      int ok_pool;
      int ok_context;
      int ok_dbd;
    } flag;
    
    int error;
    ns_context_t *context;
    char *er_msg;
    apr_pool_t *pool;
    struct mg_mgr mgr;
    struct sigaction sig_action;

  } st = {
    .flag.ok_apr_init = 0,
    .flag.ok_pool = 0,
    .flag.ok_context = 0,
    .flag.ok_dbd = 0,
    .error = 0,
    .context = NULL,
    .er_msg = NULL
  };

  /*
  APPLICATION LOGIC
  */
  do {
    
    apr_status_t rv;

    /*
    Inizializzo il signal handler
    st.sig_action intercetta e gestisce i segnali di interruzione (es. CTRL+C)
    */
    ns_signal_handler(&(st.sig_action), ns_signal_cb);
    
    /*
    Inizializzo le strutture dati del runtime APR
    */
    rv = apr_initialize();
    st.flag.ok_apr_init = rv == APR_SUCCESS;
    if (st.error = !st.flag.ok_apr_init) {
      break;
    }

    /*
    Alloco il pool di memoria associato al main process del daemon
    st.pool è condiviso con il logger ed è notificato ad ogni request handler
    per la gestione delle operazioni condivise
    */
    rv = apr_pool_create(&(st.pool), NULL);
    st.flag.ok_pool = rv == APR_SUCCESS;
    if (st.error = !st.flag.ok_pool) {
      break;
    }
    
    /*
    Alloco lo stato globale del daemon
    st.context è la struttura dati propagata dal main process ai request handler
    */
    st.context = ns_context_alloc(st.pool);
    if (st.error = (st.context == NULL)) {
      break;
    }

    /*
    Inizializzo st.context con i valori degli argomenti della riga di comando,
    il puntatore al logger e il puntatore a st.pool
    */
    rv = ns_context_init(st.pool, &(st.context), argc, argv, &(st.er_msg));
    st.flag.ok_context = rv == APR_SUCCESS;
    if (st.error = !st.flag.ok_context) {
      break;
    }

    /*
    Inizializzo le strutture dati del driver DBD
    Questa operazione viene eseguita solo se i dati di connessione
    e il nome del driver di database sono stati passati dalla riga di comando
    */
    if ((st.context)->dbd_driver != NULL) {
      if ((st.context)->dbd_conn_s != NULL) {
        rv = apr_dbd_init(st.pool);
        st.flag.ok_dbd = rv == APR_SUCCESS;
        if (st.error = !st.flag.ok_dbd) {
          break;
        }
      }
    }

    /*
    Eseguo il daemon in background
    */
    #ifdef DAEMONIZE
    daemonize();
    #endif

    /*
    Metto in ascolto il daemon su porta e indirizzo specificati
    dalla riga di comando e avvio il main loop del daemon fino alla
    ricezione del segnale di terminazione
    */
    mg_mgr_init(&(st.mgr));
    mg_http_listen(&(st.mgr), (st.context)->addr, req_hd, (void*)(st.context));
    while (ns_server_run) {
      mg_mgr_poll(&(st.mgr), 1000);
    }
    sleep(2); // 2 secondi di attesa per l'uscita
    mg_mgr_free(&(st.mgr));
    
    /*
    Rilascio st.context
    */
    ns_context_destroy(st.context);

  } while (0);

  /*
  ERROR HANDLING
  st.error viene settato prima dell'esecuzione in background del daemon
  quindi STDOUT_FILENO non è stato ancora chiuso
  */
  if (st.error) {
    if (!st.flag.ok_apr_init) {
      printf("Environment initialization error\n");
    } else if (!st.flag.ok_pool) {
      printf("Memory pool allocation error\n");
    } else if (st.context == NULL) {
      printf("Context allocation error\n");
    } else if (!st.flag.ok_context) {
      if (st.er_msg != NULL) {
        printf("%s.\n", st.er_msg);
      } else {
        printf("Context initialization error\n");
      }
    } else if (!st.flag.ok_dbd) {
      printf("DBD initialization error\n");
    } else {
      printf("General error\n");
    }
  }

  /*
  CLEANING
  */
  if (st.flag.ok_apr_init) {
    if (st.flag.ok_pool) {
      apr_pool_destroy(st.pool);
    }
    apr_terminate();
  }

  return 0;
}
