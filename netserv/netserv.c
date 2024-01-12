
#include "netserv.h"

apr_status_t file_open(apr_file_t **fd, const char *f, apr_int32_t fl, apr_pool_t *mp) {
  apr_status_t rv = APR_EGENERAL;
  if (mp && f) {
    rv = apr_file_open(fd, f, fl, APR_OS_DEFAULT, mp);
  }
  return rv;
}

apr_status_t file_open_read(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return file_open(fd, f, APR_READ, mp);
}

apr_status_t file_open_append(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return file_open(fd, f, APR_WRITE | APR_CREATE | APR_APPEND, mp);
}

apr_status_t file_open_truncate(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return file_open(fd, f, APR_WRITE | APR_CREATE | APR_TRUNCATE, mp);
}

apr_size_t file_write(apr_file_t *fd, const char *buf, apr_size_t l) {
  apr_size_t rv = 0;
  if (fd && buf && (l > 0)) {
    apr_status_t st = apr_file_write_full(fd, buf, l, &rv);
    if (st != APR_SUCCESS) {
      rv = 0;
    }
  }
  return rv;
}

apr_size_t file_read(apr_pool_t *mp, apr_file_t *fd, void **buf) {
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

apr_status_t file_close(apr_file_t *fd) {
  return apr_file_close(fd);
}


apr_time_t timestamp(int year, int month, int day, int hour, int minute, int second) {
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

apr_time_t now() {
  return timestamp(0, 0, 0, 0, 0, 0);
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
  apr_time_t ts = now(); //timestamp(l->pool, NULL, NULL);
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
  rv = file_open_truncate(&fh_new, l->fname, l->pool);
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

logger_t* log_alloc(apr_pool_t *mp, apr_thread_mutex_t *m, const char *f, apr_size_t sz) {
  logger_t *ret = (logger_t*)apr_palloc(mp, sizeof(logger_t));
  if (ret != NULL) {
    ret->pool = mp;
    ret->fname = f;
    ret->mutex = m;
    ret->max_size = sz ? sz : APRX_LOG_MAX_FILE_SIZE;
    apr_status_t st = file_open_append(&(ret->fh), f, mp);
    if (st != APR_SUCCESS) {
      return NULL;
    }
    log_rotate(ret);
  }
  return ret;
}

void log_destroy(logger_t *l) {
  if (l != NULL) {
    if (l->fh != NULL) {
      apr_file_close(l->fh);
      l->fh = NULL;
    }
    l = NULL;
  }
}


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


ns_request_t* ns_request_alloc(apr_pool_t *mp)
{
  ns_request_t *req = (ns_request_t*)apr_palloc(mp, sizeof(ns_request_t));
  if (req != NULL) {
    req->args = NULL;
    req->body = NULL;
    req->headers = apr_table_make(mp, 0);
    req->parsed_uri = apr_table_make(mp, 0);
    req->query = NULL;
    req->uri = NULL;
  }
  return req;
}
