
#include "netserv.h"

int ns_rand(int l, int h) {
  srand(time(NULL));
  return l < h ? (rand() % (h - l + 1)) + l : 0;
}

int ns_is_empty(const char *s) {
  int rv = 1;
  if (s && (*s != '\0')) {
    apr_size_t l = strlen(s);
    for (apr_size_t i = 0; i < l; i ++) {
      // La stringa non è vuota se contiene almeno un carattere non vuoto
      if (!apr_isspace(s[i])) {
        rv = 0;
        break;
      }
    }
  }
  return rv;
}

int ns_is_int(const char *s) {
  int rv = 0;
  if (s && (*s != '\0')) {
    // Puntatore alla fine della stringa
    char *endp;
    // Converto la stringa in intero (in base 10)
    (void)strtol(s, &endp, 10);
    // Verifico se il puntatore di fine stringa è valido
    rv = (endp != s) && (*endp == '\0');
  }
  return rv;
}

int ns_is_double(const char *s) {
  int rv = 0;
  if (s && (*s != '\0')) {
    // Puntatore alla fine della stringa
    char *endp;
    // Converto la stringa in double
    (void)strtod(s, &endp);
    // Verifico se il puntatore di fine stringa è valido
    rv = (endp != s) && (*endp == '\0');
  }
  return rv;
}

int ns_in_string(const char *s, const char *sub) {
  int rv = 0;
  if (s && sub) {
    apr_size_t ls, lsub;
    rv = ((ls = strlen(s)) > 0) && ((lsub = strlen(sub)) > 0) &&
         (lsub <= ls) && (strstr(s, sub) != NULL);
  }
  return rv;
}

/**
 * Alloca la stringa s nel pool di memoria, in un buffer di dimensione bf_size.
 * Restituisce un puntatore alla stringa.
 * La stringa restituita ha sempre un terminatore NULL e può avere una
 * dimensione di al più bf_size-1 bytes.
*/
char* ns_buffer(apr_pool_t *mp, const char *s, apr_size_t *bf_size) {
  char *rv = NULL, *ends = NULL, str[(*bf_size)];
  if (mp && s && *bf_size > 0) {
    ends = apr_cpystrn(str, s, (*bf_size));
  }
  if (ends) {
    *bf_size = ends - str;
    if ((*bf_size) > 0) {
      rv = (char*) apr_palloc(mp, sizeof(char)*(*bf_size) + 1);
      if (rv) {
        ends = apr_cpystrn(rv, s, (*bf_size) + 1);
      }
    }
  }
  if (!rv) {
    *bf_size = 0;
  }
  return rv;
}

char* ns_str(apr_pool_t *mp, const char *s, apr_size_t sz) {
  char *rv;
  apr_size_t bf_size = sz;
  rv = ns_buffer(mp, s, &bf_size);
  return rv && bf_size > 0 ? rv : NULL;
}

const char* ns_trim(apr_pool_t *mp, const char *s) {
  char *rv = NULL;
  if (s) {
    int start = 0, end = strlen(s) - 1;
    while (isspace(s[start])) {
      start ++;
    }
    while (end > start && isspace(s[end])) {
      end --;
    }
    if (end > start) {
      int l = end - start + 1;
      rv = apr_palloc(mp, sizeof(char)*l);
      if (rv) {
        memmove(rv, s + start, l);
        rv[l] = '\0';
      }
    }
  }
  return !rv ? s : (const char*)rv;
}

const char* ns_strip_char(apr_pool_t *mp, const char *s, char c) {
  char *rv = NULL;
  apr_size_t l, j = 0;
  if (mp && s) {
    l = (apr_size_t)strlen(s);
    if (l > 0) {
      rv = (char*)apr_palloc(mp, sizeof(char) * (l + 1));
    }
  }
  if (rv) {
    // Ricostruisco la stringa con ogni elemento diverso da c
    for (apr_size_t i = 0; i < l; i ++) {
      if (s[i] != c) {
        rv[j] = s[i];
        j ++;
      }
    }
    // Aggiungo il terminatore alla fine
    rv[j] = '\0';
  }
  return !rv ? s : (const char*)rv;
}

char* ns_slice(apr_pool_t *mp, const char *s, apr_size_t i, apr_size_t l) {
  char *rv = NULL;
  apr_size_t len = 0;
  if (mp && s && (i >= 0) && (l > 0)) {
    len = (apr_size_t)strlen(s);
  }
  if ((len > 0) && (i <= (len - 1)) && (l <= (len - i))) {
    rv = (char*)apr_palloc(mp, sizeof(char) * (l + 1));
  }
  if (rv) {
    for (apr_size_t j = 0; j < l; j ++) {
      rv[j] = s[i + j];
    }
    rv[l] = '\0';
  }
  return rv;
}

const char* ns_str_replace(apr_pool_t *mp, const char *s, const char *f, const char *r) {
  char *rv = NULL;
  int i = 0, cnt = 0, r_len = 0, f_len = 0;
  if (mp && s && f && r) {
    if ((*s != '\0') && (*f != '\0') && (*r != '\0')) {
      if (strcmp(f, r) != 0) {
        f_len = strlen(f);
        r_len = strlen(r);
      }
    }
  }
  if (f_len > 0 && r_len > 0) {
    for (i = 0; s[i] != '\0'; i++) {
      if (strstr(&s[i], f) == &s[i]) {
        cnt ++;
        i += f_len - 1;
      }
    }
  }
  if (cnt > 0) {
    rv = (char*)apr_palloc(mp, i + cnt * (r_len-f_len) + 1);
  }
  if (rv) {
    i = 0;
    while (*s) {
      if (strstr(s, f) == s) {
        strcpy(&rv[i], r);
        i += r_len;
        s += f_len;
      } else {
        rv[i++] = *s++;
      }
    }
    rv[i] = '\0';
  }
  return !rv ? s : (const char*)rv;
}

const char* ns_replace_char(apr_pool_t *mp, const char *s, char f, char r) {
  char *rv = NULL; 
  if (mp && s && f && r) {
    if((*s != '\0') && (f != r)) {
      rv = apr_pstrdup(mp, s);
    }
  }
  if (rv) {
    for (int i = 0; i < strlen(rv); i++) {
      if (rv[i] == f) {
        rv[i] = r;
      }
    }
  }
  return !rv ? s : (const char*)rv;
}

char* ns_empty_string_make(apr_pool_t *mp) {
  char *rv = NULL;
  if (mp) {
    rv = (char*)apr_palloc(mp, 1);
    if (rv) {
      rv[0] = '\0';
    }
  }
  return rv;
}

apr_array_header_t* ns_split(apr_pool_t *mp, const char *s, const char *sp) {
  apr_array_header_t *rv = NULL;
  char *str = NULL;
  const char *tmp = NULL;
  apr_size_t l_sp = 0;
  if (mp && s && sp) {
    if (strlen(s) > 0) {
      l_sp = (apr_size_t)strlen(sp);
    }
  }
  if(l_sp > 0) {
    rv = apr_array_make(mp, 0, sizeof(const char*));
  }
  if (rv) {
    str = apr_pstrdup(mp, s);
  }
  if (str) {
    char *ptr = strstr(str, sp);
    while (ptr) {
      *ptr = '\0';
      if (strlen(str) <= 0) {
        tmp = (const char*)ns_empty_string_make(mp);
        if (tmp) {
          APR_ARRAY_PUSH(rv, const char*) = tmp;
        }
      } else {
        tmp = apr_pstrdup(mp, str);
        if (tmp) {
          APR_ARRAY_PUSH(rv, const char*) = tmp;
        }
      }
      str = ptr + l_sp;
      ptr = strstr(str, sp);
    }
  }
  if (strlen(str) <= 0) {
    tmp = (const char*)ns_empty_string_make(mp);
    if (tmp) {
      APR_ARRAY_PUSH(rv, const char*) = tmp;
    }
  } else {
    tmp = apr_pstrdup(mp, str);
    if (tmp) {
      APR_ARRAY_PUSH(rv, const char*) = tmp;
    }
  }
  return rv;
}

char* ns_join(apr_pool_t *mp, apr_array_header_t *a, const char *sp) {
  int valid_input = 0, valid_array = 0;
  apr_size_t sp_l;
  char *item, *rv = NULL;
  apr_array_header_t *tmp = NULL;
  valid_input = mp && a;
  if (valid_input) {
    valid_array = a->nelts > 0;
  }
  if (valid_array) {
    if (!sp) {
      rv = apr_array_pstrcat(mp, a, 0);
    } else {
      sp_l = (apr_size_t)strlen(sp);
      if (sp_l > 0) {
        for (int i = 0; i < a->nelts; i ++) {
          item = APR_ARRAY_IDX(a, i, char*);
          if (item) {
            if (!tmp) {
              tmp = apr_array_make(mp, a->nelts, sizeof(char*));
            }
          }
          if (tmp) {
            APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, item);
            if (i < (a->nelts - 1)) {
              APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, sp);
            }
          }
        }
      }
      if (tmp && (tmp->nelts > 0)) {
        rv = apr_array_pstrcat(mp, tmp, 0);
      }
    }
  }
  return rv;
}

char* ns_md5(apr_pool_t *mp, const char *s) {
  char *rv = NULL;
  apr_size_t l = 0;
  unsigned char digest[APR_MD5_DIGESTSIZE];
  if (mp && s) { 
    l = strlen(s);
  }
  if(l > 0) {
    apr_md5_ctx_t ctx;
    apr_md5_init(&ctx);
    apr_md5_update(&ctx, s, l);
    apr_md5_final(digest, &ctx);
    rv = (char*)apr_pcalloc(mp, 32 + 1);
  }
  if (rv) {
    for (int i = 0; i < APR_MD5_DIGESTSIZE; i ++) {
      sprintf(&rv[i * 2], "%02x", digest[i]);
    }
  }
  return rv;
}

char* ns_base64_encode(apr_pool_t *mp, const char *s) {
  char *rv = NULL;
  apr_size_t l = 0;
  if (mp && s) {
    l = (apr_size_t)strlen(s);
  }
  if (l > 0) {
    rv = (char*)apr_pcalloc(mp, apr_base64_encode_len(l));
  }
  if (rv != NULL) {
    apr_base64_encode(rv, s, l);
  }
  return rv;
}

char* ns_base64_decode(apr_pool_t* mp, const char* s) {
  char* rv = NULL;
  apr_size_t s_len = 0, max_rv_len = 0, rv_len = 0;
  if (mp && s) {
    s_len = strlen(s);
  }
  if (s_len > 0) {
    max_rv_len = apr_base64_decode_len(s);
  }
  if (max_rv_len > 0) {
    rv = (char*)apr_palloc(mp, max_rv_len);
  }
  if (rv) {
    rv_len = apr_base64_decode(rv, s);
  }
  if (rv_len >= 0) {
    rv[rv_len] = '\0';
  }
  return rv;
}

apr_table_t* ns_args_to_table(apr_pool_t *mp, const char *q) {
  apr_table_t *rv = NULL;
  apr_array_header_t *args, *elts;
  args = ns_split(mp, q, "&");
  if (args && args->nelts) {
    rv = apr_table_make(mp, args->nelts);
    for (int i = 0; i < args->nelts; i++) {
      const char *arg = APR_ARRAY_IDX(args, i, const char*);
      elts = ns_split(mp, arg, "=");
      if (elts && elts->nelts == 2) {
        apr_table_set(
          rv,
          APR_ARRAY_IDX(elts, 0, const char*),
          APR_ARRAY_IDX(elts, 1, const char*)
        );
      }
    }
  }
  return rv;
}

int ns_table_nelts(apr_table_t *t) {
  return t ? (apr_table_elts(t))->nelts : -1;
}

apr_table_entry_t* ns_table_elt(apr_table_t *t, int i) {
  apr_table_entry_t *rv = NULL;
  if (t && (i >= 0)) {
    if (i < (apr_table_elts(t))->nelts) {
      rv = &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i];
    }
  }
  return rv;
}

char* ns_datetime(apr_pool_t *mp, apr_time_t t, const char *f) {
  char *rv = NULL;
  apr_time_exp_t tm;
  apr_size_t size = 100;
  const char *fm = NULL;
  char tmp[100] = {0};
  if (mp && t && f) {
    if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
      fm = apr_pstrdup(mp, f);
      if (fm) {
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "Y", "%Y"), "y", "%y");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "m", "%m"), "d", "%d");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "H", "%H"), "h", "%I");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "s", "%S"), "i", "%M");
      }
    }
  }
  if (fm) {
    if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
      rv = apr_pstrdup(mp, tmp);
    }
  }
  return rv;
}

char* ns_datetime_local(apr_pool_t *mp, apr_time_t t, const char *f) {
  char *rv = NULL;
  apr_time_exp_t tm;
  apr_size_t size = 100;
  const char *fm = NULL;
  char tmp[100] = {0};
  if (mp && t && f) {
    if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
      fm = apr_pstrdup(mp, f);
      if (fm) {
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "Y", "%Y"), "y", "%y");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "m", "%m"), "d", "%d");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "H", "%H"), "h", "%I");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "s", "%S"), "i", "%M");
        fm = apr_pstrcat(mp, fm, "%z", NULL);
      }
    }
  }
  if (fm) {
    if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
      rv = apr_pstrdup(mp, tmp);
    }
  }
  return rv;
}

char* ns_datetime_utc(apr_pool_t *mp, apr_time_t t, const char *f) {
  apr_time_exp_t tm;
  apr_size_t size = 100;
  char tmp[100] = {0}, *rv = NULL;
  if (mp && t) {
    // Usa apr_time_exp_gmt invece di apr_time_exp_lt
    if (apr_time_exp_gmt(&tm, t) == APR_SUCCESS) {
      // Formato desiderato
      const char *fm = "%Y-%m-%d %H:%M:%S";
      if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
        rv = apr_pstrdup(mp, tmp);
      }
    }
  }
  return rv;
}

int ns_is_dir(const char *d, apr_pool_t *mp) {
  apr_finfo_t finfo;
  return mp && d && (strlen(d) > 0) &&
    (apr_stat(&finfo, d, APR_FINFO_TYPE, mp) == APR_SUCCESS) &&
    (finfo.filetype == APR_DIR);
}

int ns_is_file(const char *f, apr_pool_t *mp) {
  apr_finfo_t finfo;
  return mp && f && (strlen(f) > 0) &&
    (apr_stat(&finfo, f, APR_FINFO_NORM, mp) == APR_SUCCESS);
}

apr_status_t ns_file_open(apr_file_t **fd, const char *f, apr_int32_t fl, apr_pool_t *mp) {
  apr_status_t rv = APR_EGENERAL;
  if (mp && f) {
    rv = apr_file_open(fd, f, fl, APR_OS_DEFAULT, mp);
  }
  return rv;
}

apr_status_t ns_file_open_read(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return ns_file_open(fd, f, APR_READ, mp);
}

apr_status_t ns_file_open_append(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return ns_file_open(fd, f, APR_WRITE | APR_CREATE | APR_APPEND, mp);
}

apr_status_t ns_file_open_truncate(apr_file_t **fd, const char *f, apr_pool_t *mp) {
  return ns_file_open(fd, f, APR_WRITE | APR_CREATE | APR_TRUNCATE, mp);
}

apr_size_t ns_file_write(apr_file_t *fd, const char *buf, apr_size_t l) {
  apr_size_t rv = 0;
  if (fd && buf && (l > 0)) {
    apr_status_t st = apr_file_write_full(fd, buf, l, &rv);
    if (st != APR_SUCCESS) {
      rv = 0;
    }
  }
  return rv;
}

apr_size_t ns_file_read(apr_pool_t *mp, apr_file_t *fd, void **buf) {
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
      if (fsize > NS_MAX_READ_BUFFER) {
        fsize = NS_MAX_READ_BUFFER;
      }
      *buf = (void*)apr_palloc(mp, fsize);
      if (buf) {
        st = apr_file_read_full(fd, *buf, fsize, &rv);
      }
    }
  }
  return rv;
}

apr_status_t ns_file_close(apr_file_t *fd) {
  return apr_file_close(fd);
}

apr_time_t ns_timestamp(int year, int month, int day, int hour, int minute, int second) {
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

apr_time_t ns_now() {
  return ns_timestamp(0, 0, 0, 0, 0, 0);
}

void ns_log_rotate(logger_t *l) {
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
  apr_time_t ts = ns_now();
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
  rv = ns_file_open_truncate(&fh_new, l->fname, l->pool);
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

logger_t* ns_log_alloc(apr_pool_t *mp, apr_thread_mutex_t *m, const char *f, apr_size_t sz) {
  logger_t *ret = (logger_t*)apr_palloc(mp, sizeof(logger_t));
  if (ret != NULL) {
    ret->pool = mp;
    ret->fname = f;
    ret->mutex = m;
    ret->max_size = sz ? sz : NS_LOG_MAX_FILE_SIZE;
    apr_status_t st = ns_file_open_append(&(ret->fh), f, mp);
    if (st != APR_SUCCESS) {
      return NULL;
    }
    log_rotate(ret);
  }
  return ret;
}

void ns_log_destroy(logger_t *l) {
  if (l != NULL) {
    if (l->fh != NULL) {
      apr_file_close(l->fh);
      l->fh = NULL;
    }
    l = NULL;
  }
}

void ns_daemonize()
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

/**
 *  Legge i dati dallo standard input e li restituisce come una stringa.
 * 'm' è il pool di memoria da utilizzare per l'allocazione di eventuali risorse.
*/
char* ns_ppipein(apr_pool_t *mp) {
  char *rv = NULL;
  char buf[NS_MAX_READ_BUFFER] = {0};
  apr_size_t l;
  apr_file_t *fd;
  apr_size_t bytes = NS_MAX_READ_BUFFER - 1;
  apr_status_t st = apr_file_open_stdin(&fd, mp);
  if (st == APR_SUCCESS) {
    st = apr_file_read(fd, buf, &bytes);
  }
  if (st == APR_SUCCESS) {
    if (bytes > 0) {
      rv = (char*)apr_palloc(mp, bytes + 1);
    }
    if (rv) {
      memcpy(rv, buf, bytes);
      rv[bytes] = '\0';
    }
    apr_file_close(fd);
  }
  return rv;
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

// Setter e getter per il campo 'method'
void set_request_method(ns_request_t *request, const char *method) {
  request->method = method;
}

const char *get_request_method(const ns_request_t *request) {
  return request->method;
}

// Setter e getter per il campo 'body'
void set_request_body(ns_request_t *request, const char *body) {
  request->body = body;
}

const char *get_request_body(const ns_request_t *request) {
  return request->body;
}

// Setter e getter per il campo 'query'
void set_request_query(ns_request_t *request, const char *query) {
  request->query = query;
}

const char *get_request_query(const ns_request_t *request) {
  return request->query;
}

// Setter e getter per il campo 'uri'
void set_request_uri(ns_request_t *request, const char *uri) {
  request->uri = uri;
}

const char *get_request_uri(const ns_request_t *request) {
  return request->uri;
}

// Setter e getter per il campo 'headers'
void set_request_headers(ns_request_t *request, apr_table_t *headers) {
  request->headers = headers;
}

apr_table_t *get_request_headers(const ns_request_t *request) {
  return request->headers;
}

// Setter e getter per il campo 'args'
void set_request_args(ns_request_t *request, apr_table_t *args) {
  request->args = args;
}

apr_table_t *get_request_args(const ns_request_t *request) {
  return request->args;
}

// Setter e getter per il campo 'parsed_uri'
void set_request_parsed_uri(ns_request_t *request, apr_table_t *parsed_uri) {
  request->parsed_uri = parsed_uri;
}

apr_table_t *get_request_parsed_uri(const ns_request_t *request) {
  return request->parsed_uri;
}

// Setter e getter per il campo 'http_version'
void set_request_http_version(ns_request_t *request, const char *http_version) {
  request->http_version = http_version;
}

const char *get_request_http_version(const ns_request_t *request) {
  return request->http_version;
}

// Setter e getter per il campo 'client_ip'
void set_request_client_ip(ns_request_t *request, const char *client_ip) {
  request->client_ip = client_ip;
}

const char *get_request_client_ip(const ns_request_t *request) {
  return request->client_ip;
}

// Setter e getter per il campo 'client_port'
void set_request_client_port(ns_request_t *request, int client_port) {
  request->client_port = client_port;
}

int get_request_client_port(const ns_request_t *request) {
  return request->client_port;
}

// Setter e getter per il campo 'prev_method'
void set_request_prev_method(ns_request_t *request, const char *prev_method) {
  request->prev_method = prev_method;
}

const char *get_request_prev_method(const ns_request_t *request) {
  return request->prev_method;
}

// Setter e getter per il campo 'prev_uri'
void set_request_prev_uri(ns_request_t *request, const char *prev_uri) {
  request->prev_uri = prev_uri;
}

const char *get_request_prev_uri(const ns_request_t *request) {
  return request->prev_uri;
}

// Setter e getter per il campo 'session_id'
void set_request_session_id(ns_request_t *request, const char *session_id) {
  request->session_id = session_id;
}

const char *get_request_session_id(const ns_request_t *request) {
  return request->session_id;
}

// Setter e getter per il campo 'cookies'
void set_request_cookies(ns_request_t *request, apr_table_t *cookies) {
  request->cookies = cookies;
}

apr_table_t *get_request_cookies(const ns_request_t *request) {
  return request->cookies;
}

// Setter per una entry specifica nella tabella 'headers'
void set_request_header_entry(ns_request_t *request, const char *key, const char *value) {
  if (request->headers == NULL) {
    // Inizializza la tabella se non è stata ancora creata
    request->headers = apr_table_make(/* pool */, /* size_hint */);
  }

  // Imposta la chiave e il valore nella tabella
  apr_table_set(request->headers, key, value);
}

// Getter per una entry specifica nella tabella 'headers'
const char *get_request_header_entry(const ns_request_t *request, const char *key) {
  return (request->headers != NULL) ? apr_table_get(request->headers, key) : NULL;
}

// Setter per una entry specifica nella tabella 'args'
void set_request_args_entry(ns_request_t *request, const char *key, const char *value) {
  if (request->args == NULL) {
    // Inizializza la tabella se non è stata ancora creata
    request->args = apr_table_make(/* pool */, /* size_hint */);
  }

  // Imposta la chiave e il valore nella tabella
  apr_table_set(request->args, key, value);
}

// Getter per una entry specifica nella tabella 'args'
const char *get_request_args_entry(const ns_request_t *request, const char *key) {
  return (request->args != NULL) ? apr_table_get(request->args, key) : NULL;
}

// Setter per una entry specifica nella tabella 'parsed_uri'
void set_request_parsed_uri_entry(ns_request_t *request, const char *key, const char *value) {
  if (request->parsed_uri == NULL) {
    // Inizializza la tabella se non è stata ancora creata
    request->parsed_uri = apr_table_make(/* pool */, /* size_hint */);
  }

  // Imposta la chiave e il valore nella tabella
  apr_table_set(request->parsed_uri, key, value);
}

// Getter per una entry specifica nella tabella 'parsed_uri'
const char *get_request_parsed_uri_entry(const ns_request_t *request, const char *key) {
  return (request->parsed_uri != NULL) ? apr_table_get(request->parsed_uri, key) : NULL;
}

// Setter per una entry specifica nella tabella 'cookies'
void set_request_cookies_entry(ns_request_t *request, const char *key, const char *value) {
  if (request->cookies == NULL) {
    // Inizializza la tabella se non è stata ancora creata
    request->cookies = apr_table_make(/* pool */, /* size_hint */);
  }

  // Imposta la chiave e il valore nella tabella
  apr_table_set(request->cookies, key, value);
}

// Getter per una entry specifica nella tabella 'cookies'
const char *get_request_cookies_entry(const ns_request_t *request, const char *key) {
  return (request->cookies != NULL) ? apr_table_get(request->cookies, key) : NULL;
}
