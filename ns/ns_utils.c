
#include "ns_utils.h"

#define NS_MAX_READ_BUFFER 16384
#define NS_ERROR_FMT "Error: %s.\r\n"

int ns_random(int l, int h) {
  srand(time(NULL));
  return (rand() % (h - l + 1)) + l;
}

int ns_is_empty(const char *s) {
  int ret = 1;
  // Verifico se la stringa è valida
  if ((s != NULL) && (*s != '\0')) {
    // Ottengo la lunghezza
    apr_size_t l = strlen(s);
    // Attraverso la stringa
    for (apr_size_t i = 0; i < l; i ++) {
      // Se trovo un carattere non vuoto restituisco false
      if (!apr_isspace(s[i])) {
        ret = 0;
      }
    }
  }
  return ret;
}

int ns_is_integer(const char *s) {
  int ret = 0;
  // Verifico se la stringa è valida
  if ((s != NULL) && (*s != '\0')) {
    // Puntatore alla fine della stringa
    char *endp;
    // Converto la stringa in intero (in base 10)
    (void)strtol(s, &endp, 10);
    // Verifico se il puntatore di fine stringa è valido
    ret = (endp != s && *endp == '\0');
  }
  return ret;
}

int ns_is_float(const char *s) {
  int ret = 0;
  // Verifico se la stringa è valida
  if ((s != NULL) && (*s != '\0')) {
    // Puntatore alla fine della stringa
    char *endp;
    // Converto la stringa in float
    (void)strtod(s, &endp);
    // Verifico se il puntatore di fine stringa è valido
    ret = (endp != s && *endp == '\0');
  }
  return ret;
}

int ns_in_string(const char *str, const char *sub) {
  apr_size_t lstr, lsub;
  return ((str != NULL) && (sub != NULL) &&
          ((lstr = strlen(str)) > 0) && ((lsub = strlen(sub)) > 0) &&
          (lsub <= lstr) && (strstr(str, sub) != NULL));
}

const char* ns_empty_string(apr_pool_t *mp) {
  char *s = NULL;
  if ((mp != NULL) && ((s = (char*)apr_palloc(mp, 1)) != NULL)) s[0] = '\0';
  return (const char*)s;
}

const char* ns_ltrim(apr_pool_t *mp, const char *s) {
  char *ret = NULL;
  if ((mp != NULL) && (s != NULL) && (*s != '\0')) {
    while (apr_isspace(*s)) s++;
    ret = apr_pstrdup(mp, s);
  }
  return (ret == NULL) ? s : (const char*)ret; 
}

const char* ns_rtrim(apr_pool_t *mp, const char *s) {
  char *ret = NULL;
  if((mp != NULL) && (s != NULL) && (*s != '\0')) {
    if ((ret = apr_pstrdup(mp, s)) != NULL) {
      char *ptr = ret + strlen(s);
      while (isspace(*--ptr)) continue;
      *(ptr + 1) = '\0';
    }
  }
  return (ret == NULL) ? s : (const char*)ret;
}

const char* ns_trim(apr_pool_t *mp, const char *s) {
  return ((mp == NULL) || (s == NULL) || (*s == '\0'))
          ? s : ns_ltrim(mp, ns_rtrim(mp, s));
}

const char* ns_strip_char(apr_pool_t *mp, const char *s, char c) {
  char *ret = NULL;
  apr_size_t l, j = 0;
  if ((mp != NULL) && (s != NULL) && ((l = (apr_size_t)strlen(s)) > 0)) {
    if ((ret = (char*)apr_palloc(mp, sizeof(char) * (l + 1))) != NULL) {
      for (apr_size_t i = 0; i < l; i ++) {
        if (s[i] != c) {
          ret[j] = s[i];
          j ++;
        }
      }
      ret[j] = '\0';
    }
  }
  return (ret == NULL) ? s : (const char*)ret;
}

const char* ns_slice(apr_pool_t *mp, const char *s, apr_size_t i, apr_size_t l) {
  char *ret = NULL;
  apr_size_t len;
  if ((mp != NULL) && (s != NULL) && (len = (apr_size_t)strlen(s))) {
    if ((i >= 0) && (i <= (len - 1)) && (l > 0) && (l <= (len - i))) {
      if ((ret = (char*)apr_palloc(mp, sizeof(char) * (l + 1))) != NULL) {
        for (apr_size_t j = 0; j < l; j++)
          ret[j] = s[i+j];
        ret[l] = '\0';
      }
    }
  }
  return (const char*)ret;
}

const char* ns_replace(apr_pool_t *mp, const char* s, const char *f, const char *r) {
  char *ret = NULL;
  int i = 0, cnt = 0, r_len, f_len;
  if ((mp != NULL) && (s != NULL) && (*s != '\0') &&
      (f != NULL) && (*f != '\0') && (r != NULL) && (*r != '\0')) {
    if (strcmp(f, r) != 0) {
      r_len = strlen(r);
      f_len = strlen(f);
      for (i = 0; s[i] != '\0'; i++) {
        if (strstr(&s[i], f) == &s[i]) {
          cnt ++;
          i += f_len - 1;
        }
      }
      if (cnt > 0) {
        if ((ret = (char*)apr_palloc(mp, i + cnt * (r_len-f_len) + 1)) != NULL) {
          i = 0;
          while (*s) {
            if (strstr(s, f) == s) {
              strcpy(&ret[i], r);
              i += r_len;
              s += f_len;
            } else {
              ret[i++] = *s++;
            }
          }
          ret[i] = '\0';
        }
      }
    }
  }
  return (ret == NULL) ? s : (const char*)ret;
}

const char* ns_replace_char(apr_pool_t *mp, const char *s, char f, char r) {
  char *ret = NULL; 
  if ((mp != NULL) && (s != NULL) && (*s != '\0') && f && r) {
    if (f != r) {
      if ((ret = apr_pstrdup(mp, s)) != NULL) {
        for (int i = 0; i < strlen(ret); i++) {
          if (ret[i] == f) {
            ret[i] = r;
          }
        }
      }
    }
  }
  return ret == NULL ? s : (const char*)ret;
}

apr_array_header_t* ns_split(apr_pool_t *mp, const char *s, const char *sp) {
  char *str, *ptr, *tmp;
  apr_size_t l_sp;
  apr_array_header_t *ret = NULL;
  if ((mp != NULL) && (s != NULL) && (sp != NULL)) {
    if ((strlen(s) > 0) && ((l_sp = (apr_size_t)strlen(sp)) > 0)) {
      if ((ret = apr_array_make(mp, 0, sizeof(const char*))) != NULL) {
        if ((str = apr_pstrdup(mp, s)) != NULL) {
          ptr = strstr(str, sp);
          while (ptr != NULL) {
            *ptr = '\0';
            if (strlen(str) <= 0) {
              if ((tmp = apr_pstrdup(mp, "\0")) != NULL) {
                APR_ARRAY_PUSH(ret, const char*) = tmp;
              }
            } else {
              if ((tmp = apr_pstrdup(mp, str)) != NULL) {
                APR_ARRAY_PUSH(ret, const char*) = tmp;
              }
            }
            str = ptr + l_sp;
            ptr = strstr(str, sp);
          }
          if (strlen(str) <= 0) {
            if ((tmp = apr_pstrdup(mp, "\0")) != NULL) {
              APR_ARRAY_PUSH(ret, const char*) = tmp;
            }
          } else {
            if ((tmp = apr_pstrdup(mp, str)) != NULL) {
              APR_ARRAY_PUSH(ret, const char*) = tmp;
            }
          }
        }
      }
    }
  }
  return ret;
}

const char* ns_join(apr_pool_t *mp, apr_array_header_t *a, const char *sp) {
  apr_size_t sp_l;
  char *item, *ret = NULL;
  apr_array_header_t *tmp = NULL;
  if ((mp != NULL) && (a != NULL) && (a->nelts > 0)) {
    if (sp == NULL) {
      ret = apr_array_pstrcat(mp, a, 0);
    } else {
      if ((sp_l = (apr_size_t)strlen(sp)) > 0) {
        for (int i = 0; i < a->nelts; i ++) {
          if ((item = APR_ARRAY_IDX(a, i, char*))) {
            if (tmp == NULL) tmp = apr_array_make(mp, a->nelts, sizeof(char*));
            if (tmp != NULL) {
              APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, item);
              if ((sp != NULL) && (sp_l > 0) && (i < (a->nelts - 1))) {
                APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, sp);
              }
            }
          }
        }
        if ((tmp != NULL) && tmp->nelts) {
          ret = apr_array_pstrcat(mp, tmp, 0);
        }
      }
    }
  }
  return ret == NULL ? NULL : (const char*)ret;
}

const char* ns_md5(apr_pool_t *mp, const char *s) {
  char *ret = NULL;
  apr_size_t l;
  unsigned char digest[APR_MD5_DIGESTSIZE];
  if ((mp != NULL) && (s != NULL) && ((l = strlen(s)) > 0)) {
    apr_md5_ctx_t ctx;
    apr_md5_init(&ctx);
    apr_md5_update(&ctx, s, l);
    apr_md5_final(digest, &ctx);
    ret = (char*)apr_pcalloc(mp, 32 + 1);
    if (ret != NULL) {
      for(int i = 0; i < APR_MD5_DIGESTSIZE; i ++) {
        sprintf(&ret[i*2], "%02x", digest[i]);
      }
    }
  }
  return ret == NULL ? NULL : (const char*)ret;
}

const char* ns_base64_encode(apr_pool_t *mp, const char *s) {
  apr_size_t l;
  char *ret = NULL;
  if ((mp != NULL) && (s != NULL) && ((l = (apr_size_t)strlen(s)) > 0)) {
    if ((ret = (char*)apr_pcalloc(mp, apr_base64_encode_len(l))) != NULL) {
      apr_base64_encode(ret, s, l);
    }
  }
  return ret == NULL ? NULL : (const char*)ret;
}

const char* ns_base64_decode(apr_pool_t* mp, const char* s) {
  char* ret = NULL;
  apr_size_t s_len, max_ret_len, ret_len;
  if ((mp != NULL) && (s != NULL)) {
    s_len = strlen(s);
    if (s_len > 0) {
      max_ret_len = apr_base64_decode_len(s);
      if (max_ret_len > 0) {
        ret = (char*)apr_palloc(mp, max_ret_len);
        if (ret != NULL) {
          ret_len = apr_base64_decode(ret, s);
          if (ret_len >= 0) {
            ret[ret_len] = '\0';
          }
        }
      }
    }
  }
  return ret == NULL ? NULL : (const char*)ret;
}

char* ns_bufferize(apr_pool_t *mp, const char *s, apr_size_t *bf_size) {
  char *ends, *ret;
  if ((ret = (char*)apr_palloc(mp, (*bf_size)+1)) != NULL) {
    if ((ends = apr_cpystrn(ret, s, (*bf_size)+1)) != NULL) {
      *bf_size = ends - ret;
    } else {
      bf_size = 0;
      ret = NULL;
    }
  }
  return ret;
}

char* ns_str(apr_pool_t *mp, const char *s, apr_size_t sz) {
  char *ret;
  apr_size_t bf_size = sz;
  ret = ns_bufferize(mp, s, &bf_size);
  return ret != NULL && bf_size > 0 ? ret : NULL;
}

int ns_table_num_entries(apr_table_t *t) {
  return (t != NULL) ? (apr_table_elts(t))->nelts : -1;
}

apr_table_entry_t* ns_table_entry(apr_table_t *t, int i) {
  return
    (
      (t != NULL) &&
      (i >= 0) &&
      (i < (apr_table_elts(t))->nelts)
    )
    ? &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i]
    : NULL;
}

/** @p mp memory pool @p d data (1972-10-23) @p f formato (yyyy-mm-dd) */
apr_time_t ns_timestamp(apr_pool_t *mp, const char *d, const char *f) {
  apr_time_exp_t tm;
  apr_time_t t, t_inc;
  int l, inc = 0, v, er = 0;
  const char *tmp;
  if ((mp == NULL)) {return -1;}
  if ((d == NULL)) {
    return apr_time_now();
  } else if((strlen(d) > 1) && ((d[0] == '+') || (d[0] == '-'))) {
    t = apr_time_now();
    tmp = ns_strip_char(mp, d, (d[0] == '+') ? '+' : '-');
    if (tmp == NULL) {return -1;}
    t_inc = ((apr_time_t)atoi(tmp)) * APR_USEC_PER_SEC;
    return (d[0] == '+') ? t + t_inc : t - t_inc;
  } else {
    if ((f != NULL) && ((l = (int)strlen(f)) > 0)) {
      tm.tm_usec = 0;
      for (int i = 0; i < l; i++) {
        if (!er && (f[i] == 'y')) {
          if (((tmp = ns_slice(mp, d, inc, 2)) != NULL) && ns_is_integer(tmp)) {
            // 2000 - 1900
            v = atoi(tmp) + 100;
            if (v >= 0) {
              tm.tm_year = (int)v;
              inc = inc + 2 + 1;
            } else {er = 1;}
          } else {er = 1;}
        } else if (!er && (f[i] == 'Y')) {
          if (((tmp = ns_slice(mp, d, inc, 4)) != NULL) && ns_is_integer(tmp)) {
            v = atoi(tmp) - 1900;
            if (v >= 0) {
              tm.tm_year = (int)v;
              inc = inc + 4 + 1;
            } else {er = 1;}
          } else {er = 1;}
        } else if (!er && (f[i] == 'm')) {
          if (((tmp = ns_slice(mp, d, inc, 2)) != NULL) && ns_is_integer(tmp)) {
            v = atoi(tmp) - 1;
            if ((v >= 0) && (v <= 11)) {
              tm.tm_mon = (int)v;
              inc = inc + 2 + 1;
            } else {er = 1;}
          } else {er = 1;}
        } else if (!er && (f[i] == 'd')) {
          if (((tmp = ns_slice(mp, d, inc, 2)) != NULL) && ns_is_integer(tmp)) {
            v = atoi(tmp);
            if ((v >= 1) && (v <= 31)) {
              tm.tm_mday = (int)v;
              inc = inc + 2 + 1;
            } else {er = 1;}
          } else {er = 1;}
        } else if (!er && (f[i] == 'h')) {
          if (((tmp = ns_slice(mp, d, inc, 2)) != NULL) && ns_is_integer(tmp)) {
            v = atoi(tmp);
            if ((v >= 0) && (v <= 23)) {
              tm.tm_hour = (int)v;
              inc = inc + 2 + 1;
            } else {er = 1;}
          } else {er = 1;}
        } else if (!er && (f[i] == 'i')) {
          if (((tmp = ns_slice(mp, d, inc, 2)) != NULL) && ns_is_integer(tmp)) {
            v = atoi(tmp);
            if ((v >= 0) && (v <= 59)) {
              tm.tm_min = (int)v;
              inc = inc + 2 + 1;
            } else {er = 1;}
          } else {er = 1;}
        } else if (!er && (f[i] == 's')) {
          if (((tmp = ns_slice(mp, d, inc, 2)) != NULL) && ns_is_integer(tmp)) {
            v = atoi(tmp);
            if ((v >= 0) && (v <= 59)) {
              tm.tm_sec = (int)v;
              inc = inc + 2 + 1;
            } else {er = 1;}
          } else {er = 1;}
        }
      }
    }
  }
  return (!er && (apr_time_exp_get(&t, &tm) == APR_SUCCESS)) ? t : -1;
}

const char* ns_datetime(apr_pool_t *mp, apr_time_t t, const char *f) {
  apr_time_exp_t tm;
  apr_size_t size = 100;
  const char *fm;
  char tmp[100] = {0}, *ret = NULL;
  if ((mp != NULL) && t && (f != NULL)) {
    if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
      fm = apr_pstrdup(mp, f);
      fm = ns_replace(mp, ns_replace(mp, fm, "Y", "%Y"), "y", "%y");
      fm = ns_replace(mp, ns_replace(mp, fm, "m", "%m"), "d", "%d");
      fm = ns_replace(mp, ns_replace(mp, fm, "H", "%H"), "h", "%I");
      fm = ns_replace(mp, ns_replace(mp, fm, "s", "%S"), "i", "%M");
      if (fm != NULL) {
        if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
          ret = apr_pstrdup(mp, tmp);
        }
      }
    }
  }
  return ret == NULL ? NULL : (const char*)ret;
}

const char* ns_datetime_local(apr_pool_t *mp, apr_time_t t, const char *f) {
  apr_time_exp_t tm;
  apr_size_t size = 100;
  const char *fm;
  char tmp[100] = {0}, *ret = NULL;
  if ((mp != NULL) && t && (f != NULL)) {
    if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
      fm = apr_pstrdup(mp, f);
      fm = ns_replace(mp, ns_replace(mp, fm, "Y", "%Y"), "y", "%y");
      fm = ns_replace(mp, ns_replace(mp, fm, "m", "%m"), "d", "%d");
      fm = ns_replace(mp, ns_replace(mp, fm, "H", "%H"), "h", "%I");
      fm = ns_replace(mp, ns_replace(mp, fm, "s", "%S"), "i", "%M");
      fm = apr_pstrcat(mp, fm, "%z", NULL);
      if (fm != NULL) {
        if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
          ret = apr_pstrdup(mp, tmp);
        }
      }
    }
  }
  return ret == NULL ? NULL : (const char*)ret;
}

const char* ns_datetime_utc(apr_pool_t *mp, apr_time_t t, const char *f) {
  apr_time_exp_t tm;
  apr_size_t size = 100;
  char tmp[100] = {0}, *ret = NULL;
  
  if ((mp != NULL) && t) {
    if (apr_time_exp_gmt(&tm, t) == APR_SUCCESS) { // Usa apr_time_exp_gmt invece di apr_time_exp_lt
      const char *fm = "%Y-%m-%d %H:%M:%S"; // Formato desiderato

      if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
        ret = apr_pstrdup(mp, tmp);
      }
    }
  }
  
  return ret == NULL ? NULL : (const char*)ret;
}

int ns_is_dir(apr_pool_t *mp, const char *d) {
  int ret = 0;
  apr_status_t rv;
  apr_finfo_t finfo;
  if ((mp != NULL) && (d != NULL) && (strlen(d) > 0)) {
    rv = apr_stat(&finfo, d, APR_FINFO_TYPE, mp);
    ret = (int)((rv == APR_SUCCESS) && (finfo.filetype == APR_DIR));
  }
  return ret;
}

int ns_is_file(apr_pool_t *mp, const char *f) {
  int ret = 0;
  apr_finfo_t finfo;
  if ((mp != NULL) && (f != NULL) && (strlen(f) > 0)) {
    ret = (int)(apr_stat(&finfo, f, APR_FINFO_NORM, mp) == APR_SUCCESS);
  }
  return ret;
}

int ns_file_exists(apr_pool_t *mp, const char *f) {
  apr_finfo_t finfo;
  if (mp == NULL || f == NULL) return 0;
  apr_status_t rv = apr_stat(&finfo, f, APR_FINFO_NORM, mp);
  return rv == APR_SUCCESS;
}

apr_size_t ns_file_write(apr_pool_t *mp, const char *f, const char *b, apr_size_t l, int a, int lk, char **er) {
  apr_file_t *fd;
  apr_status_t rv;
  apr_size_t ret = 0;
  *er = NULL;
  int mode = APR_WRITE | APR_CREATE;
  if (a) mode |= APR_APPEND;
  if ((mp != NULL) && (er != NULL)) {
    if ((f != NULL) && (strlen(f) > 0)) {
      if ((rv = apr_file_open(&fd, f, mode, APR_OS_DEFAULT, mp)) == APR_SUCCESS) {
        if (lk) {
          rv = apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
        }
        if (rv == APR_SUCCESS) {
          ret = l;
          if ((rv = apr_file_write_full(fd, b, l, &ret)) != APR_SUCCESS) {
            *er = apr_pstrdup(mp, "Error writing to file");
          }
          if (!a) {
            if ((rv = apr_file_trunc(fd, ret)) != APR_SUCCESS) {
              *er = apr_pstrdup(mp, "Error truncating file");
            }
          }
          if (lk) {
            if ((rv = apr_file_unlock(fd)) != APR_SUCCESS) {
              *er = apr_pstrdup(mp, "Error releasing lock");
            }
          }
        } else {
          *er = apr_pstrdup(mp, "Error acquiring lock");
        }
        apr_file_close(fd);
      } else {
        *er = apr_pstrdup(mp, "Error opening file");
      }
    } else {
      *er = apr_pstrdup(mp, "Invalid filename");
    }
  } else {
    *er = apr_pstrdup(mp, "Memory pool error");
  }
  return ret;
}

apr_size_t ns_file_read(apr_pool_t *mp, const char *f, void **b, int lk, char **er) {
  int rv;
  apr_size_t sz, sr;
  apr_file_t *fd;
  apr_finfo_t finfo;
  apr_size_t ret = 0;
  if ((mp != NULL) && (b != NULL) && (er != NULL)) {
    if((f != NULL) && (strlen(f) > 0) && ns_is_file(mp, f)) {
      rv = apr_file_open(&fd, f, APR_FOPEN_READ, APR_OS_DEFAULT, mp);
      if (rv == APR_SUCCESS) {
        if (lk) {
          rv = apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
        }
        if (rv == APR_SUCCESS) {
          rv = apr_file_info_get(&finfo, APR_FINFO_NORM, fd);
          if (rv == APR_SUCCESS) {
            sz = (apr_size_t)finfo.size;
            if (sz > NS_MAX_READ_BUFFER) {
              sz = NS_MAX_READ_BUFFER;
              *er = apr_pstrdup(mp, "The file size exceeds the maximum value "
                                   "that can be stored to the buffer");
            }
            if ((*b = (void*)apr_palloc(mp, sz)) != NULL) {
              if ((rv = apr_file_read_full(fd, *b, sz, &sr)) != APR_SUCCESS) {
                *er = apr_pstrdup(mp, "Error reading file");
              }
              ret = sr;
            } else {
              *er = apr_pstrdup(mp, "Error allocating buffer");
            }
            if ((rv = apr_file_unlock(fd)) != APR_SUCCESS) {
              *er = apr_pstrdup(mp, "Error releasing lock");
            }
          } else {
            *er = apr_pstrdup(mp, "Error acquiring file info");
          }
          apr_file_close(fd);
        } else {
          *er = apr_pstrdup(mp, "Error acquiring lock");
        }
      } else {
        *er = apr_pstrdup(mp, "Error opening file");
      }
    } else {
      *er = apr_pstrdup(mp, "Invalid filename");
    }
  } else {
    *er = apr_pstrdup(mp, "Memory pool error");
  }
  return ret;
}

apr_file_t* ns_file_open(apr_pool_t *mp, const char *f, apr_int32_t fl, char **er) {
  if (mp != NULL && f != NULL) {
    apr_file_t *fd;
    apr_status_t rv = apr_file_open(&fd, f, fl, APR_OS_DEFAULT, mp);
    if (rv == APR_SUCCESS) {
      return fd;
    } else {
      if (er != NULL) {
        char error_buf[256];
        apr_strerror(rv, error_buf, sizeof(error_buf));
        *er = apr_pstrdup(mp, error_buf);
      }
    }
  }
  return NULL;
}

apr_file_t* ns_file_open_read(apr_pool_t *mp, const char *f, char **er) {
  return ns_file_open(mp, f, APR_READ, er);
}

apr_file_t* ns_file_open_append(apr_pool_t *mp, const char *f, char **er) {
  return ns_file_open(mp, f, APR_WRITE | APR_CREATE | APR_APPEND, er);
}

apr_file_t* ns_file_open_truncate(apr_pool_t *mp, const char *f, char **er) {
  return ns_file_open(mp, f, APR_WRITE | APR_CREATE | APR_TRUNCATE, er);
}

const char* ns_env(apr_pool_t *mp, const char *e) {
  char *ret;
  apr_status_t rv = apr_env_get(&ret, e, mp);
  return rv == APR_SUCCESS ? (const char*)ret : NULL;
}

// /**
//  * Legge i dati dallo standard input e li restituisce come una stringa.
//  * 'm' è il pool di memoria da utilizzare per l'allocazione di eventuali risorse.
//  */
const char* ns_pipein(apr_pool_t *mp) {
  char *ret = NULL;
  char buf[NS_MAX_READ_BUFFER] = {0};
  apr_size_t l;
  apr_file_t *fd;
  apr_size_t bytes = NS_MAX_READ_BUFFER-1;
  if (apr_file_open_stdin(&fd, mp) == APR_SUCCESS) {
    if (apr_file_read(fd, buf, &bytes) == APR_SUCCESS) {
      if ((l = strlen(buf)) > 0) {
        if ((ret = (char*)apr_palloc(mp, l+1)) != NULL) {
          memcpy(ret, buf, l);
          ret[l] = '\0';
        }
      }
    }
    apr_file_close(fd);
  }
  return (const char*)ret;
}

void ns_daemonize() {
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
