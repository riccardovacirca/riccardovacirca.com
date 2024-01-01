
#include "aprx.h"




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


// /** @p mp memory pool @p d data (1972-10-23) @p f formato (yyyy-mm-dd) */
// apr_time_t aprx_timestamp(apr_pool_t *mp, const char *d, const char *f) {
//   apr_time_exp_t tm;
//   apr_time_t t, t_inc;
//   int l, inc = 0, v, er = 0;
//   const char *tmp;
//   if ((mp == NULL)) {
//     return -1;
//   }
//   if ((d == NULL)) {
//     return apr_time_now();
//   } else if((strlen(d) > 1) && ((d[0] == '+') || (d[0] == '-'))) {
//     t = apr_time_now();
//     tmp = aprx_pstripc(mp, d, (d[0] == '+') ? '+' : '-');
//     if (tmp == NULL) {return -1;}
//     t_inc = ((apr_time_t)atoi(tmp)) * APR_USEC_PER_SEC;
//     return (d[0] == '+') ? t + t_inc : t - t_inc;
//   } else {
//     if ((f != NULL) && ((l = (int)strlen(f)) > 0)) {
//       tm.tm_usec = 0;
//       for (int i = 0; i < l; i++) {
//         if (!er && (f[i] == 'y')) {
//           if (((tmp = aprx_pslice(mp, d, inc, 2)) != NULL) && aprx_isint(tmp)) {
//             // 2000 - 1900
//             v = atoi(tmp) + 100;
//             if (v >= 0) {
//               tm.tm_year = (int)v;
//               inc = inc + 2 + 1;
//             } else {er = 1;}
//           } else {er = 1;}
//         } else if (!er && (f[i] == 'Y')) {
//           if (((tmp = aprx_pslice(mp, d, inc, 4)) != NULL) && aprx_isint(tmp)) {
//             v = atoi(tmp) - 1900;
//             if (v >= 0) {
//               tm.tm_year = (int)v;
//               inc = inc + 4 + 1;
//             } else {er = 1;}
//           } else {er = 1;}
//         } else if (!er && (f[i] == 'm')) {
//           if (((tmp = aprx_pslice(mp, d, inc, 2)) != NULL) && aprx_isint(tmp)) {
//             v = atoi(tmp) - 1;
//             if ((v >= 0) && (v <= 11)) {
//               tm.tm_mon = (int)v;
//               inc = inc + 2 + 1;
//             } else {er = 1;}
//           } else {er = 1;}
//         } else if (!er && (f[i] == 'd')) {
//           if (((tmp = aprx_pslice(mp, d, inc, 2)) != NULL) && aprx_isint(tmp)) {
//             v = atoi(tmp);
//             if ((v >= 1) && (v <= 31)) {
//               tm.tm_mday = (int)v;
//               inc = inc + 2 + 1;
//             } else {er = 1;}
//           } else {er = 1;}
//         } else if (!er && (f[i] == 'h')) {
//           if (((tmp = aprx_pslice(mp, d, inc, 2)) != NULL) && aprx_isint(tmp)) {
//             v = atoi(tmp);
//             if ((v >= 0) && (v <= 23)) {
//               tm.tm_hour = (int)v;
//               inc = inc + 2 + 1;
//             } else {er = 1;}
//           } else {er = 1;}
//         } else if (!er && (f[i] == 'i')) {
//           if (((tmp = aprx_pslice(mp, d, inc, 2)) != NULL) && aprx_isint(tmp)) {
//             v = atoi(tmp);
//             if ((v >= 0) && (v <= 59)) {
//               tm.tm_min = (int)v;
//               inc = inc + 2 + 1;
//             } else {er = 1;}
//           } else {er = 1;}
//         } else if (!er && (f[i] == 's')) {
//           if (((tmp = aprx_pslice(mp, d, inc, 2)) != NULL) && aprx_isint(tmp)) {
//             v = atoi(tmp);
//             if ((v >= 0) && (v <= 59)) {
//               tm.tm_sec = (int)v;
//               inc = inc + 2 + 1;
//             } else {er = 1;}
//           } else {er = 1;}
//         }
//       }
//     }
//   }
//   return (!er && (apr_time_exp_get(&t, &tm) == APR_SUCCESS)) ? t : -1;
// }

// =============================================================================
// LOGS
// =============================================================================

aprx_logger_t* aprx_log_init(apr_pool_t *mp, apr_thread_mutex_t *m, const char *f, apr_size_t sz) {
  aprx_logger_t *ret = (aprx_logger_t*)apr_palloc(mp, sizeof(aprx_logger_t));
  if (ret != NULL) {
    ret->pool = mp;
    ret->fname = f;
    ret->mutex = m;
    ret->max_size = sz ? sz : APRX_LOG_MAX_FILE_SIZE;
    apr_status_t st = aprx_pfopen_append(&(ret->fh), f, mp);
    if (st != APR_SUCCESS) {
      return NULL;
    }
    aprx_log_rotate(ret);
  }
  return ret;
}

void aprx_log_rotate(aprx_logger_t *l) {
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

void aprx_log_close(aprx_logger_t *l) {
  if (l != NULL) {
    if (l->fh != NULL) {
      apr_file_close(l->fh);
      l->fh = NULL;
    }
    l = NULL;
  }
}

// =============================================================================
// JSON
// =============================================================================

#ifdef json

#include "hlp_json.h"

#define HLP_JSON_TRUE_S  "true"
#define HLP_JSON_FALSE_S "false"
#define HLP_JSON_NULL_S  "null"

hlp_json_pair_t* hlp_json_pair_init(apr_pool_t *mp) {
  hlp_json_pair_t *ret = NULL;
  if (mp != NULL) {
    if ((ret = (hlp_json_pair_t*)apr_palloc(mp, sizeof(hlp_json_pair_t))) != NULL) {
      //ret->pool = mp;
      ret->key = NULL;
      ret->val = NULL;
      ret->type = HLP_JSON_T_ZERO;
    }
  }
  return ret;
}

hlp_json_object_t* hlp_json_object_init(apr_pool_t *mp) {
  return (hlp_json_object_t*)apr_array_make(mp, 0, sizeof(hlp_json_pair_t*));
}

int hlp_json_object_add(apr_pool_t *mp, hlp_json_object_t *jo, hlp_json_type_t tp, const char *k, void *v) {
  int ret = 0;
  hlp_json_pair_t *entry;
  if ((mp != NULL) && (jo != NULL) && (tp >= 0)) {
    if ((entry = hlp_json_pair_init(mp)) != NULL) {
      entry->key = k;
      entry->val = v;
      entry->type = tp;
      APR_ARRAY_PUSH(jo, hlp_json_pair_t*) = entry;
      ret = 1;
    }
  }
  return ret;
}

hlp_json_type_t hlp_int_type(apr_int64_t v) {
  if (v < APR_INT32_MIN) {
    return HLP_JSON_T_INT64;
  } else if (v < APR_INT16_MIN) {
    return HLP_JSON_T_INT32;
  } else if (v <= APR_INT16_MAX) {
    return HLP_JSON_T_INT16;
  } else if (v <= APR_UINT16_MAX) {
    return HLP_JSON_T_UINT16;
  } else if (v <= APR_INT32_MAX) {
    return HLP_JSON_T_INT32;
  } else if (v <= APR_UINT32_MAX) {
    return HLP_JSON_T_UINT32;
  } else if (v < APR_INT64_MAX) {
    return HLP_JSON_T_INT64;
  } else {
    return HLP_JSON_T_ZERO;
  }
}

hlp_json_pair_t* hlp_json_array_entry_make(apr_pool_t *mp, int type, const char *key, json_object *val) {
  hlp_json_pair_t *entry = hlp_json_pair_init(mp);
  entry->key = key != NULL ? apr_pstrdup(mp, key) : NULL;
  // Eseguo lo switch dei tipi predefiniti di json-c
  switch (type) {
    case json_type_null: {
      entry->type = HLP_JSON_T_NULL;
      entry->val = NULL;
    } break;
    case json_type_boolean:{
      entry->type = HLP_JSON_T_BOOLEAN;
      entry->val = (void*)apr_palloc(mp, sizeof(char));
      *((char*)entry->val) = json_object_get_boolean(val);
    } break;
    case json_type_double: {
      entry->type = HLP_JSON_T_DOUBLE;
      entry->val = (void*)apr_palloc(mp, sizeof(double));
      *((double*)entry->val) = json_object_get_double(val);
    } break;
    case json_type_int: {
      apr_uint64_t tmp_u = 0;
      apr_int64_t tmp_i = (apr_int64_t)json_object_get_int64(val);
      hlp_json_type_t int_type = hlp_int_type(tmp_i);
      if (!int_type) {
        tmp_u = (apr_uint64_t)json_object_get_uint64(val);
        if (tmp_u > APR_INT64_MAX) {
          int_type = HLP_JSON_T_UINT64;
        } else {
          int_type = HLP_JSON_T_INT64;
        }
      }
      if (int_type == HLP_JSON_T_INT16) {
        entry->type = HLP_JSON_T_INT16;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_int16_t));
        *((apr_int16_t*)entry->val) = (apr_int16_t)tmp_i;
      } else if (int_type == HLP_JSON_T_UINT16) {
        entry->type = HLP_JSON_T_UINT16;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_uint16_t));
        *((apr_uint16_t*)entry->val) = (apr_uint16_t)tmp_i;
      } else if (int_type == HLP_JSON_T_INT32) {
        entry->type = HLP_JSON_T_INT32;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_int32_t));
        *((apr_int32_t*)entry->val) = (apr_int32_t)tmp_i;
      } else if (int_type == HLP_JSON_T_UINT32) {
        entry->type = HLP_JSON_T_UINT32;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_uint32_t));
        *((apr_uint32_t*)entry->val) = (apr_uint32_t)tmp_i;
      } else if (int_type == HLP_JSON_T_INT64) {
        entry->type = HLP_JSON_T_INT64;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_int64_t));
        *((apr_int64_t*)entry->val) = (apr_int64_t)tmp_i;
      } else if (int_type == HLP_JSON_T_UINT64) {
        entry->type = HLP_JSON_T_UINT64;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_uint64_t));
        *((apr_uint64_t*)entry->val) = (apr_uint64_t)tmp_u;
      }
    } break;
    case json_type_string: {
      entry->type = HLP_JSON_T_STRING;
      entry->val = (void*)apr_pstrdup(mp, (const char*)json_object_get_string(val));
    } break;
  }
  return entry;
}

apr_array_header_t* hlp_json_parse(apr_pool_t *mp, json_object *jobj);

apr_array_header_t* hlp_json_parse_array(apr_pool_t *mp, json_object *jarr) {
  int jarr_l;
  enum json_type type;
  //, *jtmp; è stata sostituita dalla seguente riga:
  json_object *jval; 
  hlp_json_pair_t *entry;
  apr_array_header_t *res = NULL;
  jarr_l = json_object_array_length(jarr);
  for (int i = 0; i < jarr_l; i ++) {
    jval = json_object_array_get_idx(jarr, i);
    type = json_object_get_type(jval);
    if (type == json_type_array) {
      entry = hlp_json_pair_init(mp);
      entry->type = HLP_JSON_T_ARRAY;
      entry->key = NULL;
      entry->val = (void*)hlp_json_parse_array(mp, jval);
    } else if (type == json_type_object) {
      //entry = (hlp_json_pair_t*)apr_palloc(mp, sizeof(hlp_json_pair_t));
      entry = hlp_json_pair_init(mp);
      entry->type = HLP_JSON_T_OBJECT;
      entry->key = NULL;
      entry->val = (void*)hlp_json_parse(mp, jval);
    } else {
      entry = hlp_json_array_entry_make(mp, type, NULL, jval);
    }
    if (res == NULL) res = apr_array_make(mp, 0, sizeof(hlp_json_pair_t*));
    APR_ARRAY_PUSH(res, hlp_json_pair_t*) = entry;
  }
  return res;
}

apr_array_header_t* hlp_json_parse(apr_pool_t *mp, json_object *jobj) {
  hlp_json_pair_t *entry = NULL;
  apr_array_header_t *res = NULL;
  enum json_type type;
  json_object *jtmp;
  json_object_object_foreach(jobj, key, val) {
    type = json_object_get_type(val);
    switch (type) {
      case json_type_object: {
        if (json_object_object_get_ex(jobj, key, &jtmp)) {
          entry = hlp_json_pair_init(mp);
          entry->type = HLP_JSON_T_OBJECT;
          entry->key = apr_pstrdup(mp, key);
          entry->val = (void*)hlp_json_parse(mp, jtmp);
        }
      } break;
      case json_type_array: {
        if (json_object_object_get_ex(jobj, key, &jtmp)) {
          entry = hlp_json_pair_init(mp);
          entry->type = HLP_JSON_T_ARRAY;
          entry->key = apr_pstrdup(mp, key);
          entry->val = (void*)hlp_json_parse_array(mp, jtmp);
        }
      } break;
      default: {
        entry = hlp_json_array_entry_make(mp, type, key, val);
      } break;
    }
    if (res == NULL) res = apr_array_make(mp, 0, sizeof(hlp_json_pair_t*));
    APR_ARRAY_PUSH(res, hlp_json_pair_t*) = entry;
  }
  return res;
}

apr_array_header_t* hlp_json_decode(apr_pool_t *mp, const char *s) {
  json_object *jobj;
  apr_array_header_t* ret;
  jobj = json_tokener_parse(s);
  ret = hlp_json_parse(mp, jobj);
  json_object_put(jobj);
  return ret;
}

const char* hlp_json_encode(apr_pool_t *mp, const void *v, hlp_json_type_t tp) {
  int len;
  apr_table_entry_t *e;
  apr_table_t *t;
  hlp_json_pair_t *p;
  // Dichiaro 2 array temporanei
  apr_array_header_t *obj, *arr = NULL;
  // Inizializzo il valore di ritorno
  const char *ret = NULL;
  // Verifico che la memoria sia allocata e il tipo di dato specificato
  if (mp != NULL && tp) {
    if (v == NULL || tp == HLP_JSON_T_NULL) {
      // Il dato è una primitiva NULL
      ret = apr_pstrdup(mp, HLP_JSON_NULL_S);
    } else if (tp == HLP_JSON_T_BOOLEAN) {
      // Il dato è una primitiva booleana
      ret = apr_pstrdup(mp, *(char*)v ? HLP_JSON_TRUE_S : HLP_JSON_FALSE_S);
    } else if (tp == HLP_JSON_T_INT16) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%hd", *((apr_int16_t*)v));
    } else if (tp == HLP_JSON_T_UINT16) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%hu", *((apr_uint16_t*)v));
    } else if (tp == HLP_JSON_T_INT32) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%d", *((apr_int32_t*)v));
    } else if (tp == HLP_JSON_T_UINT32) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%u", *((apr_uint32_t*)v));
    } else if (tp == HLP_JSON_T_INT64) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%" APR_INT64_T_FMT, *((apr_int64_t*)v));
    } else if (tp == HLP_JSON_T_UINT64) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%" APR_UINT64_T_FMT, *((apr_uint64_t*)v));
    } else if (tp == HLP_JSON_T_DOUBLE) {
      // Il dato è una primitiva double
      ret = apr_psprintf(mp, "%0.8lf", *(double*)v);
    } else if (tp == HLP_JSON_T_STRING) {
      // Il dato è una stringa
      ret = apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, (const char*)v, 1));
    } else if (tp == HLP_JSON_T_JSON) {
      // Il dato è una stringa JSON pre-codificata
      ret = apr_psprintf(mp, "%s", (const char*)v);
    } else if (tp == HLP_JSON_T_TIMESTAMP) {
      // Il dato è un apr_time_t
      ret = apr_psprintf(mp, "%" APR_TIME_T_FMT, (apr_time_t)v);
    } else if (tp > HLP_JSON_T_VECTOR) {
      // Il dato è un vettore di elementi di tipo (tp - HLP_JSON_T_VECTOR)
      // La funzione si aspetta un vettore di primitive o di stringhe
      int type = tp - HLP_JSON_T_VECTOR;
      // Un vettore è una struttura apr_array_header_t di dati dello stesso tipo
      obj = (apr_array_header_t*)v;
      // Verifico che la struttura non sia vuota
      if (obj->nelts > 0) {
        if (arr == NULL) {
          // Alloco un array temporaneo per gli elementi del vettore
          arr = apr_array_make(mp, 1, sizeof(const char*));
        }
        if (arr != NULL) {
          // Ripeto per ogni elemento del vettore
          for (int i = 0; i < obj->nelts; i ++) {
            switch (type) {
              case HLP_JSON_T_NULL: {
                // Aggiungo all'array temporaneo una stringa null
                APR_ARRAY_PUSH(arr, const char*) = apr_pstrdup(mp, HLP_JSON_NULL_S);
              } break;
              case HLP_JSON_T_BOOLEAN: {
                // Estraggo il intero
                int entry = APR_ARRAY_IDX(obj, i, int);
                // Aggiungo all'array temporaneo una stringa true o false
                APR_ARRAY_PUSH(arr, const char*) = apr_pstrdup(mp, entry ? HLP_JSON_TRUE_S : HLP_JSON_FALSE_S);
              } break;
              case HLP_JSON_T_INT16: {
                // Estraggo il valore intero
                apr_int16_t entry = APR_ARRAY_IDX(obj, i, apr_int16_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%hd", entry);
              } break;
              case HLP_JSON_T_UINT16: {
                // Estraggo il valore intero
                apr_uint16_t entry = APR_ARRAY_IDX(obj, i, apr_uint16_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%hu", entry);
              } break;
              case HLP_JSON_T_INT32: {
                // Estraggo il valore intero
                apr_int32_t entry = APR_ARRAY_IDX(obj, i, apr_int32_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%d", entry);
              } break;
              case HLP_JSON_T_UINT32: {
                // Estraggo il valore intero
                apr_uint32_t entry = APR_ARRAY_IDX(obj, i, apr_uint32_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%u", entry);
              } break;
              case HLP_JSON_T_INT64: {
                // Estraggo il valore intero
                apr_int64_t entry = APR_ARRAY_IDX(obj, i, apr_int64_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%" APR_INT64_T_FMT, entry);
              } break;
              case HLP_JSON_T_UINT64: {
                // Estraggo il valore intero
                apr_uint64_t entry = APR_ARRAY_IDX(obj, i, apr_uint64_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%" APR_UINT64_T_FMT, entry);
              } break;
              case HLP_JSON_T_DOUBLE: {
                // Estraggo il valore double
                double entry = APR_ARRAY_IDX(obj, i, double);
                // Aggiungo all'array temporaneo il valore double
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%0.8lf", entry);
              } break;
              case HLP_JSON_T_STRING: {
                // Estraggo il valore stringa
                // ------------------------------------------------------------
                // FIXME: deve essere eseguito l'escape della stringa estratta
                //        prima che venga aggiunta all'array temporaneo
                // ------------------------------------------------------------
                const char *entry = APR_ARRAY_IDX(obj, i, const char*);
                // Aggiungo all'array temporaneo il valore stringa
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, entry, 1));
              } break;
              case HLP_JSON_T_JSON: {
                const char *entry = APR_ARRAY_IDX(obj, i, const char*);
                // Aggiungo all'array temporaneo il valore stringa JSON
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%s", entry);
              } break;
              case HLP_JSON_T_TIMESTAMP: {
                // Estraggo il valore apr_time_t
                apr_time_t entry = APR_ARRAY_IDX(obj, i, apr_time_t);
                // Aggiungo all'array temporaneo il valore apr_time_t
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%" APR_TIME_T_FMT, entry);
              } break;
              case HLP_JSON_T_TABLE: {
                apr_table_t *entry = APR_ARRAY_IDX(obj, i, apr_table_t*);
                APR_ARRAY_PUSH(arr, const char*) =
                  //apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, entry, 1));
                  hlp_json_encode(mp, (const void*)entry, HLP_JSON_T_TABLE);
              } break;
            }
          }
          // Al termine del ciclo for se l'array temporaneo non è vuoto
          // setto il valore di ritorno con la sua versione serializzata
          // in caso contrario il valore di ritorno contiene ancora NULL
          if (arr->nelts > 0) {
            const char *tmp_s = hlp_join(mp, arr, ",");
            if (tmp_s != NULL) {
              ret = apr_psprintf(mp, "[%s]", tmp_s);
            }
            // @todo else
          }
        }
      }
    } else if (tp == HLP_JSON_T_TABLE) {
      t = (apr_table_t*)v;
      if (t && (len = (apr_table_elts(t))->nelts)) {
        if ((arr = apr_array_make(mp, len, sizeof(const char*)))) {
          for (int i = 0; i < len; i ++) {
            if ((e = &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i])) {
              APR_ARRAY_PUSH(arr, const char*) =
                apr_psprintf(mp, "\"%s\":\"%s\"", (const char*)e->key,
                             apr_pescape_echo(mp, (const char*)e->val, 1));
            }
          }
          if (arr->nelts > 0) {
            const char *tmp_s = hlp_join(mp, arr, ",");
            if (tmp_s != NULL) {
              ret = apr_psprintf(mp, "{%s}", tmp_s);
            }
          }
        }
      }
    } else if (tp == HLP_JSON_T_OBJECT) {
      // Il dato è un oggetto (ovvero un array associativo)
      // Un oggetto è una struttura apr_array_header_t di hlp_json_pair_t
      // La struttura hlp_json_pair_t contiene informazioni anche sul tipo di dato
      // La funzione richiede che le chiavi dei pair dell'array non siano NULL
      // altrimenti l'elemento non verrà aggiunto all'array temporaneo
      obj = (apr_array_header_t*)v;
      // Verifico che l'oggetto non sia vuoto
      if (obj->nelts > 0) {
        // Alloco un array temporaneo per gli elementi dell'oggetto
        if ((arr = apr_array_make(mp, 1, sizeof(const char*))) != NULL) {
          // Ripeto per ogni elemento dell'oggetto
          for (int i = 0; i < obj->nelts; i++) {
            // Estraggo il prossimo pair
            if ((p = APR_ARRAY_IDX(obj, i, hlp_json_pair_t*)) != NULL) {
              if (!p->key) continue;
              switch (p->type) {
                case HLP_JSON_T_NULL: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore null
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, HLP_JSON_NULL_S);
                } break;
                case HLP_JSON_T_BOOLEAN: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore boolean
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, *(char*)p->val ? HLP_JSON_TRUE_S : HLP_JSON_FALSE_S);
                } break;
                case HLP_JSON_T_INT16: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%hd", p->key, *(apr_int16_t*)p->val);
                } break;
                case HLP_JSON_T_UINT16: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%hu", p->key, *(apr_uint16_t*)p->val);
                } break;
                case HLP_JSON_T_INT32: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%d", p->key, *(apr_int32_t*)p->val);
                } break;
                case HLP_JSON_T_UINT32: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%u", p->key, *(apr_uint32_t*)p->val);
                } break;
                case HLP_JSON_T_INT64: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%" APR_INT64_T_FMT, p->key, *(apr_int64_t*)p->val);
                } break;
                case HLP_JSON_T_UINT64: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%" APR_UINT64_T_FMT, p->key, *(apr_uint64_t*)p->val);
                } break;
                case HLP_JSON_T_TIMESTAMP: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore timestamp
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%" APR_TIME_T_FMT, p->key, *(apr_time_t*)p->val);
                } break;
                case HLP_JSON_T_DOUBLE: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore double
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%0.8lf", p->key, *(double*)p->val);
                } break;
                case HLP_JSON_T_STRING: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore string
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":\"%s\"", p->key, apr_pescape_echo(mp, (const char*)p->val, 1));
                } break;
                case HLP_JSON_T_JSON: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore string JSON
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, (const char*)p->val);
                } break;
                case HLP_JSON_T_OBJECT: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore object
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, hlp_json_encode(mp, p->val, HLP_JSON_T_OBJECT));
                } break;
                default: break;
              }
            }
          }
          if (arr->nelts > 0) {
            const char *tmp_s = hlp_join(mp, arr, ",");
            if (tmp_s != NULL) {
              ret = apr_psprintf(mp, "{%s}", tmp_s);
            }
          }
        }
      }
    }
  }
  return ret;
}

#endif

// =============================================================================
// DBD
// =============================================================================

#ifdef dbd

#include "hlp_dbd.h"

hlp_dbd_t* hlp_dbd_init(apr_pool_t *mp) {
  hlp_dbd_t *ret = NULL;
  if (mp != NULL) {
    if ((ret = (hlp_dbd_t*)apr_palloc(mp, sizeof(hlp_dbd_t))) != NULL) {
      ret->drv = NULL;
      ret->hdl = NULL;
      ret->err = NULL;
      ret->trx = NULL;
      ret->cod = 0;
    }
  }
  return ret;
}

int hlp_dbd_open(apr_pool_t *mp, hlp_dbd_t *d, const char *s, const char *c) {
  int ret = 0;
  apr_status_t rv;
  d->err = NULL;
  d->drv = NULL;
  d->hdl = NULL;
  d->cod = 0;
  if (mp && d) {
    rv = apr_dbd_get_driver(mp, s, &(d->drv));
  }
  if (rv == APR_SUCCESS) {
    rv = apr_dbd_open_ex(d->drv, mp, c, &(d->hdl), &(d->err));
  }
  ret = rv == APR_SUCCESS;
  if (!ret) {
    d->drv = NULL;
    d->hdl = NULL;
    d->cod = 1;
  }
  return ret;
}

const char* hlp_dbd_escape(apr_pool_t *mp, hlp_dbd_t *d, const char *s) {
  return ((mp == NULL) || (d == NULL) || (s == NULL))
    ? NULL
    : apr_dbd_escape(d->drv, mp, s, d->hdl);
}

int hlp_dbd_query(apr_pool_t *mp, hlp_dbd_t *d, const char *sql) {
  int aff_rows = 0;
  if (mp == NULL || d == NULL || sql == NULL) return -1;
  d->err = NULL;
  d->cod = apr_dbd_query(d->drv, d->hdl, &aff_rows, sql);
  if (d->cod) {
    d->err = apr_pstrdup(mp, apr_dbd_error(d->drv, d->hdl, d->cod));
    return -1;
  }
  return aff_rows;
}

int hlp_dbd_transaction_start(apr_pool_t *mp, hlp_dbd_t *dbd) {
  int rv = 1;
  const char *error;
  if ((mp != NULL) && (dbd != NULL)) {
    if ((rv = apr_dbd_transaction_start(dbd->drv, mp, dbd->hdl, &(dbd->trx)))) {
      if ((error = apr_dbd_error(dbd->drv, dbd->hdl, rv)) != NULL) {
        dbd->err = apr_pstrdup(mp, error);
      }
    }
  }
  return (rv == 0 ? 0 : -1);
}

int hlp_dbd_transaction_end(apr_pool_t *mp, hlp_dbd_t *dbd)
{
  int rv = 1;
  const char *error;
  if ((mp != NULL) && (dbd != NULL)) {
    if ((rv = apr_dbd_transaction_end(dbd->drv, mp, dbd->trx))) {
      if ((error = apr_dbd_error(dbd->drv, dbd->hdl, rv)) != NULL) {
        dbd->err = apr_pstrdup(mp, error);
      }
    }
  }
  return (rv == 0 ? 0 : -1);
}

apr_array_header_t*
hlp_dbd_result_to_array(apr_pool_t *mp, hlp_dbd_t *dbd, apr_dbd_results_t *res) {
  apr_table_t *rec;
  apr_dbd_row_t *row = NULL;
  apr_array_header_t *rset = NULL;
  const char *k, *v;
  int rv, first_rec, num_fields;
  if ((mp != NULL) && (dbd != NULL) && (res != NULL)) {
    if ((rv = apr_dbd_get_row(dbd->drv, mp, res, &row, -1)) != -1) {
      first_rec = 1;
      while (rv != -1) {
        if (first_rec) {
          num_fields = apr_dbd_num_cols(dbd->drv, res);
          rset = apr_array_make(mp, num_fields, sizeof(apr_table_t*));
          first_rec = 0;
        }
        rec = apr_table_make(mp, num_fields);
        for (int i = 0; i < num_fields; i++) {
          k = apr_dbd_get_name(dbd->drv, res, i);
          v = apr_dbd_get_entry(dbd->drv, row, i);
          apr_table_set(rec, apr_pstrdup(mp, k),
                        apr_pstrdup(mp, hlp_is_empty(v) ? "NULL" : v));
        }
        APR_ARRAY_PUSH(rset, apr_table_t*) = rec;
        rv = apr_dbd_get_row(dbd->drv, mp, res, &row, -1);
      }
    }
  }
  return rset;
}

int hlp_dbd_prepared_query(apr_pool_t *mp, hlp_dbd_t *dbd, const char *sql,
                          apr_table_t *args)
{
  apr_table_entry_t *arg;
  const char **args_ar, *err;
  apr_dbd_prepared_t *stmt = NULL;
  int aff_rows = 0, nelts, rv;
  if (mp != NULL && dbd != NULL && sql != NULL) {
    dbd->err = NULL;
    if ((nelts = apr_table_elts(args)->nelts) > 0) {
      args_ar = (const char**)apr_palloc(mp, sizeof(const char*)*nelts);
      if (args_ar != NULL) {
        for (int i = 0; i < nelts; i++) {
          arg = hlp_table_entry(args, i);
          if (arg != NULL) {
            args_ar[i] = apr_pstrdup(mp, arg->val);
            if (args_ar[i] == NULL) {
              return -1;
            }
          }
        }
        dbd->cod = apr_dbd_prepare(dbd->drv, mp, dbd->hdl, sql, NULL, &stmt);
        if (dbd->cod) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, dbd->cod);
          dbd->err = apr_pstrdup(mp, err);
          return -1;
        }
        dbd->cod = apr_dbd_pquery(dbd->drv, mp, dbd->hdl, &aff_rows, stmt, nelts,
                                  args_ar);
        if (dbd->cod) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, dbd->cod);
          dbd->err = apr_psprintf(mp, "%s", err);
          return -1;
        }
      }
    }
  }
  return aff_rows;
}

// int hlp_dbd_prepared_query(apr_pool_t *mp, hlp_dbd_t *dbd,
//                           const char *sql, const char **args, int sz) {
  
//   const char *err;
//   apr_dbd_prepared_t *stmt = NULL;
//   int aff_rows = 0, rv;
//   if (mp != NULL && dbd != NULL && sql != NULL && args != NULL && sz > 0) {
//     dbd->err = NULL;
//     rv = apr_dbd_prepare(dbd->drv, mp, dbd->hdl, sql, NULL, &stmt);
//     if (rv) {
//       err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
//       dbd->err = apr_pstrdup(mp, err);
//       return -1;
//     }
//     rv = apr_dbd_pquery(dbd->drv, mp, dbd->hdl, &aff_rows, stmt, sz, args);
//     if (rv) {
//       err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
//       dbd->err = apr_psprintf(mp, "%s", err);
//       return -1;
//     }
//   }
//   return aff_rows;
// }

apr_array_header_t* hlp_dbd_prepared_select(apr_pool_t *mp, hlp_dbd_t *dbd,
                                           const char *sql, apr_table_t *args) {
  int rv, nelts;
  apr_dbd_results_t *res = NULL;
  apr_array_header_t *rset = NULL;
  char **args_ar;
  const char *err;
  apr_table_entry_t *arg;
  apr_dbd_prepared_t *stmt = NULL;
  if ((mp != NULL) && (dbd != NULL) && (sql != NULL) && (args != NULL)) {
    if ((nelts = apr_table_elts(args)->nelts) > 0) {
      if ((args_ar = (char**)apr_palloc(mp, sizeof(char*)*nelts)) != NULL) {
        for (int i = 0; i < nelts; i++) {
          if ((arg = hlp_table_entry(args, i)) != NULL) {
            if ((args_ar[i] = apr_psprintf(mp, "%s", arg->val)) == NULL) {
              return NULL;
            }
          }
        }
        rv = apr_dbd_prepare(dbd->drv, mp, dbd->hdl, sql, NULL, &stmt);
        if (rv) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
          dbd->err = apr_psprintf(mp, "%s", err);
          return NULL;
        }
        rv = apr_dbd_pselect(dbd->drv, mp, dbd->hdl, &res,
                             stmt, 0, nelts, (const char**)args_ar);
        if (rv) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
          dbd->err = apr_psprintf(mp, "%s", err);
          return NULL;
        }
        rset = hlp_dbd_result_to_array(mp, dbd, res);
      }
    }
  }
  return rset;
}

apr_array_header_t* hlp_dbd_select(apr_pool_t *mp, hlp_dbd_t *d, const char *sql) {
  int rv, err;
  apr_dbd_results_t *res = NULL;
  apr_dbd_row_t *row = NULL;
  apr_array_header_t *rset = NULL;
  apr_table_t *rec;
  const char *k, *v;
  int first_rec, num_fields;
  if ((mp != NULL) && (d != NULL) && (sql != NULL)) {
    d->err = NULL;
    if ((err = apr_dbd_select(d->drv, mp, d->hdl, &res, sql, 0))) {
      d->err = apr_pstrdup(mp, apr_dbd_error(d->drv, d->hdl, err));
    } else {
      if (res != NULL) {
        if ((rv = apr_dbd_get_row(d->drv, mp, res, &row, -1)) != -1) {
          rset = NULL;
          first_rec = 1;
          while (rv != -1) {
            if (first_rec) {
              num_fields = apr_dbd_num_cols(d->drv, res);
              rset = apr_array_make(mp, num_fields, sizeof(apr_table_t*));
              first_rec = 0;
            }
            rec = apr_table_make(mp, num_fields);
            for (int i = 0; i < num_fields; i++) {
              k = apr_dbd_get_name(d->drv, res, i);
              v = apr_dbd_get_entry(d->drv, row, i);
              apr_table_set(rec, apr_pstrdup(mp, k),
                            apr_pstrdup(mp, hlp_is_empty(v) ? "NULL" : v));
            }
            APR_ARRAY_PUSH(rset, apr_table_t*) = rec;
            rv = apr_dbd_get_row(d->drv, mp, res, &row, -1);
          }
        }
      }
    }
  }
  return rset;
}

int hlp_dbd_num_records(apr_array_header_t *r) {
  return (int)(r != NULL ? r->nelts : 0);
}

int hlp_dbd_num_columns(apr_array_header_t *r) {
  int ret = 0;
  apr_table_t *rec;
  if (r && r->nelts) {
    if ((rec = APR_ARRAY_IDX(r, 0, apr_table_t*))) {
      ret = apr_table_elts(rec)->nelts;
    }
  }
  return ret;
}

apr_array_header_t* hlp_dbd_column_names(apr_pool_t *mp, apr_array_header_t *r) {
  int nelts;
  apr_table_entry_t* e;
  apr_table_t *rec;
  apr_array_header_t *ret = NULL;
  if (r != NULL && r->nelts) {
    if ((rec = APR_ARRAY_IDX(r, 0, apr_table_t*))) {
      if ((nelts = (apr_table_elts(rec)->nelts))) {
        if ((ret = apr_array_make(mp, nelts, sizeof(const char*)))) {
          for (int i = 0; i < nelts; i++) {
            if ((e = &((apr_table_entry_t*)((apr_table_elts(rec))->elts))[i])) {
              APR_ARRAY_PUSH(ret, const char*) = apr_pstrdup(mp, e->key);
            }
          }
        }
      }
    }
  }
  return ret;
}

apr_table_t* hlp_dbd_record(apr_array_header_t *r, int i) {
  return (r != NULL) && r->nelts && (i <= r->nelts-1)
    ? APR_ARRAY_IDX(r, i, apr_table_t*)
    : NULL;
}

const char* hlp_dbd_field_value(apr_array_header_t *res, int i, const char *k) {
  if (res == NULL || res->nelts <= 0 || i > (res->nelts-1)) return NULL;
  apr_table_t* rec = APR_ARRAY_IDX(res, i, apr_table_t*);
  return apr_table_get(rec, k);
}

int hlp_dbd_field_set(apr_array_header_t *r, int i, const char *k, const char *v) {
  if (r == NULL || r->nelts <= 0 || i > (r->nelts-1)) return 1;
  apr_table_t* t = APR_ARRAY_IDX(r, i, apr_table_t*);
  apr_table_set(t, k, v);
  return 0;
}

int hlp_dbd_close(hlp_dbd_t *d) {
  return d == NULL ? 0 : apr_dbd_close(d->drv, d->hdl);
}

const char* hlp_dbd_driver_name(hlp_dbd_t *dbd) {
  return dbd == NULL ? NULL : apr_dbd_name(dbd->drv);
}

const char* hlp_dbd_error(hlp_dbd_t *d) {
  return (d == NULL) ? NULL : d->err;
}
#endif

// =============================================================================
// COOKIES
// =============================================================================

#ifdef cookies
void hlp_cookie_set(request_rec *r, const char *k, const char *v, const char *p) {
  const char *c = apr_psprintf(r->pool, "%s=%s; path=%s", k, v, p);
  apr_table_add(r->headers_out, "Set-Cookie", c);
}

const char* hlp_cookie_get(request_rec *r, const char *k, const char *v, const char *p) {
  return (char*)apr_table_get(r->headers_in, "Cookie");
}
#endif



// =============================================================================
// MEMCACHE
// =============================================================================

#ifdef memcache
#include "hlp_memcache.h"

apr_memcache_t* hlp_memcache_init(apr_pool_t *mp, const char *host, int port) {
  apr_status_t rv;
  apr_memcache_t *ret;
  apr_memcache_server_t *serv;
  rv = apr_memcache_create(mp, 10, 0, &ret);
  if (rv == APR_SUCCESS) {
    rv = apr_memcache_server_create(mp, host, port, 0, 1, 1, 60, &serv);
    if (rv == APR_SUCCESS) {
      rv = apr_memcache_add_server(ret, serv);
    }
  }
  return rv == APR_SUCCESS ? ret : NULL;
}

apr_size_t hlp_memcache_get(apr_memcache_t *mc, apr_pool_t *mp, const char *k, char **v) {
  apr_size_t l;
  apr_status_t rv = apr_memcache_getp(mc, mp, k, v, &l, NULL);
  return (rv == APR_SUCCESS)? l : 0;
}

apr_status_t hlp_memcache_set(apr_memcache_t *mc, apr_pool_t *mp, const char *k, char **v) {
  return apr_memcache_set(mc, k, v, strlen(v), hlp_MEMCACHE_TIMEOUT, 0);
}

apr_status_t hlp_memcache_set(apr_memcache_t *mc, const char *k, char *v) {
  return apr_memcache_replace(mc, k, v, strlen(v), 0, 0);
}

// apr_status_t hlp_memcache_delete() {
//   return apr_memcache_delete(mc, k, , 0);
// }

#endif

// =============================================================================
// OBSERVER funzioni chiamate da watchdog
// =============================================================================
#ifdef observer

#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_network_io.h"

#include "httpd.h"
#include "http_protocol.h"
#include "http_log.h"

int hlp_observer_notify(apr_pool_t *p) {
  apr_size_t len;
  apr_socket_t *sock = NULL;
  char buf[256];
  len = apr_snprintf(buf, sizeof(buf), "%s", "hello from notifier");
  do {
    apr_status_t rv;
    rv = apr_socket_create(&sock, APR_INET, SOCK_DGRAM, APR_PROTO_UDP, p);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                   NULL, APLOGNO(02097) "HELLO: apr_socket_create failed");
      break;
    }
    rv = apr_mcast_loopback(sock, 1);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                   NULL, APLOGNO(02098) "HELLO: apr_mcast_loopback failed");
      break;
    }
    apr_sockaddr_t *mcast_addr;
    rv = apr_sockaddr_info_get(&mcast_addr, "192.168.1.8", APR_INET, 3500, 0, p);
    rv = apr_socket_sendto(sock, mcast_addr, 0, buf, &len);
    if (rv) {
      ap_log_error(APLOG_MARK, APLOG_WARNING, rv,
                   NULL, APLOGNO(02099) "HELLO: apr_socket_sendto failed");
      break;
    }
  } while (0);
  if (sock) {
    apr_socket_close(sock);
  }
  return OK;
}

#endif

// =============================================================================
// schema
// =============================================================================

#ifdef schema


#include "apr.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "apr_escape.h"
#include "hlp_dbd.h"
#include "hlp_schema.h"

#define HLP_DBD_SCHEMA_MYSQL 0x01
#define HLP_DBD_SCHEMA_PGSQL 0x02
#define HLP_DBD_SCHEMA_SQLITE3 0x03
#define HLP_DBD_SCHEMA_MSSQL 0x04

typedef apr_array_header_t*(*hlp_schema_tab_fn_t) (apr_pool_t *mp, hlp_dbd_t *dbd, const char *tab);
typedef apr_array_header_t*(*hlp_schema_col_fn_t) (apr_pool_t *mp, hlp_dbd_t *dbd, const char *tab, const char *col);
typedef const char*(*hlp_schema_inf_fn_t) (apr_pool_t *mp, hlp_dbd_t *dbd);

typedef struct hlp_schema_t {
  int err;
  const char *log;
  const char *tab;
  int dbd_server_type;
  apr_array_header_t *att;
  hlp_schema_tab_fn_t tb_name_fn;
  hlp_schema_tab_fn_t cl_attr_fn;
  hlp_schema_tab_fn_t pk_attr_fn;
  hlp_schema_tab_fn_t fk_tabs_fn;
  hlp_schema_tab_fn_t fk_attr_fn;
  hlp_schema_tab_fn_t un_attr_fn;
  hlp_schema_col_fn_t cl_name_fn;
  hlp_schema_col_fn_t id_last_fn;
  hlp_schema_inf_fn_t db_vers_fn;
  apr_array_header_t *pk_attrs;
  apr_array_header_t *unsigned_attrs;
  apr_array_header_t *refs_attrs;
} hlp_schema_t;

apr_array_header_t* hlp_mysql_tb_name(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb) {
  const char *pt =
  "SELECT table_name "
  "FROM INFORMATION_SCHEMA.tables WHERE table_name='%s'";
  const char *sql = apr_psprintf(mp, pt, tb);
  return hlp_dbd_select(mp, dbd, sql);
}

apr_array_header_t* hlp_mysql_cl_name(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb, const char *cl) {
  const char *pt =
  "SELECT column_name FROM INFORMATION_SCHEMA.columns "
  "WHERE table_name='%s' AND column_name='%s'";
  const char *sql = apr_psprintf(mp, pt, tb, cl);
  return hlp_dbd_select(mp, dbd, sql);
}

apr_array_header_t* hlp_mysql_cl_attr(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb) {
  const char *pt =
  "SELECT ordinal_position as ordinal_position,"
  "table_name as table_name,"
  "column_name as column_name,"
  "(case when column_default is null then 'null' else column_default end) as column_default, "
  "data_type as data_type,"
  "(case when character_set_name is null then 'null' else character_set_name end) as character_set_name, "
  "column_type as column_type,"
  "(case when column_key is null then 'null' else column_key end) as column_key,"
  "(case when (column_comment is null or COLUMN_COMMENT like '') then 'null' else COLUMN_COMMENT end) as column_comment,"
  "(column_type LIKE '%%unsigned%%') as is_unsigned,"
  "0 as is_primary_key,"
  "0 as is_foreign_key,"
  "(extra LIKE 'auto_increment') as is_auto_increment,"
  "(is_nullable LIKE 'YES') as is_nullable,"
  "(!isnull(numeric_precision)) as is_numeric,"
  "(isnull(numeric_precision)) as is_string,"
  "(data_type LIKE 'date') as is_date,"
  "(column_type LIKE 'tinyint(1) unsigned') as is_boolean,"
  "'null' as column_options,"
  "'null' as referenced_schema,"
  "'null' as referenced_table,"
  "'null' as referenced_column,"
  "0 as is_referenced_pk_multi,"
  "'null' as referenced_pk "
  "FROM INFORMATION_SCHEMA.columns WHERE table_name='%s' "
  "ORDER BY ordinal_position ASC";
  const char *sql = apr_psprintf(mp, pt, tb);
  apr_array_header_t*ret =  hlp_dbd_select(mp, dbd, sql);
  return ret;
}

apr_array_header_t* hlp_mysql_pk_attr(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb) {
  const char *pt =
  "SELECT c.column_name FROM "
  "INFORMATION_SCHEMA.columns AS c JOIN INFORMATION_SCHEMA.statistics AS s "
  "ON s.column_name=c.column_name AND s.table_schema=c.table_schema AND "
  "s.table_name=c.table_name WHERE !isnull(s.index_name) AND "
  "s.index_name LIKE 'PRIMARY' AND c.table_name='%s'";
  const char *sql = apr_psprintf(mp, pt, tb);
  return hlp_dbd_select(mp, dbd, sql);
}

apr_array_header_t* hlp_mysql_un_attr(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb) {
  return NULL;
}

apr_array_header_t* hlp_mysql_fk_tabs(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb) {
  const char *pt = 
  "SELECT table_name FROM INFORMATION_SCHEMA.key_column_usage "
  "WHERE referenced_table_name='%s'";
  const char *sql = apr_psprintf(mp, pt, tb);
  return hlp_dbd_select(mp, dbd, sql);
}

apr_array_header_t* hlp_mysql_fk_attr(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb) {
  const char *pt =
  "SELECT column_name,referenced_table_schema referenced_schema,"
  "referenced_table_name referenced_table,"
  "referenced_column_name referenced_column "
  "FROM INFORMATION_SCHEMA.key_column_usage "
  "WHERE referenced_column_name IS NOT NULL AND table_name='%s'";
  const char *sql = apr_psprintf(mp, pt, tb);
  return hlp_dbd_select(mp, dbd, sql);
}

apr_array_header_t* hlp_mysql_id_last(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tb, const char *pk) {
  const char *sql = apr_pstrdup(mp, "SELECT last_insert_id() as last_id");
  return hlp_dbd_select(mp, dbd, sql);
}

const char* hlp_mysql_version(apr_pool_t *mp, hlp_dbd_t *dbd) {
  apr_array_header_t *res = hlp_dbd_select(mp, dbd, "SELECT version() version");
  if (res != NULL) {
    apr_table_t *t = APR_ARRAY_IDX(res, 0, apr_table_t*);
    if (t != NULL) return apr_table_get(t, "version");
  }
  return NULL;
}

apr_array_header_t* hlp_sqlite3_tb_name(apr_pool_t *mp, hlp_dbd_t *d, const char *tb) {
  const char *sql = apr_psprintf(mp, "PRAGMA table_info(%s)", tb);
  apr_array_header_t *res = hlp_dbd_select(mp, d, sql);
  if (res == NULL) return NULL;
  apr_table_t *tab = APR_ARRAY_IDX(res, 0, apr_table_t*);
  apr_table_set(tab, "table_name", tb);
  return res;
}

apr_array_header_t* hlp_sqlite3_cl_name(apr_pool_t *mp, hlp_dbd_t *d, const char *tb, const char *cl) {
  const char *sql, *col;
  apr_array_header_t *res;
  apr_table_t *tab;
  sql = apr_psprintf(mp, "PRAGMA table_info(%s)", tb);
  if (sql == NULL) return NULL;
  res = hlp_dbd_select(mp, d, sql);
  if (res == NULL || res->nelts <= 0) return NULL;
  for (int i = 0; i < res->nelts; i++) {
    tab = APR_ARRAY_IDX(res, i, apr_table_t*);
    col = apr_table_get(tab, "name");
    if (col == NULL) continue;
    if (strcmp(col, cl) == 0) return res;
  }
  return NULL;
}

apr_array_header_t* hlp_sqlite3_cl_attr(apr_pool_t *mp, hlp_dbd_t *d, const char *tb) {
  const char *pt =
  "SELECT t.cid+1 ordinal_position,'%s' table_name,t.name column_name,"
  "t.dflt_value column_default,t.type data_type,e.encoding character_set_name,"
  "t.type column_type,null column_key,null column_comment,0 is_unsigned,"
  "t.pk is_primary_key,0 is_foreign_key,"
  "CASE WHEN ((SELECT 1 FROM sqlite_master AS m WHERE "
  "m.'name'='%s' AND lower(sql) LIKE '%%autoincrement%%')=1) AND (t.'pk'=1) "
  "THEN '1' ELSE '0' END is_auto_increment,"
  "CASE WHEN t.'notnull'='0' THEN '0' ELSE '1' END is_nullable,"
  "CASE WHEN lower(t.'type')='integer' OR lower(t.'type')='numeric' OR "
  "lower(t.'type')='real' THEN '1' ELSE '0' END is_numeric,"
  "CASE WHEN lower(t.'type')='text' THEN '1' ELSE '0' END is_string,"
  "0 as is_date,0 as is_boolean,null column_options,null referenced_schema,"
  "null referenced_table,null referenced_column,0 is_referenced_pk_multi,"
  "null referenced_pk FROM "
  "pragma_table_info('%s') AS t,pragma_encoding AS e,"
  "sqlite_master AS m WHERE m.name='%s'";
  const char *sql = apr_psprintf(mp, pt, tb, tb, tb, tb);
  if (sql == NULL) return NULL;
  return hlp_dbd_select(mp, d, sql);
}

apr_array_header_t* hlp_sqlite3_pk_attr(apr_pool_t *mp, hlp_dbd_t *d, const char *tb) {
  const char *sql, *attrib; //, *encoding = NULL;
  apr_array_header_t *res, *retv;
  apr_table_t *tab;
  sql = apr_psprintf(mp, "PRAGMA table_info(%s)", tb);
  if (sql == NULL) return NULL;
  res = hlp_dbd_select(mp, d, sql);
  if (res == NULL || res->nelts <= 0) return NULL;
  retv = apr_array_make(mp, 1, sizeof(apr_table_t*));
  if (retv == NULL) return NULL;
  for (int i = 0; i < res->nelts; i++) {
    tab = APR_ARRAY_IDX(res, i, apr_table_t*);
    if ((attrib = apr_table_get(tab, "pk")) == NULL) continue;
    if (atoi(attrib)) {
      if ((attrib = apr_table_get(tab, "name")) == NULL) continue;
      apr_table_set(tab, "column_name", attrib);
      apr_table_unset(tab, "cid");
      apr_table_unset(tab, "name");
      apr_table_unset(tab, "type");
      apr_table_unset(tab, "notnull");
      apr_table_unset(tab, "dflt_value");
      apr_table_unset(tab, "pk");
      APR_ARRAY_PUSH(retv, apr_table_t*) = tab;
    }
  }
  return retv;
}

apr_array_header_t* hlp_sqlite3_un_attr(apr_pool_t *mp, hlp_dbd_t *d, const char *tb) {
  return NULL;
}

apr_array_header_t* hlp_sqlite3_fk_tabs(apr_pool_t *mp, hlp_dbd_t *d, const char *tb) {
  const char *pt =
  "SELECT m.name table_name FROM sqlite_master m "
  "JOIN pragma_foreign_key_list(m.name) p ON m.name!=p.'table' "
  "AND p.'table'='%s' WHERE m.type='table' ORDER BY m.name";
  const char *sql = apr_psprintf(mp, pt, tb);
  return hlp_dbd_select(mp, d, sql);
}

apr_array_header_t* hlp_sqlite3_fk_attr(apr_pool_t *mp, hlp_dbd_t *d, const char *tb) {
  const char *sql, *attrib;
  apr_array_header_t *res;
  apr_table_t *tab;
  sql = apr_psprintf(mp, "PRAGMA foreign_key_list(%s)", tb);
  res = sql != NULL ? hlp_dbd_select(mp, d, sql) : NULL;
  if (res == NULL || res->nelts <= 0) return NULL;
  for (int i = 0; i < res->nelts; i++) {
    tab = APR_ARRAY_IDX(res, i, apr_table_t*);
    if (tab == NULL || (apr_table_elts(tab))->nelts <= 0) continue;
    if((attrib = apr_table_get(tab, "from")) == NULL) continue;
    apr_table_set(tab, "column_name", attrib);
    apr_table_set(tab, "is_foreign_key", "1");
    apr_table_set(tab, "referenced_schema", "null");
    if ((attrib = apr_table_get(tab, "table")) == NULL) continue;
    apr_table_set(tab, "referenced_table", attrib);
    if ((attrib = apr_table_get(tab, "to")) == NULL) continue;
    apr_table_set(tab, "referenced_column", attrib);
    apr_table_unset(tab, "id");
    apr_table_unset(tab, "seq");
    apr_table_unset(tab, "table");
    apr_table_unset(tab, "from");
    apr_table_unset(tab, "to");
    apr_table_unset(tab, "table");
    apr_table_unset(tab, "on_update");
    apr_table_unset(tab, "on_delete");
    apr_table_unset(tab, "match");
  }
  return res;
}

apr_array_header_t* hlp_sqlite3_id_last(apr_pool_t *mp, hlp_dbd_t *d, const char *tb, const char *pk) {
  const char *sql = apr_pstrdup(mp, "SELECT last_insert_rowid()");
  return hlp_dbd_select(mp, d, sql);
}

const char* hlp_sqlite3_version(apr_pool_t *mp, hlp_dbd_t *d) {
  const char *sql = apr_pstrdup(mp, "SELECT sqlite_version() as version");
  apr_array_header_t *res = hlp_dbd_select(mp, d, sql);
  if (res != NULL && res->nelts > 0) {
    apr_table_t *t = APR_ARRAY_IDX(res, 0, apr_table_t*);
    if (t != NULL) return apr_table_get(t, "version");
  }
  return NULL;
}

apr_array_header_t* hlp_schema_attr_get(hlp_schema_t *schema) {
  return schema->att;
}

const char* hlp_schema_table_get(hlp_schema_t *schema) {
  return schema->tab;
}

apr_array_header_t* hlp_schema_get_col_attrs(apr_pool_t *mp, hlp_dbd_t *dbd, hlp_schema_t *schema, const char *tab) {
  apr_array_header_t*ret =schema->cl_attr_fn(mp, dbd, tab);
  return ret;
}

apr_array_header_t* hlp_schema_get_pk_attrs(apr_pool_t *mp, hlp_dbd_t *dbd, hlp_schema_t *schema, const char *tab)
{
  return schema->pk_attr_fn(mp, dbd, tab);
}

apr_array_header_t* hlp_schema_get_unsig_attrs(apr_pool_t *mp, hlp_dbd_t *dbd, hlp_schema_t *schema, const char *tab)
{
  return schema->dbd_server_type ==  HLP_DBD_SCHEMA_MYSQL
    ? NULL 
    : schema->un_attr_fn(mp, dbd, tab);
}

apr_array_header_t* hlp_schema_get_refs_attrs(apr_pool_t *mp, hlp_dbd_t *dbd,
                                                 hlp_schema_t *schema,
                                                 const char *tab)
{
  return schema->fk_attr_fn(mp, dbd, tab);
}

int hlp_schema_update_attrs(apr_pool_t *mp, hlp_dbd_t *dbd,
                               hlp_schema_t *schema)
{
  const char *c_name, *c_pk_name, *c_uns_name, *c_rf_name;
  for (int i = 0; i < schema->att->nelts; i++) {
    c_name = hlp_dbd_field_value(schema->att, i, "column_name");
    if (c_name == NULL) continue;
    /// Updates primary key attributes
    if (schema->pk_attrs != NULL && schema->pk_attrs->nelts > 0) {
      for (int j = 0; j < schema->pk_attrs->nelts; j ++) {
        c_pk_name = hlp_dbd_field_value(schema->pk_attrs, j, "column_name");
        if (c_pk_name == NULL) continue;
        if (strcmp(c_name, c_pk_name) != 0) continue;
        hlp_dbd_field_set(schema->att, i, "is_primary_key", "1");
      }
    }
    /// Updates unsigned attributes
    if (schema->unsigned_attrs != NULL && schema->unsigned_attrs->nelts > 0) {
      for (int j = 0; j < schema->unsigned_attrs->nelts; j ++) {
        c_uns_name = hlp_dbd_field_value(schema->unsigned_attrs, j, "column_name");
        if (c_uns_name == NULL) continue;
        if (strcmp(c_name, c_uns_name) != 0) continue;
        hlp_dbd_field_set(schema->att, i, "is_unsigned", "1");
      }
    }
    /// Updates foreign key attributes
    if (schema->refs_attrs != NULL && schema->refs_attrs->nelts > 0) {
      for (int j = 0; j < schema->refs_attrs->nelts; j ++) {
        c_rf_name = hlp_dbd_field_value(schema->refs_attrs, j, "column_name");
        if (c_rf_name == NULL) continue;
        if (strcmp(c_name, c_rf_name) != 0) continue;
        hlp_dbd_field_set(schema->att, i, "is_foreign_key", "1");
        hlp_dbd_field_set(schema->att, i, "referenced_schema",
                         hlp_dbd_field_value(schema->refs_attrs,
                         j, "referenced_schema"));
        hlp_dbd_field_set(schema->att, i, "referenced_table",
                         hlp_dbd_field_value(schema->refs_attrs,
                         j, "referenced_table"));
        hlp_dbd_field_set(schema->att, i, "referenced_column",
                         hlp_dbd_field_value(schema->refs_attrs,
                         j, "referenced_column"));
        const char *rt = hlp_dbd_field_value(schema->refs_attrs,
                                            j, "referenced_table");
        apr_array_header_t *rk = hlp_schema_get_pk_attrs(mp, dbd, schema, rt);
        if (rk == NULL || rk->nelts <= 0) continue;
        if (rk->nelts <= 1) {
          hlp_dbd_field_set(schema->att, i, "referenced_pk",
                           hlp_dbd_field_value(rk, 0, "column_name"));
          continue;
        }
        apr_array_header_t *rk_names =
          apr_array_make(mp, rk->nelts, sizeof(const char*));
        for (int k = 0; k < rk->nelts; k ++)
          APR_ARRAY_PUSH(rk_names, const char*) =
            hlp_dbd_field_value(rk, k, "column_name");
        hlp_dbd_field_set(schema->att, i, "referenced_pk",
                         apr_array_pstrcat(mp, rk_names, ','));
        hlp_dbd_field_set(schema->att, i, "is_referenced_pk_multi", "1");
      }
    }
  }
  return 0;
}

//hlp_schema_t* hlp_dbd_schema(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tab) {
apr_array_header_t* hlp_dbd_schema(apr_pool_t *mp, hlp_dbd_t *dbd, const char *tab) {
  const char *dbd_driver_name;
  hlp_schema_t *schema = (hlp_schema_t*)apr_palloc(mp, sizeof(hlp_schema_t));
  if (schema == NULL) {
    return NULL;
  }
  schema->err = 0;
  schema->log = NULL;
  schema->dbd_server_type = 0;
  schema->att = NULL;
  schema->tb_name_fn = NULL;
  schema->cl_name_fn = NULL;
  schema->cl_attr_fn = NULL;
  schema->pk_attr_fn = NULL;
  schema->fk_tabs_fn = NULL;
  schema->fk_attr_fn = NULL;
  schema->un_attr_fn = NULL;
  schema->id_last_fn = NULL;
  schema->db_vers_fn = NULL;
  schema->pk_attrs = NULL;
  schema->unsigned_attrs = NULL;
  schema->refs_attrs = NULL;
  schema->tab = apr_pstrdup(mp, tab);
  dbd_driver_name = hlp_dbd_driver_name(dbd);
  if (dbd_driver_name == NULL) {
    return NULL;
  }
  if (strcmp(dbd_driver_name, "mysql") == 0) {
    schema->tb_name_fn = hlp_mysql_tb_name;
    schema->cl_name_fn = hlp_mysql_cl_name;
    schema->cl_attr_fn = hlp_mysql_cl_attr;
    schema->pk_attr_fn = hlp_mysql_pk_attr;
    schema->un_attr_fn = hlp_mysql_un_attr;
    schema->fk_tabs_fn = hlp_mysql_fk_tabs;
    schema->fk_attr_fn = hlp_mysql_fk_attr;
    schema->id_last_fn = hlp_mysql_id_last;
    schema->db_vers_fn = hlp_mysql_version;
  } else if (strcmp(dbd_driver_name, "sqlite3") == 0) {
    schema->tb_name_fn = hlp_sqlite3_tb_name;
    schema->cl_name_fn = hlp_sqlite3_cl_name;
    schema->cl_attr_fn = hlp_sqlite3_cl_attr;
    schema->pk_attr_fn = hlp_sqlite3_pk_attr;
    schema->un_attr_fn = hlp_sqlite3_un_attr;
    schema->fk_tabs_fn = hlp_sqlite3_fk_tabs;
    schema->fk_attr_fn = hlp_sqlite3_fk_attr;
    schema->id_last_fn = hlp_sqlite3_id_last;
    schema->db_vers_fn = hlp_sqlite3_version;
  } else {
    return NULL;
  }
  // #elif defined(WITH_PGSQL)
  // if (strcmp(dbd_driver_name, "pgsql") == 0) {
  //   schema->tb_name_fn = hlp_pgsql_tb_name;
  //   schema->cl_name_fn = hlp_pgsql_cl_name;
  //   schema->cl_attr_fn = hlp_pgsql_cl_attr;
  //   schema->pk_attr_fn = hlp_pgsql_pk_attr;
  //   schema->un_attr_fn = hlp_pgsql_un_attr;
  //   schema->fk_tabs_fn = hlp_pgsql_fk_tabs;
  //   schema->fk_attr_fn = hlp_pgsql_fk_attr;
  //   schema->id_last_fn = hlp_pgsql_id_last;
  //   schema->db_vers_fn = hlp_pgsql_version;
  // } else {
  //   return NULL;
  // }
  // #else
  // return NULL;
  // #endif
  // Estrae gli attributi di colonna
  // per la tabella di riferimento o restituisce un errore
  schema->att = hlp_schema_get_col_attrs(mp, dbd, schema, tab);
  if (schema->att == NULL) {
    return NULL;
  }
  // Estrae gli attributi delle chiavi primarie
  // per la tabella di riferimento o restituisce un errore
  schema->pk_attrs = hlp_schema_get_pk_attrs(mp, dbd, schema, tab);
  if (schema->err) {
    return NULL;
  }
  // Estrae gli attributi delle colonne unsigned
  // per la tabella di riferimento o restituisce un errore
  schema->unsigned_attrs = hlp_schema_get_unsig_attrs(mp, dbd, schema, tab);
  if (schema->err) {
    return NULL;
  }
  // Estrae gli attributi delle chiavi esterne
  // per la tabella di riferimento o restituisce un errore
  schema->refs_attrs = hlp_schema_get_refs_attrs(mp, dbd, schema, tab);
  if (schema->err) {
    return NULL;
  }
  // Sovrascrive gli attributi di colonna
  // con i valori di chiave primaria, unsigned e chiave esterna
  hlp_schema_update_attrs(mp, dbd, schema);
  return schema->att;
}

#endif

// =============================================================================
// session
// =============================================================================
#ifdef session

#include "hlp_session.h"

hlp_session_t* hlp_session_start(request_rec *r) {
  apr_status_t rv;
  hlp_session_t *s = NULL;
  hlp_session_load_t session_load;
  session_load = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
  if (session_load != NULL) {
    s = (hlp_session_t*)apr_palloc(r->pool, sizeof(hlp_session_t));
    if (s != NULL) {
      s->is_active = 0;
      s->save = APR_RETRIEVE_OPTIONAL_FN(ap_session_save);
      s->get = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
      s->set = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);
      if (s->save != NULL && s->get != NULL && s->set != NULL) {
        rv = session_load(r, &(s->ssn));
        if (rv == APR_SUCCESS) {
          s->is_active = 1;
        }
      }
    }
  }
  return s;
}

int hlp_session_destroy(request_rec* r, hlp_session_t* s) {
  apr_status_t rv = !APR_SUCCESS;
  if ((s != NULL) && s->is_active) {
    s->is_active = 0;
    s->ssn->maxage = 1; /* Set max age to 1 second */
    rv = s->save(r, s->ssn);
  }
  return (rv == APR_SUCCESS);
}

int hlp_session_set(request_rec *r, hlp_session_t *s, const char *k, const char *v) {
  apr_status_t rv = !APR_SUCCESS;
  if ((s != NULL) && s->is_active) {
    rv = s->set(r, s->ssn, k, v);
  }
  return (rv == APR_SUCCESS);
}
int hlp_session_get(request_rec *r, hlp_session_t *s, const char *k, const char **v) {
  apr_status_t rv = !APR_SUCCESS;
  if ((s != NULL) && s->is_active) {
    rv = s->get(r, s->ssn, k, v);
  }
  return rv == APR_SUCCESS;
};

int hlp_session_save(request_rec *r, hlp_session_t *s, int force) {
  apr_status_t rv = !APR_SUCCESS;
  if (s->is_active) {
    if (force == 1) s->ssn->dirty = 1;
    rv = s->save(r, s->ssn);
  }
  return (rv == APR_SUCCESS);
}

apr_table_t* hlp_session_entries(hlp_session_t *s) {
  return (s != NULL) && (s->ssn != NULL) && !apr_is_empty_table(s->ssn->entries)
    ? s->ssn->entries : NULL;
}

int hlp_session_num_entries(hlp_session_t *s) {
  apr_table_t *entries = hlp_session_entries(s);
  return entries != NULL ? apr_table_elts(entries)->nelts : 0;
}


#endif

// =============================================================================
// ssl
// =============================================================================
#ifdef ssl

#include "openssl/engine.h"
#include "openssl/hmac.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "hlp_ssl.h"

const unsigned char* hlp_ssl_rsa_encrypt(apr_pool_t *mem, const unsigned char *msg, apr_size_t *sz, const char* k_path, char **err) {
  RSA *pub_k = NULL;
  FILE* k_file = fopen(k_path, "r");
  //unsigned char *ret = NULL;
  const unsigned char *enc, *ret=NULL;
  if (k_file == NULL) {
    *err = apr_pstrdup(mem, "Error opening public key file");
    return NULL;
  }
  pub_k = PEM_read_RSA_PUBKEY(k_file, NULL, NULL, NULL);
  fclose(k_file);
  if (!pub_k) {
      char er_buf[256];
      ERR_error_string(ERR_get_error(), er_buf);
      *err = apr_psprintf(mem, "Error reading public key: %s", er_buf);
      return NULL;
  }
  if (pub_k == NULL) {
    *err = apr_pstrdup(mem, "Error reading public key");
    return NULL;
  }
  //int max_data_size = RSA_size(pub_k) - 42; // RSA_PKCS1_OAEP_PADDING

  enc = (const unsigned char*)calloc(RSA_size(pub_k), sizeof(const unsigned char));
  
  *sz = RSA_public_encrypt(strlen((const char*)msg), msg, (unsigned char*)enc, pub_k, RSA_PKCS1_OAEP_PADDING);

  if (*sz == -1) {
    *err = apr_pstrdup(mem, "Error encrypting data");
    RSA_free(pub_k);
    free((void*)ret);
    return NULL;
  }

  ret = (const unsigned char*)apr_pcalloc(mem, *sz);
  if (ret != NULL) {
    memcpy((void*)ret, enc, *sz);
  }
  RSA_free(pub_k);
  return (const unsigned char*)ret;
}

const char* hlp_ssl_rsa_decrypt(apr_pool_t *mem, const char* encrypted_msg, const char* private_key_path) {
  RSA *private_key = NULL;
  FILE* private_key_file = fopen(private_key_path, "r");
  if (private_key_file == NULL) {
    fprintf(stderr, "Error opening private key file.\n");
    return NULL;
  }
  private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
  fclose(private_key_file);
  if (private_key == NULL) {
    fprintf(stderr, "Error reading private key.\n");
    return NULL;
  }
  unsigned char* decrypted_data = (unsigned char*)calloc(RSA_size(private_key), sizeof(unsigned char));
  int decrypted_data_length = RSA_private_decrypt(RSA_size(private_key), (unsigned char*)encrypted_msg, decrypted_data, private_key, RSA_PKCS1_OAEP_PADDING);
  if (decrypted_data_length == -1) {
    fprintf(stderr, "Error decrypting data.\n");
    RSA_free(private_key);
    free(decrypted_data);
    return NULL;
  }
  RSA_free(private_key);
  return (const char*)decrypted_data;
}

const char* hlp_ssl_hash(apr_pool_t *mem, const char *a, const char *s) {
  char *ret = NULL;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  if ((mem != NULL) && (a != NULL) && (s != NULL)) {
    const EVP_MD *md = EVP_get_digestbyname(a);
    if (md != NULL) {
      EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(mdctx, md, NULL);
      EVP_DigestUpdate(mdctx, s, strlen(s));
      EVP_DigestFinal_ex(mdctx, md_value, &md_len);
      EVP_MD_CTX_free(mdctx);
      ret = (char*)apr_palloc(mem, md_len * 2 + 1);
      if (ret != NULL) {
        for (unsigned int i = 0; i < md_len; i++) {
          sprintf(&ret[i * 2], "%02x", md_value[i]);
        }
        ret[md_len * 2] = '\0';
      }
    }
  }
  return (const char*)(ret == NULL ? hlp_empty_string(mem) : ret);
}

const char* hlp_ssl_hmac_digest(apr_pool_t *mem, const unsigned char *k, unsigned int k_len, unsigned char *s, unsigned int s_len) {
  apr_array_header_t *ar;
  unsigned int len;
  unsigned char hash[EVP_MAX_MD_SIZE], *res;
  const char *ret = NULL;
  if ((mem != NULL) && (k != NULL) && (s != NULL) && (k_len > 0) && (s_len > 0)) {
    if((res = HMAC(EVP_sha256(), k, k_len, s, s_len, hash, &len)) != NULL) {
      ar = apr_array_make(mem, EVP_MAX_MD_SIZE, sizeof(const char*));
      if (ar != NULL) {
        for (int i = 0; i < len; i++) {
          APR_ARRAY_PUSH(ar, const char*) = apr_psprintf(mem, "%02x", res[i]);
        }
        ret = hlp_join(mem, ar, NULL);
      }
    }
  }
  return ret;
}

// mem = pool, ps = password, mh = method, u = uri, d = date, n = nonce
const char* hlp_ssl_hmac(apr_pool_t *mem, const unsigned char *ps, const char *user,const char *n, const char *mh, const char *u, const char *d) {
  unsigned char *s;
  const char *hmac, *ret = NULL;
  if ((mem != NULL) && (user != NULL) && (ps != NULL) && (mh != NULL) &&
      (u != NULL) && (d != NULL) && (n != NULL)) {
    // s = stringa da codificare
    s = (unsigned char*)apr_psprintf(mem, "%s+%s+%s+%s+%s", user, n, mh, u, d);
    if (s != NULL) {
      // ps = password
      if ((hmac = hlp_ssl_hmac_digest(mem, ps, strlen((const char*)ps), s, strlen((const char*)s))) != NULL) {
        ret = hlp_base64_encode(mem, hmac);
      }
    }
  }
  return ret;
}


#endif

// =============================================================================
// tcl
// =============================================================================
#ifdef tcl

#include "tcl.h"
#include "hlp_tcl.h"

int hlp_tcl_hello(ClientData clientData, Tcl_Interp *interp, int argc, const char *argv[]) {
  // Calcola il risultato o il valore che desideri restituire
  const char resultValue[] = "Hello";  // Ad esempio, restituiamo il valore 42
  // Converti il risultato in una stringa Tcl (in questo caso, un intero)
  Tcl_Obj *resultObj = Tcl_NewStringObj(resultValue, strlen(resultValue));
  // Imposta il risultato per la chiamata Tcl corrente
  Tcl_SetObjResult(interp, resultObj);
  // Restituisci TCL_OK per indicare il successo
  return TCL_OK;
}

const char* hlp_tcl_parse_script(apr_pool_t *mp, hlp_http_request_t *r, const char *s) {
  const char *out = NULL;
  if (mp != NULL && r != NULL && s != NULL) {
    Tcl_Interp *interp;
    // Inizializza l'interprete Tcl
    interp = Tcl_CreateInterp();
    //const char message[] = "Questo è un messaggio.";
    Tcl_SetVar(interp, "http_method", r->method, TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "http_uri", r->uri, TCL_GLOBAL_ONLY);
    Tcl_SetVar(interp, "http_query", r->query != NULL ? r->query : "NULL", TCL_GLOBAL_ONLY);
    Tcl_CreateCommand(interp, "hlp_tcl_hello", hlp_tcl_hello, NULL, NULL);
    // Esegui lo script Tcl passato come argomento
    if (Tcl_Eval(interp, s) != TCL_OK) {
      fprintf(stderr, "Errore durante l'esecuzione dello script Tcl: %s\n", Tcl_GetStringResult(interp));
      return NULL;
    }
    // Ottieni il risultato dallo script Tcl
    const char *interp_out = Tcl_GetStringResult(interp);
    if (interp_out != NULL) {
      out = apr_pstrdup(mp, interp_out);
    }
    // Rilascia le risorse
    Tcl_DeleteInterp(interp);
  }
  return out;
}

#endif

// =============================================================================
// signals
// =============================================================================
#ifdef signals

#include "hlp_signals.h"

void hlp_sighd(struct sigaction *sa, hlp_sighd_t sighd_fn) {
  sa->sa_handler = sighd_fn;
  sigemptyset(&sa->sa_mask);
  sa->sa_flags = 0;
  sigaction(SIGTERM, sa, NULL);
  sigaction(SIGINT, sa, NULL);
}

#endif

// =============================================================================
// auth
// =============================================================================
#ifdef auth

#include "hlp_auth.h"

// Verifica un authorization token
// Confronta authz_s con ogni  riga del file di autorizzazione restituisce 1 in caso di
// corrispondenza, altrimenti 0
// mp Memory pool, authz_s Token, authz_file Session file
// return (int) 1 success, 0 failure
int hlp_http_authorize(apr_pool_t *mp, const char *authz_s, const char *authz_file) {
  if (authz_file == NULL || authz_s == NULL) return 0;
  apr_array_header_t *authz_ar = wm_split(mp, authz_s, ":");
  if (authz_ar == NULL || authz_ar->nelts < 2) return 0;
  const char *authz_time_s = APR_ARRAY_IDX(authz_ar, 0, const char*);
  if (authz_time_s == NULL) return 0;
  apr_time_t authz_time = atol(authz_time_s);
  // Ottengo il time corrente
  apr_time_t curr_time = hlp_timestamp(mp, NULL, NULL);
  // Se authz_time < curr_time il token non è valido 
  if ((authz_time - curr_time) <= 0) return 0;
  int ret = 0;
  apr_file_t *file;
  // Apro il file per cercare il token
  apr_status_t rv = apr_file_open(&file, authz_file, APR_READ, APR_OS_DEFAULT, mp);
  if (rv != APR_SUCCESS) return 0;
  char buff[1024];
  apr_size_t buff_size = sizeof(buff);
  // Ripet per ogni riga
  while (apr_file_gets(buff, buff_size, file) == APR_SUCCESS) {
    // se la riga corrente è = a authz_s il token è valido
    if (strcmp(hlp_trim(mp, buff), authz_s) == 0) {
      ret = 1;
      break;
    }
  }
  return ret;
}

const char* tmp_authz(apr_pool_t*mp) {
  const char *ret = NULL;
  apr_time_t curr_ts = hlp_timestamp(mp, NULL, NULL);
  if (curr_ts > 0) {
    // Aggiunto al time corrente 60 secondi
    curr_ts = curr_ts + (1000000 * 60 * 1 * 1);
    // Genero la stringa autorizzativa con
    // il time incrementato e il l'MD5 del time corrente
    const char *curr_ts_s = apr_psprintf(mp, "%" APR_INT64_T_FMT, curr_ts);
    const char *curr_ts_md5 = hlp_md5(mp, curr_ts_s);
    ret = apr_psprintf(mp, "%s:%s", curr_ts_s, curr_ts_md5);
  }
  return ret;
}

int hlp_http_authenticate_credentials(apr_pool_t *mp, char **authz_s,
                                     const char*f, const char *u, const char *p) {
  int ret = 0;
  // Genero l'MD5 dello user
  const char *md5_user = hlp_md5(mp, u);
  if (hlp_file_exists(mp, f)) {
    apr_file_t *file;
    apr_status_t rv = apr_file_open(&file, f, APR_READ, APR_OS_DEFAULT, mp);
    if (rv == APR_SUCCESS) {
      char buffer[1024];
      apr_size_t buffer_size = sizeof(buffer);
      while (apr_file_gets(buffer, buffer_size, file) == APR_SUCCESS) {
        // La riga corrente contiene lo user come sottostringa
        if (strncasecmp(buffer, md5_user, 32) == 0) {
          apr_array_header_t *user_ar = hlp_split(mp, buffer, ":");
          if (user_ar != NULL && user_ar->nelts >= 2) {
            // Estraggo la password codificata
            const char *enc_p = APR_ARRAY_IDX(user_ar, 1, const  char*);
            // Codifico SHA256 la password ricevuta
            const  char* rcv_p = (const  char*)hlp_ssl_hash(mp, "SHA256", p);
            // La password registrata e quella ricevuta coincidono
            if (enc_p != NULL && rcv_p != NULL && (strcmp(enc_p, rcv_p) == 0)) {
              // Genero il digest
              const char *digest = apr_psprintf(mp, "%s:%s", u, enc_p);
              const char *sha256_digest = hlp_ssl_hash(mp, "SHA256", digest);
              // Genero il time corrente
              apr_time_t curr_ts = hlp_timestamp(mp, NULL, NULL);
              if (curr_ts > 0) {
                // Aggiunto al time corrente 60 secondi
                curr_ts = curr_ts + (1000000 * 60 * 1 * 1);
                // Genero la stringa autorizzativa con
                // il time incrementato e il digest HMAC generato
                // nella variabile authz_s ricevuta come argomento
                *authz_s = apr_psprintf(mp, "%" APR_INT64_T_FMT ":%s", curr_ts, sha256_digest);
                // Restituisco 1 (true) come risultato dell'autenticazione
                ret = 1;
                break;
              }

            }
          }
        }
      }
    }
  }
  return ret;
}



// Verifica un authentication token
// mp Memory pool, u URI, m HTTP method, authn_s Token, dt Date
// return (int) 1 success, 0 failure, on success authz_s contains a new token
int hlp_http_authenticate_token(apr_pool_t *mp, char **authz_s, const char *uri, const char *meth, const char *authn_s, const char *date, const char *authn_file) {
  int ret = 0;
  *authz_s = NULL;
  const char *user = NULL, *nonce = NULL, *recv_digest = NULL;
  if (uri == NULL || meth == NULL || authn_s == NULL || authn_file == NULL) return 0;
  apr_array_header_t *authn_ar = hlp_split(mp, authn_s, " ");
  if (authn_ar != NULL && authn_ar->nelts >= 2) {
    if (strcmp(APR_ARRAY_IDX(authn_ar, 0, const char*), "hmac") == 0) {
      const char *hmac_data = APR_ARRAY_IDX(authn_ar, 1, const char*);
      apr_array_header_t* hmac_data_ar = hlp_split(mp, hmac_data, ":");
      if (hmac_data_ar != NULL && hmac_data_ar->nelts >= 3) {
        // Estraggo lo user
        user = APR_ARRAY_IDX(hmac_data_ar, 0, const char*);
        // Estraggo il nonce
        nonce = APR_ARRAY_IDX(hmac_data_ar, 1, const char*);
        // Estraggo il digest hmac
        recv_digest = APR_ARRAY_IDX(hmac_data_ar, 2, const char*);
      }
    }
  }

  // se i dati sono tutti presenti li uso per estrarre la password
  // dal file delle credenziali e generare un nuovo hmac

  if (user != NULL && nonce != NULL && recv_digest != NULL) {
    // Genero l'MD5 dello user
    const char *md5_user = hlp_md5(mp, user);
    if (hlp_file_exists(mp, authn_file)) {
      apr_file_t *file;
      apr_status_t status = apr_file_open(&file, authn_file, APR_READ, APR_OS_DEFAULT, mp);
      if (status == APR_SUCCESS) {
        char buffer[1024];
        apr_size_t buffer_size = sizeof(buffer);
        while (apr_file_gets(buffer, buffer_size, file) == APR_SUCCESS) {
          // La riga corrente contiene lo user come sottostringa
          if (strncasecmp(buffer, md5_user, 32) == 0) {
            apr_array_header_t *user_ar = hlp_split(mp, buffer, ":");
            if (user_ar != NULL && user_ar->nelts >= 2) {
              // Estraggo la password codificata
              const unsigned char *enc_pass = APR_ARRAY_IDX(user_ar, 1, const unsigned char*);
              if (enc_pass != NULL) {
                // Genero il digest HMAC
                const char *gen_digest = hlp_ssl_hmac(mp, enc_pass, user, nonce, meth, uri, date);
                // Se il digest generato è = a quello ricevuto
                if (strcmp(gen_digest, recv_digest) == 0) {
                  // Genero il time corrente
                  apr_time_t curr_ts = hlp_timestamp(mp, NULL, NULL);
                  if (curr_ts > 0) {
                    // Aggiunto al time corrente 60 secondi
                    curr_ts = curr_ts + (1000000 * 60 * 1 * 1);
                    // Genero la stringa autorizzativa con
                    // il time incrementato e il digest HMAC generato
                    // nella variabile authz_s ricevuta come argomento
                    *authz_s = apr_psprintf(mp, "%" APR_INT64_T_FMT ":%s", curr_ts, gen_digest);
                    // Restituisco 1 (true) come risultato dell'autenticazione
                    ret = 1;
                    break;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return ret;
}

#endif

// =============================================================================
// ecs
// =============================================================================
#ifdef ecs

#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_errno.h"

#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_dbd.h"
#include "stdio.h"
#include "stdlib.h"

#include "hlp_commons.h"
#include "hlp_dbd.h"

#define DBD_CONN_S "host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"


// Un Context è una collezione di entities
// Non ha un nome proprio, ma corrisponde al database e al modulo
typedef struct Context {
  apr_pool_t *pool;
  apr_array_header_t *entities;
  int modified;
} Context;

// Una entity corrisponde a una tabella del database
// Contiene un riferimento al context per tenere traccia dello stato di modifica
// Il name corrisponde al nome della tabella
// L'id si riferisce a un record di tabella ed è NULL se la entity non ha ancora uno storage
// Contiene un flag che traccia lo stato di modifica
// Contiene un elenco di components il cui storage è in una tabella correlata
// mediante una chiave esterna
typedef struct Entity {
  apr_pool_t *pool;
  Context *context;
  const char *id, *name;
  apr_array_header_t *components;
  int modified;
} Entity;

// Rappresenta i dati di una entity
// Il name corrisponde al nome della tabella
// L'id si riferisce al record ed è NULL solo se il componente non ha ancora uno storage
// Ogni record della tabella è formato da id e attributes
// ha un flag modified per tracciare lo stato di modifica
typedef struct Component {
  apr_pool_t *pool;
  Entity *entity;
  const char *id, *name;
  apr_table_t *attributes;
  int modified;
} Component;

Context* context_create(apr_pool_t *mp) {
  Context *ret = NULL;
  int rv = 0, input_v;
  const char er[] = "context_create() system error: %s.\n";
  input_v = mp != NULL;
  do {
    if (!input_v) break;
    ret = (Context*)apr_palloc(mp, sizeof(Context));
    if (!ret) break;
    ret->pool = mp;
    ret->entities = apr_array_make(mp, 0, sizeof(Entity*));
    if (!ret->entities) break;
    rv = 1;
  } while(0);
  if (!rv) {
    if (!input_v) {
      printf(er, "Context input validation failed");
    } else if (!ret->entities) {
      printf(er, "Context entities allocation failed");
    } else {
      printf(er, "Context creation failed");
    }
    ret = NULL;
  }
  return ret;
}

Entity *entity_create(Context *ctx, const char *name) {
  Entity *ret = NULL;
  int rv = 0, input_v;
  const char er[] = "entity_create() error: %s.\n";
  input_v = ctx && name;
  do {
    if (!input_v) break;
    ret = (Entity*)apr_palloc(ctx->pool, sizeof(Entity));
    if (!ret) break;
    ret->pool = ctx->pool;
    ret->modified = 0;
    ret->context = ctx;
    ret->id = NULL;
    ret->name = apr_pstrdup(ctx->pool, name);
    if (!ret->name) break;
    ret->components = apr_array_make(ctx->pool, 1, sizeof(Component*));
    if (!ret->components) break;
    APR_ARRAY_PUSH(ctx->entities, Entity*) = ret;
    rv = 1;
  } while (0);
  if (!rv) {
    ret = NULL;
    if (!input_v) {
      printf(er, "Input validation failed");
    } else {
      printf(er, "Entity creation failed");
    }
  }
  return ret;
}

Component *component_create(Entity *e, const char *name) {
  Component *ret = NULL;
  int rv = 0, input_v;
  const char er[] = "component_create() error: %s.\n";
  input_v = e && name;
  do {
    if (!input_v) break;
    ret = (Component*)apr_palloc(e->pool, sizeof(Component));
    if (!ret) break;
    ret->pool = e->pool;
    ret->modified = 0;
    ret->entity = e;
    ret->id = NULL;//apr_pstrdup(e->pool, "123");
    ret->name = apr_pstrdup(e->pool, name);
    if (!ret->name) break;
    ret->attributes = apr_table_make(e->pool, 0);
    rv = ret->attributes != NULL;
  } while (0);
  if (!rv) {
    ret = NULL;
    if (!input_v) {
      printf(er, "Input validation failed");
    } else {
      printf(er, "Component creation failed");
    }
  }
  return ret;
}

void attribute_set(Component *c, const char *k, void *v) {
  if (c && k && v && c->attributes) {
    apr_table_set(c->attributes, k, v);
    c->entity->context->modified = 1;
    c->entity->modified = 1;
    c->modified = 1;
  }
}

const char* attribute_get(Component *c, const char *k) {
  const char *ret = NULL;
  if (c && c->attributes) {
    ret = apr_table_get(c->attributes, k);
  }
  return ret;
}

apr_status_t component_store(Component *c, hlp_dbd_t *dbd) {

  struct state_t {
    int valid_input, valid_sql, result, n_attrs, sql_err;
    const char *sql;
  } st = {0, 0, 0, 0, 0, NULL};
  
  st.valid_input = c && dbd;

  do {
    if (!st.valid_input)
      break;
    // Gli attributi del componente non sono settati
    if (!c->attributes)
      break;
    // Estraggo l'array degli attributi
    const apr_array_header_t *elts = apr_table_elts(c->attributes);
    if (elts) {
      // Estraggo il numero delgi attributi
      st.n_attrs = apr_table_elts(c->attributes)->nelts;
    }
    // Il numero degli attributi non è valido
    if (st.n_attrs <= 0)
      break;
    const char *keys = NULL;
    // Estraggo il primo attributo
    const char *pholds = NULL;
    apr_table_entry_t *e = hlp_table_entry(c->attributes, 0);
    if (e) {
      if (c->id) {
        // Aggiungo il primo attributo ai placeholders della query update
        pholds = apr_psprintf(c->pool, "%s=%%s", e->key);
      } else {
        // Aggiungo il nome del primo attributo ai campi della query insert
        keys = apr_pstrdup(c->pool, e->key);
        // Aggiungo il primo attributo ai placeholders della query insert
        pholds = apr_pstrdup(c->pool, "%s");
      }
    }
    // Il primo placeholder non è stato allocato
    if (!pholds)
      break;
    // Il numero degli attributi è > 1
    if (st.n_attrs > 1) {
      const char *pair;
      for (int i = 1; i < st.n_attrs; i ++) {
        // Leggo il prossimo attributo
        e = hlp_table_entry(c->attributes, i);
        if (!e)
          continue;
        pair = NULL;
        if (c->id) {
          // Genero il pair per la query update
          pair = apr_psprintf(c->pool, "%s=%%s", e->key);
        } else {
          // Genero field name per la query insert
          keys = apr_pstrcat(c->pool, keys, ", ", e->key, NULL);
        }
        if (pair) {
          // Aggiungo il pair ai placeholders della query update
          pholds = apr_pstrcat(c->pool, pholds, ", ", pair, NULL);
        } else {
          // Aggiungo un placeholder alla query insert
          pholds = apr_pstrcat(c->pool, pholds, ", ", "%s", NULL);
        }
      }
    }
    // Una delle sovrascritture della stringa pholds è fallita
    st.valid_sql = pholds != NULL;
    if (!st.valid_sql)
      break;
    if (keys) {
      // Alloco la query sql insert
      const char sql_pattern[] = "INSERT INTO %s (entity_id, %s) VALUES (%s, %s)";
      st.sql = apr_psprintf(c->pool, sql_pattern, c->name, keys, c->entity->id, pholds);
    } else {
      // Alloco la query sql update
      const char sql_pattern[] = "UPDATE %s SET %s WHERE id=%s";
      st.sql = apr_psprintf(c->pool, sql_pattern, c->name, pholds, c->id);
    }
    // L'allocazione della query è fallita
    st.valid_sql = st.sql != NULL;
    if (!st.valid_sql)
      break;
    // Eseguo la query SQL come prepared statement
    int aff_rows = hlp_dbd_prepared_query(c->pool, dbd, st.sql, c->attributes);
    st.sql_err = aff_rows <= 0; 
    if (st.sql_err)
      break;
    st.result = 1;
  } while (0);

  if (!st.result) {
    const char er_msg[] = "component_store() error: %s.\n";
    if (!st.valid_input) {
      printf(er_msg, "Invalid input values");
    } else if (!c->attributes) {
      printf(er_msg, "Invalid component attributes value");
    } else if (st.n_attrs <= 0) {
      printf(er_msg, "Invalid component attributes number");
    } else if (!st.valid_sql) {
      printf(er_msg, "SQL query allocation failed");
    } else if (st.sql_err) {
      const char *msg = NULL;
      if (dbd->err) {
        msg = apr_psprintf(c->pool, "%s. %s", dbd->err, st.sql);
      } else {
        msg = apr_psprintf(c->pool, "DBD query error: %s", st.sql);
      }
      printf(er_msg, msg ? msg : "DBD general error");
    }
  }

  return st.result ? APR_SUCCESS : APR_EGENERAL;
}

apr_status_t entity_store(Entity *e, hlp_dbd_t *dbd) {

  struct state_t {
    int valid_input;
    int valid_name;
    int valid_comps;
    int valid_storage;
    int sql_err;
    int valid_id;
    int result;
    const char *sql;
  } st = {0, 0, 0, 0, 0, 0, 0, NULL};

  st.valid_input = e && dbd;

  do {
    // Verifico la validità dell'input
    if (!st.valid_input)
      break;
    // Verifico la validità del nome
    st.valid_name = e->name && !hlp_is_empty(e->name);
    if (!st.valid_name)
      break;
    // La entity è registrata e nessun componente è stato modificato
    if (e->id && !e->modified) {
      st.result = 1;
      break;
    }
    // Verifico la validità dei componenti
    st.valid_comps = !e->components || e->components->nelts <= 0;
    if (!st.valid_comps)
      break;
    // Seleziono la query da eseguire in base al valore di e->id
    if (!e->id) {
      const char sql_pattern[] = "INSERT INTO %s VALUES (DEFAULT)";
      st.sql = apr_psprintf(e->pool, sql_pattern, e->name);
    } else {
      const char sql_pattern[] = "UPDATE %s SET updated_at=now() WHERE id=%s";
      st.sql = apr_psprintf(e->pool, sql_pattern, e->name, e->id);
    }
    // Errore di allocazione dlela query SQL
    if (!st.sql)
      break;
    // Eseguo la query di inserimento/aggiornamento
    int aff_rows = hlp_dbd_query(e->pool, dbd, st.sql);
    st.sql_err = aff_rows <= 0;
    // La query di inserimento/aggiornamento è fallita
    if (st.sql_err)
      break;
    // Estraggo il nuovo ID inserito
    if (!e->id) {
      const char sql_pattern[] = "SELECT LAST_INSERT_ID() AS id";
      apr_array_header_t *rset = hlp_dbd_select(e->pool, dbd, sql_pattern);
      st.sql_err = rset != NULL;
      if (st.sql_err)
        break;
      e->id = hlp_dbd_field_value(rset, 0, "id");
    }
    // Questa condizione è improbabile
    // Il controllo è introdotto per miglirare la robustezza del codice
    st.valid_id = e->id != NULL;
    if (!st.valid_id)
      break;
    // Lo stato di modifica dell'entità riflette quello dei suoi componenti
    // In assenza di modifiche termino con successo
    if (!e->modified) {
      st.result = 1;
      break;
    }
    int i;
    // Eseguo l'inserimento/aggiornamento dei componenti
    for (i = 0; i < e->components->nelts; i++) {
      // Estraggo il prossimo componente
      Component *c = APR_ARRAY_IDX(e->components, i, Component*);
      if (c) {
        // Registro il componente
        int res = component_store(c, dbd);
        if (res != APR_SUCCESS)
          break;
      }
    }
    // La registrazione di qualche componente è fallita
    st.valid_storage = i >= e->components->nelts;
    if (!st.valid_storage)
      break;
    // Setto la condizione di successo
    st.result = 1;
  } while (0);

  if (!st.result) {
    const char er_msg[] = "entity_store() error: %s.\n\n";
    if (!st.valid_input) {
      printf(er_msg, "Input validation failed");
    } else if (!st.valid_name) {
      printf(er_msg, "Entity name is NULL or empty");
    } else if (!st.valid_comps) {
      printf(er_msg, "Entity components array is NULL or empty");
    } else if (st.sql_err) {
      const char *msg = NULL;
      if (dbd->err) {
        msg = apr_psprintf(e->pool, "%s. %s", dbd->err, st.sql);
      } else {
        msg = apr_psprintf(e->pool, "DBD query error: %s", st.sql);
      }
      printf(er_msg, msg ? msg : "DBD general error");    
    } else if (!st.valid_id) {
      printf(er_msg, "Invalid entity ID");
    } else if (!st.valid_storage) {
      printf(er_msg, "Some components have not been stored");
    }
  }

  return st.result ? APR_SUCCESS : APR_EGENERAL;
}


apr_status_t entity_storage_create(Entity *e, hlp_dbd_t *dbd) {

  struct status_t {
    int valid_input, valid_name, sql_err, result;
  } st = {0, 0};

  st.valid_input = e && dbd;

  do {
    if (!st.valid_input)
      break;

    const char sql_pattern[] = "create table if not esists %s ("
      "id bigint not null primary key auto_increment,"
      "created_at datetime not null default current_timestamp,"
      "updated_at datetime not null default current_timestamp,"
      "deleted_at datetime default null"
      ") engine innodb";

    const char *sql = apr_psprintf(e->pool, sql_pattern, e->name);

    int aff_row = hlp_dbd_query(e->pool, dbd, sql);
    st.sql_err = aff_row <= 0;
    if (st.sql_err)
      break;


  } while (0);

  if (!st.result) {
    const char er_msg[] = "component_store() error: %s.\n";
    if (!st.valid_input) {
      printf(er_msg, "Invalid input values");
    } else if (!st.valid_name) {
      printf(er_msg, "Invalid input values");
    } else if (st.sql_err) {
      printf(er_msg, "Invalid input values");
    }
  }


  return st.result ? APR_SUCCESS : APR_EGENERAL;
}



apr_status_t context_store(Context *ctx, hlp_dbd_t *dbd) {

  struct state_t {
    int valid_input, valid_storage, result;
  } st = {0, 0};

  st.valid_input = ctx != NULL;

  do {
    if (!st.valid_input)
      break;
    if (!ctx->entities)
      break;
    int i;
    for (i = 0; i < ctx->entities->nelts; i ++) {
      Entity *e = APR_ARRAY_IDX(ctx->entities, i, Entity*);
      if (e) {
        apr_status_t rv = entity_store(e, dbd);
        if (rv != APR_SUCCESS)
          break;
      }
    }
    st.valid_storage = i >= ctx->entities->nelts;
    if (!st.valid_storage)
      break;
    st.result = 1;
  } while (0);

  if (!st.result) {
    const char er_msg[] = "component_store() error: %s.\n";
    if (!st.valid_input) {
      printf(er_msg, "Invalid input values");
    } else if (!ctx->entities) {
      printf(er_msg, "Invalid input values");
    } else if (!st.valid_storage) {
      printf(er_msg, "Invalid input values");
    }
  }

  return st.result ? APR_SUCCESS : APR_EGENERAL;
}

/**
 * main()
*/
int main(int argc, char **argv) {

  int rv = 0;
  int id = 0, input_v = 1, apr_v = 0, mp_v = 0, apr_dbd_v = 0,
      db_open_v = 0, db_reset_v = 0;
  apr_pool_t *mp = NULL;
  const char conn_s[] = DBD_CONN_S;
  hlp_dbd_t *dbd = NULL;
  const char er[] = "Error in main: %s.\n";

  if (input_v) {
    apr_v = apr_initialize() == APR_SUCCESS;
  }
  
  if (apr_v) {
    mp_v = apr_pool_create(&mp, NULL) == APR_SUCCESS;
  }
  
  if (mp_v) {
    apr_dbd_v = apr_dbd_init(mp) == APR_SUCCESS;
  }
  
  if(apr_dbd_v) {
    dbd = hlp_dbd_init(mp);
  }
  
  if (dbd) {
    db_open_v = hlp_dbd_open(mp, dbd, "mysql", conn_s);
  }
  
  Context *shop = NULL;
  Entity *customer = NULL;
  Component *credentials = NULL, *registry = NULL;

  shop = context_create(mp);
  if (shop) {
    customer = entity_create(shop, "customer");
  }

  if (customer) {
    registry = component_create(customer, "registry");
    credentials = component_create(customer, "credentials");
  }

  if (registry && credentials) {

    context_store(shop, dbd);

  }
  
  if (!rv) {
    if (!input_v) {
      printf(er, "Input validation failed");
    } else if (!apr_v) {
      printf(er, "APR initialization failed");
    } else if (!mp_v) {
      printf(er, "Memory pool allocation failed");
    } else if (!apr_dbd_v) {
      printf(er, "APR DB initialization failed");
    } else if (dbd == NULL) {
      printf(er, "DB initialization failed");
    } else if (!db_open_v) {
      printf(er, "DB open failed");
    } else {
      printf(er, "Context creation failed");
    }
  }

  if (db_open_v) {
    hlp_dbd_close(dbd);
  }
  if (mp_v) {
    apr_pool_destroy(mp);
  }
  apr_terminate();
  exit(rv ? EXIT_SUCCESS : EXIT_FAILURE);
}

#endif

// =============================================================================
// request
// =============================================================================
#ifdef request

#include "hlp_request.h"

typedef struct hlp_http_request_t {
  apr_pool_t *pool;
  const char *method;
  const char *uri;
  const char *query;
  const char *body;
  apr_size_t body_sz;
  apr_table_t *headers;
  apr_table_t *args;
  apr_table_t *vars;
  apr_table_t *cookies;
} hlp_http_request_t;

hlp_http_request_t* hlp_http_request_init(apr_pool_t *mp) {
  hlp_http_request_t *ret = (hlp_http_request_t*)apr_palloc(mp, sizeof(hlp_http_request_t));
  if (ret != NULL) {
    ret->pool = mp;
    ret->method = NULL;
    ret->uri = NULL;
    ret->query = NULL;
    ret->body = NULL;
    ret->body_sz = 0;
    ret->headers = NULL;
    ret->args = NULL;
    ret->vars = NULL;
    ret->cookies = NULL;
  }
  return ret;
}

void hlp_http_request_set_field(hlp_http_request_t *r, const char **field, const char *value, apr_size_t sz) {
  if (r != NULL && field != NULL && value != NULL) {
    const char *s = hlp_str(r->pool, value, sz);
    if (s != NULL) {
      *field = s;
    }
  }
}

void hlp_http_request_method_set(hlp_http_request_t *r, const char *m, apr_size_t sz) {
  hlp_http_request_set_field(r, &(r->method), m, sz);
}

const char* hlp_http_request_method_get(hlp_http_request_t *r) {
  return r->method;
}

void hlp_http_request_uri_set(hlp_http_request_t *r, const char *u, apr_size_t sz) {
  hlp_http_request_set_field(r, &(r->uri), u, sz);
}

const char* hlp_http_request_uri_get(hlp_http_request_t *r) {
  return r->uri;
}

void hlp_http_request_query_set(hlp_http_request_t *r, const char *q, apr_size_t sz) {
  hlp_http_request_set_field(r, &(r->query), q, sz);
}

const char* hlp_http_request_query_get(hlp_http_request_t *r) {
  return r->query;
}

void hlp_http_request_body_set(hlp_http_request_t *r, const char *u, apr_size_t sz) {
  hlp_http_request_set_field(r, &(r->body), u, sz);
  r->body_sz = sz;
}

const char* hlp_http_request_body_get(hlp_http_request_t *r) {
  return r->body;
}

apr_size_t hlp_http_request_body_size_get(hlp_http_request_t *r) {
  return r->body_sz;
}

void hlp_http_request_headers_set(hlp_http_request_t *r, apr_table_t *v) {
  r->headers = v;
}

apr_table_t* hlp_http_request_headers_get(hlp_http_request_t *r) {
  return r->headers;
}

void hlp_http_request_args_set(hlp_http_request_t *r, apr_table_t *v) {
  r->args = v;
}

apr_table_t* hlp_http_request_args_get(hlp_http_request_t *r) {
  return r->args;
}

void hlp_http_request_vars_set(hlp_http_request_t *r, apr_table_t *v) {
  r->vars = v;
}

apr_table_t* hlp_http_request_vars_get(hlp_http_request_t *r) {
  return r->vars;
}

void hlp_http_request_cookies_set(hlp_http_request_t *r, apr_table_t *v) {
  r->cookies = v;
}

apr_table_t* hlp_http_request_cookies_get(hlp_http_request_t *r) {
  return r->cookies;
}

apr_table_t* hlp_http_parse_formdata(request_rec *r)
{
  int rv;
  char *buffer;
  apr_off_t len;
  apr_size_t size;
  apr_table_t *retv;
  apr_array_header_t *pairs = NULL;
  rv = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
  if (rv != OK || !pairs) return NULL;
  if ((retv = apr_table_make(r->pool, pairs->nelts)) == NULL) return NULL;
  while (pairs && !apr_is_empty_array(pairs)) {
    ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
    apr_brigade_length(pair->value, 1, &len);
    size = (apr_size_t) len;
    buffer = (char*)apr_palloc(r->pool, size + 1);
    apr_brigade_flatten(pair->value, buffer, &size);
    buffer[len] = 0;
    apr_table_setn(retv, apr_pstrdup(r->pool, pair->name), buffer);
  }
  return retv;
}

size_t hlp_http_parse_rawdata(request_rec *r, const char **rbuf)
{
  int st;
  size_t size;
  *rbuf = NULL;
  if ((st = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) return 1;
  if (ap_should_client_block(r)) {
    char buf[HUGE_STRING_LEN];
    apr_off_t rsize, len_read, rpos = 0;
    apr_off_t length = r->remaining;
    *rbuf = (const char*)apr_pcalloc(r->pool, (apr_size_t)(length + 1));
    if (*rbuf == NULL) return 1;
    size = length;
    while ((len_read = ap_get_client_block(r, buf, sizeof(buf))) > 0) {
      if ((rpos + len_read) > length) rsize = length - rpos;
      else rsize = len_read;
      memcpy((char *) *rbuf + rpos, buf, (size_t) rsize);
      rpos += rsize;
    }
  }
  return size;
}
#endif



#ifdef APRX_TEST_APACHE_MODULE

#include "apr.h"
#include "apr_general.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_optional.h"
#include "apr_dbd.h"
#include "apr_time.h"

#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "mod_dbd.h"
#include "mod_hello_api.h"
#include "mod_watchdog.h"
#include "hlp_observer.h"

module AP_MODULE_DECLARE_DATA hello_module;

const char* (*say_hello_fn)(apr_pool_t *mp) = NULL;
const char* (*say_goodbye_fn)(apr_pool_t *mp) = NULL;
ap_dbd_t *(*authn_dbd_acquire_fn)(request_rec*) = NULL;

// -----------------------------------------------------------------------------
// SERVER SENT EVENT (SSE) HANDLER
// -----------------------------------------------------------------------------

static void hello_sse_event(request_rec *r) {
  ap_rprintf(r, "data: {\"message\": \"%s\"}\n\n", say_hello_fn(r->pool));
  ap_rflush(r);
}

static void hello_sse_handler(request_rec *r) {
  if (r->protocol && !strcasecmp(r->protocol, "HTTP/1.1")) {
    ap_set_content_type(r, "text/event-stream");
    ap_set_keepalive(r);
    // Inizio del flusso di eventi
    ap_rprintf(r, "data: Server: Apache/%s\n\n", ap_get_server_banner());
    ap_rflush(r);
    // Invia eventi SSE a intervalli regolari
    for (int i = 0; i < 10; i++) {
      hello_sse_event(r);
      // Attende per 1 secondo
      apr_sleep(1 * APR_USEC_PER_SEC);
    }
    // Fine del flusso di eventi
    ap_rputs("event: end\ndata: {}\n\n", r);
    ap_rflush(r);
  }
}

// -----------------------------------------------------------------------------
// HTTP REQUEST HANDLER
// -----------------------------------------------------------------------------

static int hello_request_handler(request_rec *r) {

  apr_table_t *cfg;
  ap_dbd_t *dbd = NULL;

  if (strcmp(r->handler, "hello")) {
    return DECLINED;
  }

  cfg = (apr_table_t*)ap_get_module_config(r->server->module_config, &hello_module);

  dbd = NULL;
  authn_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
  if (authn_dbd_acquire_fn) {
    dbd = authn_dbd_acquire_fn(r);
  }

  say_hello_fn = APR_RETRIEVE_OPTIONAL_FN(say_hello);
  ap_set_content_type(r, "text/plain");
  ap_rprintf(r, "%s\n", say_hello_fn(r->pool));
  return OK;
}

// -----------------------------------------------------------------------------
// THREADED MONITOR
// -----------------------------------------------------------------------------

static void* APR_THREAD_FUNC hello_monitor_handler(apr_thread_t* th, void* dt) {
  apr_pool_t *mp;
  apr_status_t rv;
  do {
    rv = apr_initialize();
    if (rv != APR_SUCCESS) break;
    rv = apr_pool_create(&mp, NULL);
    if (rv != APR_SUCCESS) {
      apr_terminate();
      break;
    }
    apr_sleep(1000000 * 3);
    hlp_observer_notify(mp);
    apr_pool_destroy(mp);
    apr_terminate();
  } while (0);
  apr_thread_exit(th, APR_SUCCESS);
  return NULL;
}

static int hello_monitor_init(server_rec *s, const char *name, apr_pool_t *mp) {
  return OK;
}

static int hello_monitor_exit(server_rec *s, const char *name, apr_pool_t *mp) {
  return OK;
}

static int hello_monitor_step(server_rec *s, const char *name, apr_pool_t *mp) {
  apr_thread_t* th;
  if (strcmp(name, AP_WATCHDOG_SINGLETON)) {
    return OK;
  }
  apr_thread_create(&th, NULL, hello_monitor_handler, NULL, mp);
  printf("TEST\n");
  return OK;
}

static int hello_monitor_need(server_rec *s, const char *name,
                              int parent, int singl) {
  if (singl && !strcmp(name, AP_WATCHDOG_SINGLETON)) {
    return OK;
  } else {
    return DECLINED;
  }
}

// -----------------------------------------------------------------------------
// CONFIGURATION
// -----------------------------------------------------------------------------

void* hello_conf_make(apr_pool_t *m, server_rec *s) {
  return (void*)apr_table_make(m, 2);
}

const char* hello_conf_set(cmd_parms *p, void *c, const char *v) {
  void *cfg = ap_get_module_config(p->server->module_config, &hello_module);
  apr_table_setn((apr_table_t*)cfg, p->cmd->name, v);
  return NULL;
}

const command_rec hello_conf[] = {
  AP_INIT_TAKE1("DBDriver", hello_conf_set, NULL, OR_OPTIONS, ""),
  AP_INIT_TAKE1("HelloEnableObserver", hello_conf_set, NULL, OR_OPTIONS, ""),
  {NULL}
};

// -----------------------------------------------------------------------------
// HOOKS REGISTRATION
// -----------------------------------------------------------------------------

void hello_register_hooks(apr_pool_t *mp) {
  ap_hook_handler(hello_request_handler, NULL, NULL, APR_HOOK_LAST);
  ap_hook_watchdog_need(hello_monitor_need, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_watchdog_init(hello_monitor_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_watchdog_step(hello_monitor_step, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_watchdog_exit(hello_monitor_exit, NULL, NULL, APR_HOOK_MIDDLE);
}

// -----------------------------------------------------------------------------
// MODULE DATA STRUCT DECLARATION
// -----------------------------------------------------------------------------

module AP_MODULE_DECLARE_DATA hello_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  hello_conf_make,
  NULL,
  hello_conf,
  hello_register_hooks
};
#endif



#ifdef APRX_TEST_APACHE_MODULE_API
module AP_MODULE_DECLARE_DATA hello_api_module;

static void hello_api_register_hooks(apr_pool_t *p) {
  APR_REGISTER_OPTIONAL_FN(say_hello);
  APR_REGISTER_OPTIONAL_FN(say_goodbye);
}

module AP_MODULE_DECLARE_DATA hello_api_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  hello_api_register_hooks
};
#endif



// =============================================================================
// TEST
// =============================================================================


char* convertToDateString(apr_time_t timestamp) {
    char* dateStr = (char*)malloc(sizeof(char) * 20); // Allocazione della memoria per la stringa di output

    apr_time_exp_t timeExp;
    apr_time_exp_gmt(&timeExp, timestamp);

    apr_snprintf(dateStr, 20, "%04d-%02d-%02d %02d:%02d:%02d",
                 timeExp.tm_year + 1900, timeExp.tm_mon + 1, timeExp.tm_mday,
                 timeExp.tm_hour, timeExp.tm_min, timeExp.tm_sec);

    return dateStr;
}

#define expect(cond, expr, res) do { \
  cond;\
  printf("%s: %s\n", #expr, ((int)(expr))==(res) ? "PASS" : "FAIL"); \
} while(0)

void test_heplers(apr_pool_t *mp) {
  expect(int r, (r=aprx_rand(10, 100)) && r > 10 && r < 100, 1);
  expect(int r, (r=aprx_isempty("")), 1);
  expect(int r, (r=aprx_isempty(" ")), 1);
  expect(int r, (r=aprx_isempty("\n")), 1);
  expect(int r, (r=aprx_isempty("\r")), 1);
  expect(int r, (r=aprx_isempty("\r\n")), 1);
  expect(int r, (r=aprx_isempty("a")), 0);
  expect(int r, (r=aprx_isint("123")), 1);
  expect(int r, (r=aprx_isint("12.3")), 0);
  expect(int r, (r=aprx_isint("-123")), 1);
  expect(int r, (r=aprx_isdouble("123")), 1);
  expect(int r, (r=aprx_isdouble("12.3")), 1);
  expect(int r, (r=aprx_isdouble("-123")), 1);
  expect(int r, (r=aprx_instr("hello", "hell")), 1);
  expect(int r, (r=aprx_instr("hello", "a")), 0);
  expect(int r, (r=aprx_instr("hello", "")), 0);
  expect(const char* r, (r=aprx_ptrim(mp," Hi")) && (strcmp(r,"Hi")==0), 1);
  expect(const char* r, (r=aprx_ptrim(mp,"Hi ")) && (strcmp(r,"Hi")==0), 1);
  expect(const char* r, (r=aprx_ptrim(mp," Hi ")) && (strcmp(r,"Hi")==0), 1);
  expect(const char* r, (r=aprx_pstripc(mp, "Hello", 'l'))
         && (strcmp(r, "Heo")==0), 1);
  expect(char *r, (r=aprx_pslice(mp, "Hello", 1, 3))
         && (strcmp(r, "ell")==0), 1);
  expect(const char* r, (r=aprx_pstrrep(mp, "Hello", "He", "ha"))
         && (strcmp(r, "hallo")==0), 1);
  expect(const char* r, (r=aprx_prepc(mp, "Hello", 'e', 'a'))
         && (strcmp(r, "Hallo")==0), 1);
  expect(char* r, (r=aprx_strempty(mp)) && aprx_isempty(r)==1, 1);
  {
    apr_array_header_t *ar;
    expect(ar = NULL, (ar=aprx_psplit(mp, "a,b,c", ",")) && (ar != NULL)
           && (ar->nelts == 3)
           && (strcmp(APR_ARRAY_IDX(ar, 0, const char*), "a") == 0)
           && (strcmp(APR_ARRAY_IDX(ar, 1, const char*), "b") == 0)
           && (strcmp(APR_ARRAY_IDX(ar, 2, const char*), "c") == 0), 1);
    expect(const char *r, (ar != NULL) && (r=aprx_pjoin(mp, ar, ","))
           && (strcmp(r, "a,b,c")==0), 1);
  }
  expect(char* r, (r=aprx_pmd5(mp, "hello"))
         && (strcmp(r, "5d41402abc4b2a76b9719d911017c592")==0), 1);
  expect(char* r, (r=aprx_pbase64encode(mp, "hello"))
          && (strcmp(r, "aGVsbG8=")==0), 1);
  expect(char* r, (r=aprx_pbase64decode(mp, "aGVsbG8="))
          && (strcmp(r, "hello")==0), 1);
  {
    apr_table_t* tb;
    expect(tb = NULL, (tb=aprx_pargs2table(mp, "a=1&b=2&c=3")) && (tb != NULL)
           && (aprx_table_nelts(tb)==3)
           && (strcmp(apr_table_get(tb,"a"),"1")==0)
           && (strcmp(apr_table_get(tb,"b"),"2")==0)
           && (strcmp(apr_table_get(tb,"c"),"3")==0), 1);
    for (int i=0; i < aprx_table_nelts(tb); i++) {
      expect(apr_table_entry_t*e, (e=aprx_table_elt(tb,i))
             && e && e->key && e->val
             && ((strcmp(e->key,"a")==0)||
                 (strcmp(e->key,"b")==0)||
                 (strcmp(e->key,"c")==0))
             && ((strcmp(e->val,"1")==0)||
                 (strcmp(e->val,"2")==0)||
                 (strcmp(e->val,"3")==0)),
             1);
    }
  }
  {
    apr_time_t ts;
    expect(ts=0, (ts=aprx_timestamp(1972, 10, 23, 16, 30, 0)) && (ts==88705800000000), 1);
    expect(char *r, (r=aprx_pdatetime(mp, ts, "Y-m-d h:i:s")) && r && (strcmp(r, "1972-10-23 05:30:00")==0), 1);
    expect(char *r, (r=aprx_pdatetime_utc(mp, ts, "Y-m-d h:i:s")) && r && (strcmp(r, "1972-10-23 16:30:00")==0), 1);
    expect(char *r, (r=aprx_pdatetime_local(mp, ts, "Y-m-d h:i:s")) && r && (strcmp(r, "1972-10-23 05:30:00+0100")==0), 1);

    printf("%" APR_TIME_T_FMT "\n\n", ts);

    printf("%s\n\n", aprx_datetime_fmt(mp, "Y-m-d", 0));

    printf("%s\n\n", aprx_pdatetime(mp, ts, "Y-m-d"));
    printf("%s\n\n", aprx_pdatetime(mp, ts, "d/m/Y"));
    printf("%s\n\n", aprx_pdatetime(mp, ts, "d/m/y"));
    printf("%s\n\n", aprx_pdatetime(mp, ts, "d/M/y"));
    printf("%s\n\n", aprx_pdatetime(mp, ts, "d"));
    printf("%s\n\n", aprx_pdatetime(mp, ts, "m"));
    printf("%s\n\n", aprx_pdatetime(mp, ts, "Y"));
    printf("%s\n\n", aprx_pdatetime(mp, ts, "h:i:s"));
    printf("%s\n\n", aprx_pdatetime_utc(mp, ts, "h:i:s"));
  }
}






// char* aprx_pdatetime(apr_pool_t *mp, apr_time_t t, const char *f, int loc) {
//   char *rv = NULL;
//   apr_time_exp_t tm;
//   apr_size_t size = 100;
//   const char *fm = NULL;
//   char tmp[100] = {0};
//   if (mp && t && f) {
//     if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
//       fm = apr_pstrdup(mp, f);
//       if (fm) {
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "Y", "%Y"), "y", "%y");
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "m", "%m"), "d", "%d");
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "H", "%H"), "h", "%I");
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "s", "%S"), "i", "%M");
//       }
//     }
//   }
//   if (fm) {
//     if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
//       rv = apr_pstrdup(mp, tmp);
//     }
//   }
//   return rv;
// }

// char* aprx_pdatetime_local(apr_pool_t *mp, apr_time_t t, const char *f) {
//   char *rv = NULL;
//   apr_time_exp_t tm;
//   apr_size_t size = 100;
//   const char *fm = NULL;
//   char tmp[100] = {0};
//   if (mp && t && f) {
//     if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
//       fm = apr_pstrdup(mp, f);
//       if (fm) {
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "Y", "%Y"), "y", "%y");
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "m", "%m"), "d", "%d");
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "H", "%H"), "h", "%I");
//         fm = aprx_pstrrep(mp, aprx_pstrrep(mp, fm, "s", "%S"), "i", "%M");
//         fm = apr_pstrcat(mp, fm, "%z", NULL);
//       }
//     }
//   }
//   if (fm) {
//     if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
//       rv = apr_pstrdup(mp, tmp);
//     }
//   }
//   return rv;
// }

// char* aprx_pdatetime_utc(apr_pool_t *mp, apr_time_t t, const char *f) {
//   apr_time_exp_t tm;
//   apr_size_t size = 100;
//   char tmp[100] = {0}, *rv = NULL;
//   if (mp && t) {
//     // Usa apr_time_exp_gmt invece di apr_time_exp_lt
//     if (apr_time_exp_gmt(&tm, t) == APR_SUCCESS) {
//       // Formato desiderato
//       const char *fm = "%Y-%m-%d %H:%M:%S";
//       if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
//         rv = apr_pstrdup(mp, tmp);
//       }
//     }
//   }
//   return rv;
// }











// DRIVER
//#ifdef APRX_TEST_CONSOLE
int main(int argc, char **argv) {

  int rv = 0;

  struct state_t {
    int init, pool;  
  } st = {0, 0};

  do {

    st.init = apr_initialize() == APR_SUCCESS;
    if (!st.init)
      break;

    apr_pool_t *mp;
    st.pool = apr_pool_create(&mp, NULL) == APR_SUCCESS;
    if (!st.pool)
      break;

    test_heplers(mp);

    // apr_size_t sz = 32;
    // char *buffer = aprx_pbuff(mp, "hello world", &sz);
    // printf("%lu %s\n", sz, buffer);

    rv = 1;

    apr_pool_destroy(mp);
    apr_terminate();

  } while (0);

  if (!rv) {
    const char er[] = "Error: %s.\n\n";
    if (!st.init) {
      printf(er, "APR initialization failed");
    } else if (!st.pool) {
      printf(er, "Memory pool allocation failed");
    }
  }

  exit(rv ? EXIT_SUCCESS : EXIT_FAILURE);
}
//#endif

