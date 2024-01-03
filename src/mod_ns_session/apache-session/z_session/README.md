# mod_z_session.c

Modulo di esempio per la gestione della sessione. Questo modulo mostra come
implementare creare, leggere e scrivere nella sessione mediante la API della
libreria ZET e i moduli di estensione mod_session e mod_session_cookie
di Apache2.

### Installazione

L'installazione aggiunge il modulo mod_z_session.so alla directory dei moduli di
Apache2 e crea i file di configurazione z_session.conf e z_session.load.
Il file z_session.conf definisce lo handler da utilizzare per la richiesta HTTP.

```bash
$ make
$ sudo make install
```

### Attivazione del modulo e delle dipendenze
```bash
$ sudo a2enmod session
$ sudo a2enmod session_cookie
$ sudo a2enmod z_session
$ sudo systemctl restart apache2
```

#### z_session.conf
```apache
<Location /session>
SetHandler session
</Location>
```

#### z_session.load
```apache
LoadModule z_session_module modules/mod_z_session.so
```

### Test
Questo esempio mostra come usare cURL per testare il modulo utilizzando
un file temporaneo per lo storage dei cookies e il mantenimento della sessione
tra due richieste successive.
```bash
$ curl -i -c /tmp/z_cookie.txt -b /tmp/z_cookie.txt "http://localhost/session"
```

### Codice di esempio
```C
...
// Questa definizione deve precedere l'inclusione di zet.h
#define _ZET_HAS_SESSION
#include "zet.h"
...
void test_z_session(request_rec *r) {

  // Crea una nuova sessione
  z_session_t *s = z_session_start(r);
  
  // Verifica la corretta allocazione della memoria e lo stato della sessione
  if (s == NULL || !s->is_active) {
    ap_rprintf(r, "La sessione non è attiva");
    return;
  }
  
  // Ottiene il numero delle variabili allocate nella sessione
  int num_entries = z_session_num_entries(s);
  
  if (num_entries <= 0) {
    ap_rprintf(r, "La sessione è vuota");
    // Se la sessione non contiene inserimenti alloca tre valori
    z_session_set(r, s, "key_1", "value_1");
    z_session_set(r, s, "key_2", "value_2");
    z_session_set(r, s, "key_3", "value_3");
    // Salva la sessione
    z_session_save(r, s, 1);
    return;
  }

  // Estrae le variabili in una tabella
  // e ne stampa le relative coppie chiave/valore
  apr_table_t *entries = z_session_entries(s);
  if (entries != NULL) {
    for (int i = 0; i < num_entries; i++) {
      apr_table_entry_t *e = z_table_entry(entries, i);
      ap_rprintf(r, "%s: %s\n", e->key, e->val);
    }
  }
}
```

### API :: z_session

```C
/** Tipo opaco, struttura di gestione della sessione
 */
typedef struct z_session_t z_session_t;

/** Avvia una nuova sessione o ripristina una sessione esistente
 *  @param r Record della richiesta HTTP
 *  @return Struttura della sessione attiva
 */
z_session_t* z_session_start(request_rec *r);

/** Termina una sessione esistente modificandone il maxage
 *  @param r Record della richiesta HTTP
 *  @param s Struttura della sessione attiva
 *  @return Stato di successo dell'operazione
 */
int z_session_destroy(request_rec *r, z_session_t *s);

/** Setta/aggiorna un valore in sessione
  * @param r Record della richiesta HTTP
  * @param s Struttura della sessione attiva
  * @param k Chiave del valore da registrare
  * @param v Valore da registrare
  * @return Stato di successo dell'operazione
  */
int z_session_set(request_rec *r, z_session_t *s, const char *k, const char *v);

/** Estrae il valore di una variabile di sessione
  * @param r Record della richiesta HTTP
  * @param s Struttura della sessione attiva
  * @param k Chiave del valore da estrarre
  * @param v Valore da estrarre
  * @return Stato di successo dell'operazione
  */ 
int z_session_get(request_rec *r, z_session_t *s, const char *k, const char **v);

/** Restituisce una tabella di tutti i valori presenti nella sessione attiva
  * @param s Struttura della sessione attiva
  * @return Tabella delle coppie chiave/valore
  */ 
apr_table_t* z_session_entries(z_session_t *s);

/** Restituisce il numero degli inserimenti presenti nella sessione attiva
  * @param s Struttura della sessione attiva
  * @return Numero delle coppie chiave/valore
  */ 
int z_session_num_entries(z_session_t *s);

/** Registra lo stato della sessione attiva
  * @param r Record della richiesta HTTL
  * @param s Struttura della sessione attiva
  * @param d =1 se la sessione è stata modificata dall'ultimo salvataggio
  * @return Stato di successo dell'operazione
  * @note Inpostando a 1 il valore di 'd' viene forzata la scrittura dei dati
  */ 
int z_session_save(request_rec *r, z_session_t *s, int d);
```
