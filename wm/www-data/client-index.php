<?php
// TODO: Implementare il controllo sulla scadenza del token di autorizzazione
/* ========================================================================== */
$DEBUG = true;
/* ========================================================================== */
$_['DEBUGIPS'] = [$_SERVER['REMOTE_ADDR']]; // Disattivare in produzione
$_['HOSTNAME'] = 'http://server.local';
$_['USERNAME'] = 'bob@email.net';
$_['PASSWORD'] = hash("sha512", 'secret');
$_['HTMETHOD'] = $_SERVER['REQUEST_METHOD'];
$_['ENDPOINT'] = $_SERVER['REQUEST_URI'];
$_['HTTPDATA'] = http_build_query($_REQUEST);
$_['MAXREDIR'] = 10;
$_['HTENCODE'] = '';
$_['HTTPVERS'] = CURL_HTTP_VERSION_1_1;
$_['TIMEOUT']  = 30;
$_['AUTHTYPE'] = 'HMAC-HS256';
$_['HTCOOKIE'] = "/tmp/z_cookie.txt";
$_['HTHEADER'] = [
  (isset($_SERVER["HTTP_ACCEPT"])
    ? 'Accept: '.trim($_SERVER["HTTP_ACCEPT"]) : ''),
  (isset($_SERVER["CONTENT_TYPE"])
    ? 'Content-Type: '.trim($_SERVER["CONTENT_TYPE"]) : ''),
];
/* ========================================================================== */
function z_auth_hmac_hs256($method, $endp, $user, $pass) {
  $date = date("M d Y H:i:s");
  $nonce = rand(100000, 999999);
  $hmac_s = "{$method}+{$endp}+".str_replace(' ','',$date)."+{$nonce}";
  $hmac = hash_hmac("sha256", $hmac_s, $pass, false);
  $digest = base64_encode($hmac);
  $http_h = array(
    "Authentication: hmac {$user}:{$nonce}:{$digest}",
    "Date: {$date}"
  );
  return $http_h;
}
/* ========================================================================== */
function z_http($http_h) {
  global $_;
  $ch = curl_init();
  if ($_['HTMETHOD'] == 'HEAD') {
    curl_setopt($ch, CURLOPT_NOBODY, true);
  } else {
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $_['HTMETHOD']);
  }
  curl_setopt($ch, CURLOPT_HEADER, true);
  curl_setopt($ch, CURLOPT_URL, $_['HOSTNAME'].$_['ENDPOINT']);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $http_h);
  curl_setopt($ch, CURLOPT_ENCODING, $_['HTENCODE']);
  curl_setopt($ch, CURLOPT_MAXREDIRS, $_['MAXREDIR']);
  curl_setopt($ch, CURLOPT_TIMEOUT, $_['TIMEOUT']);
  curl_setopt($ch, CURLOPT_HTTP_VERSION, $_['HTTPVERS']);
  curl_setopt($ch, CURLOPT_COOKIEFILE, $_['HTCOOKIE']);
  curl_setopt($ch, CURLOPT_COOKIEJAR, $_['HTCOOKIE']); 
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  if ($_['HTMETHOD'] == 'POST') {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $_['HTTPDATA']);
  }
  $res = curl_exec($ch);
  $err = curl_error($ch);
  curl_close($ch);
  $http_headers = $http_body = null;
  if (!$err) {
    $err = null;
    $res = str_replace("\r\n", "\n", $res);
    $res = explode("\n\n", $res);
    if (count($res) > 0) {
      $headers = explode("\n", $res[0]);
      if (count($headers) > 0) {
        $http_headers = [];
        foreach($headers as $header) {
          $header = explode(':', $header);
          if (count($header) == 1) {
            $header = explode(' ', $header[0]);
            if (is_numeric($header[1])) {
              $http_headers['HTTP_STATUS'] = $header[1];
            }
          } else if (count($header) == 2) {
            $http_headers[trim($header[0])] = trim($header[1]);
          } else if (trim(strtolower($header[0])) == 'date') {
            $hd = trim($header[0]);
            array_shift($header);
            $http_headers[$hd] = trim(implode(':', $header));
          }
          else {
            print_r($header);
          }
        }
      }
      if (count($res) > 1) {
        $http_body = $res[1];
      }
    }
  }
  return [
    'http_headers' => $http_headers,
    'http_body' => $http_body,
    'error' => $err
  ];
}
/* ========================================================================== */
function z_authorize() {
  global $_;
  // Se il tipo di richieta deve prevedere una autenticazione/autorizzazione
  if (isset($_SERVER['HTTP_X_ZET_AUTH'])) {
    // Se una autorizzazione non è ancora stata richiesta
    if (!isset($_SESSION['HTTP_X_ZET_AUTH'])) {
      // Se il tipo di autenticazione/autorizzazione è supportato dal server
      if ($_SERVER['HTTP_X_ZET_AUTH'] == 'HMAC-HS256') {
        // Se il tipo di autenticazione richiesta è HMAC-HS256
        // eseguo una seconda richiesta intermedia per ottenere il token
        // autorizzativo JWT
        if ($_['AUTHTYPE'] == 'HMAC-HS256') {
          // Modifico in HEAD il metodo della request
          $_['HTMETHOD'] = "HEAD";
          // Aggiungo agli headers HTTP il token HMAC l'identificazione utente
          $http_h = array_merge(
            $_['HTHEADER'],
            z_auth_hmac_hs256(
              $_['HTMETHOD'],
              $_['ENDPOINT'],
              $_['USERNAME'],
              $_['PASSWORD']
            )
          );
        } else {
          // Tipo di autenticazione/autorizzazione non supportato dal server
          $log = "Unsupported {$_SERVER['HTTP_X_ZET_AUTH']} method";
          header('Content-Type: application/json');
          echo json_encode(['status' => 'unauthorized', 'log' => $log]);
          die;
        }
        // Richiedo autenticazione
        $res = z_http($http_h);
        if (is_null($res['error']) && !is_null($res['http_headers'])) {
          $authenticated = false;
          $token = null;
          foreach ($res['http_headers'] as $k => $v) {
            // Verifico il valore dello header di autenticazione
            if ($k == 'X-Zet-Auth-Status') {
              if ($v == 'authenticated') {
                $authenticated = true;
              }
            } else if ($k == 'X-Zet-Auth-Token') {
              // Estraggo il token di autorizzazione
              $token = $v;
            }
          }
          // Registro il token di autorizzazione nella sessione
          if ($authenticated && !is_null($token)) {
            $_SESSION['HTTP_X_ZET_AUTH'] = $token;
          }
        }
      }
    }
    // Se la sessione contiene un token di autorizzazione
    if (isset($_SESSION['HTTP_X_ZET_AUTH'])) {
      if (!empty($_SESSION['HTTP_X_ZET_AUTH'])) {
        // Recupero il metodo della request originale
        $_['HTMETHOD'] = $_SERVER['REQUEST_METHOD'];
        // Aggiungo il token di autorizzazione agli headers
        $http_h = array_merge(
          $_['HTHEADER'],
          ["Authorization: Bearer {$_SESSION['HTTP_X_ZET_AUTH']}"]
        );
      }
    }
  } else {
    // Il tipo di richieta non preved una autenticazione/autorizzazione
    $http_h = $_['HTHEADER'];
  }
  return $http_h;
}
/* ========================================================================== */
function z_is_unauthorized($res) {
  return (isset($_SESSION['HTTP_X_ZET_AUTH']) &&
          !empty($_SESSION['HTTP_X_ZET_AUTH']) &&
          isset($res['http_headers']['HTTP_STATUS']) &&
          $res['http_headers']['HTTP_STATUS'] == '401');
}
/* ========================================================================== */
function z_request() {
  $http_h = z_authorize();
  return z_http($http_h);
}
/* ========================================================================== */
// Avvio la sessione
session_start();
// Eseguo la richiesta al server
$res = z_request();
// Se la richiesta al server non viene autorizzata
if (z_is_unauthorized($res)) {
  // Rimuovo il token di autorizzazione dalla sessione
  // per forzarne la rigenerazione ed eseguo una nuova richiesta
  unset($_SESSION['HTTP_X_ZET_AUTH']);
  $res = z_request();
}
/* ========================================================================== */
if (!$res['error'] && !empty($res['http_headers']) && !empty($res['http_body'])) {
  foreach ($res['http_headers'] as $k => $v)
    if ($k != 'HTTP_STATUS') header("{$k}: {$v}");
  echo $res['http_body'];
} else if ($res['error']) {
  header('Content-Type: text/plain');
  echo $res['error'];
} else {
  header('Content-Type: text/plain');
  if ($DEBUG && in_array($_SERVER['REMOTE_ADDR'], $_['DEBUGIPS'])) {
    print_r($res);
  } else {
    echo "Empty reply from server.";
  }
}
/* ========================================================================== */
exit;
/* ========================================================================== */
?>
