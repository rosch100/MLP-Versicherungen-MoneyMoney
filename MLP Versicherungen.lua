-- Plugin Homepage: https://github.com/rosch100/MLP-Versicherungen-MoneyMoney
-- MLP Versicherungen — MoneyMoney Web Banking Extension
-- https://kundenportal.mlp.de
-- API: https://moneymoney.app/api/webbanking/
--
-- Authentifizierung: Benutzername/Passwort mit SecureGo Plus — Version 1.0
-- Version: 1.0

WebBanking{
  version     = 1.0,
  url         = "https://kundenportal.mlp.de",
  services    = {"MLP Versicherungen"},
  description = "MLP Versicherungen"
}

local CONSTANTS = {
  baseUrl           = "https://kundenportal.mlp.de",
  authBaseUrl       = "https://financepilot-pe.mlp.de",
  userAgent         = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15",
  loginEndpoint     = "/services_auth/auth-backend/api/authentication/login",
  portalOkpLogin    = "/api/okp/login?backUrl=https://kundenportal.mlp.de/kunde",
  initUiPath        = "/services_auth/auth-backend/api/init-ui",
  tanMethodsCheckPath             = "/services_auth/auth-backend/api/tan-process/tan-methods-check",
  browserDetectionStartPath       = "/services_auth/auth-backend/api/tan-process/browser-detection-auth/start",
  browserDetectionTerminationPath = "/services_auth/auth-backend/api/tan-process/browser-detection-auth/termination",
  browserDetectionChoosePath      = "/services_auth/auth-backend/api/browser-detection/choose",
  tanDeliveryPath   = "/services_auth/auth-backend/api/forward/tan/rest/de.bankenit.identitaet.tan.komponente.v1.TanKomponenteApi/liefereTanVerfahren",
  directApprovalPath = "/services_auth/auth-backend/api/forward/tan/rest/de.bankenit.identitaet.tan.komponente.v1.TanKomponenteApi/direktfreigabe/authentication",
  authClientId      = "mlp",
  authRedirectUri   = "https://kp.mlp.de/okp/login",
  consentEndpoint   = "/services_auth/auth-backend/api/consent/execution",
  vueApiBase        = "https://vue.mlp.de",
  vueTokenEndpoint  = "/vu/api/token",
  vueContractListPath = "/vu/api/contract/list",
  portalVuApi       = "/api/app/vu",
  mfaSessionExpired = "MFA-Session abgelaufen. Bitte neu einloggen.",
  secureGoPollAttempts = 40,
  secureGoPollSeconds = 3,
  secureGoMaxConsecutiveErrors = 3,
  allowedHosts = {
    "kundenportal.mlp.de",
    "financepilot-pe.mlp.de",
    "vue.mlp.de",
  },
}

-- Globale (modulweite) Variablen müssen VOR den Funktionen deklariert werden
local connection
local session = {
  contracts = {},
  username = nil,
  browserTanProcessId = nil,
  sessionCookies = {},
  persistedConnection = false
}

local function isMlpDebugEnabled()
  local storage = rawget(_G, "LocalStorage")
  return storage ~= nil and storage.mlpDebug == true
end

function mlpDebugLog(message)
  if not isMlpDebugEnabled() then
    return
  end
  if type(message) ~= "string" or message == "" then
    return
  end
  if MM and type(MM.printStatus) == "function" then
    MM.printStatus(message)
  end
end

function hostFromUrl(url)
  if type(url) ~= "string" or url == "" then
    return nil
  end
  local host = url:match("^https?://([^/?#]+)")
  if not host then
    return nil
  end
  host = host:lower():gsub(":443$", ""):gsub(":80$", "")
  return host
end

function isAllowedMlpHost(host)
  if not host or host == "" then
    return false
  end
  host = host:lower()
  for _, allowed in ipairs(CONSTANTS.allowedHosts) do
    if host == allowed:lower() then
      return true
    end
  end
  return false
end

function assertAllowedMlpUrl(url)
  if type(url) ~= "string" or url == "" then
    return nil, "URL fehlt"
  end
  if not url:match("^https://") then
    return nil, "Nur absolute https://-URLs erlaubt"
  end
  local host = hostFromUrl(url)
  if not isAllowedMlpHost(host) then
    return nil, "Host nicht erlaubt: " .. tostring(host)
  end
  return url, nil
end

-- ============================================================================
-- JWE / JOSE Kryptografie-Helper (basierend auf dokumentierten MM.* APIs)
-- ============================================================================

function base64UrlEncode(data)
  if not data or data == "" then return "" end
  if type(MM.base64urlencode) == "function" then
    return MM.base64urlencode(data)
  end
  -- Fallback: Standard base64 mit URL-safe Anpassungen
  return ""
end

-- Base64URL (RFC 4648 §5) in Standard-Base64 mit Padding umwandeln und mit dem offiziellen
-- MM.base64decode dekodieren. MM.base64urldecode existiert in MoneyMoney nicht.
function base64UrlDecode(encoded)
  if not encoded or encoded == "" then return "" end
  if type(MM.base64decode) ~= "function" then
    error("MLP Versicherungen: MM.base64decode fehlt, JWKS-Schlüssel können nicht gelesen werden.")
  end
  local standard = (encoded:gsub("-", "+"))
  standard = (standard:gsub("_", "/"))
  local padding = (4 - #standard % 4) % 4
  standard = standard .. string.rep("=", padding)
  return MM.base64decode(standard)
end

function generateRandomBytes(length)
  if type(MM.random) == "function" then
    return MM.random(length)
  end
  error("MLP Versicherungen: MM.random ist für kryptografisch sichere Zufallsdaten erforderlich.")
end

-- ============================================================================
-- JWE Compact Serialization (RSA-OAEP-512 + A256GCM)
-- ============================================================================

--- MoneyMoney ≥ 2.5.2: AES-GCM via MM.aes256encrypt(..., "aes256 gcm", aad).
function canUseA256Gcm()
  return type(MM.aes256encrypt) == "function"
end

--- True when MoneyMoney exposes the APIs needed to build MLP JWE locally.
--- RSA-OAEP-SHA-512 is enforced at encrypt time (no SHA-256 under RSA-OAEP-512 header).
function canUseJweLogin()
  return type(MM.random) == "function"
    and type(MM.base64urlencode) == "function"
    and type(MM.rsaEncrypt) == "function"
    and canUseA256Gcm()
end

function aesGcmEncrypt(key, iv, plaintext, aad)
  if type(MM.aes256encrypt) ~= "function" then
    return nil, nil
  end
  -- GCM requires AAD (may be empty); see moneymoney-app.com/api/webbanking/
  if aad == nil then
    aad = ""
  end
  local ok, ciphertext, tag = pcall(function()
    return MM.aes256encrypt(key, iv, plaintext, "aes256 gcm", aad)
  end)
  if ok and type(ciphertext) == "string" then
    if type(tag) == "string" then
      return ciphertext, tag
    end
    return ciphertext, nil
  end
  return nil, nil
end

function generateJwe(payload, publicKey)
  mlpDebugLog("MLP-DEBUG: generateJwe startet, prüfe Krypto-Funktionen...")
  if not (type(MM.random) == "function" and
          type(MM.base64urlencode) == "function" and
          type(MM.rsaEncrypt) == "function") then
    mlpDebugLog("MLP-DEBUG: Fehlende Krypto-Funktionen!")
    return nil, "Kryptografische Funktionen nicht verfügbar."
  end
  if not canUseA256Gcm() then
    mlpDebugLog("MLP-DEBUG: MM.aes256encrypt nicht verfügbar!")
    return nil, "A256GCM nicht verfügbar (MM.aes256encrypt fehlt)."
  end

  local cek = generateRandomBytes(32)
  local iv = generateRandomBytes(12)

  local header = {
    alg = "RSA-OAEP-512",
    enc = "A256GCM",
    typ = "JWE",
    kid = session.publicKeyKid or "mlp-auth-key"
  }
  local encodedHeader = base64UrlEncode(encodeJson(header))

  local payloadJson = type(payload) == "string" and payload or encodeJson(payload)
  local ciphertext, tag = aesGcmEncrypt(cek, iv, payloadJson, encodedHeader)
  if not ciphertext then
    return nil, "AES-256-GCM Verschlüsselung fehlgeschlagen"
  end

  local encryptedKey = encryptCekWithRsa(cek, publicKey)
  if not encryptedKey then
    mlpDebugLog("MLP-DEBUG: encryptCekWithRsa lieferte nil")
    return nil, "CEK-Verschlüsselung mit RSA-OAEP-512 fehlgeschlagen"
  end

  local encodedEncryptedKey = base64UrlEncode(encryptedKey)
  local encodedIv = base64UrlEncode(iv)
  local encodedCiphertext = base64UrlEncode(ciphertext)
  local encodedTag = base64UrlEncode(tag or "")

  return encodedHeader .. "." .. encodedEncryptedKey .. "." .. encodedIv .. "." ..
         encodedCiphertext .. "." .. encodedTag, nil
end

function encryptCekWithRsa(cek, publicKey)
  mlpDebugLog("MLP-DEBUG: encryptCekWithRsa startet, publicKey Typ=" .. type(publicKey))

  if type(MM.rsaEncrypt) ~= "function" then
    return nil
  end

  local keyTable = publicKey

  if type(publicKey) == "string" and type(MM.rsaPkcs8decode) == "function" then
    local ok, decoded = pcall(MM.rsaPkcs8decode, publicKey)
    if ok and type(decoded) == "table" then
      keyTable = decoded
    end
  end

  if type(keyTable) ~= "table" then
    mlpDebugLog("MLP-DEBUG: keyTable ist kein table, Typ=" .. type(keyTable))
    return nil
  end

  -- Header alg is RSA-OAEP-512: only matching OAEP-SHA-512 padding (no SHA-256 fallback).
  local paddingSpec = "pkcs1-oaep sha512"
  mlpDebugLog("MLP-DEBUG: Versuche rsaEncrypt mit " .. paddingSpec .. "...")
  local ok, encryptedKey = pcall(function()
    return MM.rsaEncrypt(keyTable, cek, paddingSpec)
  end)
  if ok and type(encryptedKey) == "string" and encryptedKey ~= "" then
    return encryptedKey
  end
  if not ok then
    mlpDebugLog("MLP-DEBUG: rsaEncrypt OAEP-SHA-512 fehlgeschlagen: " .. tostring(encryptedKey))
  end

  return nil
end

-- ============================================================================
-- Public Key Fetching (OIDC JWKS)
-- ============================================================================

-- Holt den Schlüssel für die PIN-Verschlüsselung wie der Browser:
-- 1. Start am Kundenportal (okp/login), der über OAuth-authorize zur Anmeldung führt,
-- 2. POST init-ui ohne Body. Die Antwort enthält pinEncryptionPublicKey.
-- Liefert den RSA-Schlüssel und setzt session.publicKeyKid auf dessen kid.
-- Fehlt der Schlüssel, liefert die Funktion nil (kein Fallback auf das JWKS).
-- Startet den Login am Kundenportal wie im Browser. Dort entstehen PKCE und State, mit denen
-- kp.mlp.de den Autorisierungscode später einlöst. Liefert true oder nil plus Fehlermeldung.
function startPortalAuthorization()
  local portalStart = connection:get(CONSTANTS.baseUrl .. CONSTANTS.portalOkpLogin)
  if not portalStart then
    MM.printStatus("MLP: Kundenportal-Login (okp/login) hat keine Antwort geliefert.")
    return nil, "MLP: Kundenportal-Login (okp/login) hat keine Antwort geliefert."
  end
  collectSessionCookies()
  return true
end

function fetchPinEncryptionKey()
  MM.printStatus("MLP: Lade PIN-Verschlüsselungsschlüssel...")

  if not connection then
    mlpDebugLog("MLP-DEBUG: connection ist nil!")
    return nil, nil, "MLP: Keine Verbindung für den Schlüssel-Abruf."
  end

  local started, startError = startPortalAuthorization()
  if not started then
    return nil, nil, startError
  end

  local headers = {
    ["Accept"] = "application/json",
    ["Origin"] = CONSTANTS.authBaseUrl,
    ["Referer"] = CONSTANTS.authBaseUrl .. "/",
  }
  local cookieHeader = buildCookieHeader(false)
  if cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  local initUiUrl = CONSTANTS.authBaseUrl .. CONSTANTS.initUiPath
    .. "?client_id=" .. CONSTANTS.authClientId
    .. "&redirect_uri=" .. urlEncode(CONSTANTS.authRedirectUri)
  local content = connection:request("POST", initUiUrl, "", nil, headers)
  local initUi = parseJson(content)
  local jwk = type(initUi) == "table" and initUi.pinEncryptionPublicKey or nil
  if type(jwk) ~= "table" or jwk.kty ~= "RSA" or type(jwk.kid) ~= "string" or jwk.kid == "" then
    MM.printStatus("MLP: init-ui enthält keinen PIN-Verschlüsselungsschlüssel.")
    mlpDebugLog("MLP-DEBUG: init-ui ohne gültiges pinEncryptionPublicKey")
    return nil, nil, "MLP: init-ui lieferte keinen PIN-Verschlüsselungsschlüssel."
  end

  local publicKey = extractPublicKeyFromJwk(jwk)
  if not publicKey then
    MM.printStatus("MLP: PIN-Verschlüsselungsschlüssel ist ungültig.")
    return nil, nil, "MLP: PIN-Verschlüsselungsschlüssel aus init-ui ist ungültig."
  end

  local pinNonce = initUi.pinEncryptionNonce
  if type(pinNonce) ~= "string" or pinNonce == "" then
    return nil, nil, "MLP: init-ui lieferte keine pinEncryptionNonce."
  end

  session.publicKeyKid = jwk.kid
  mlpDebugLog("MLP-DEBUG: PIN-Schlüssel aus init-ui, kid=" .. jwk.kid)
  return publicKey, pinNonce
end

function extractPublicKeyFromJwk(jwk)
  if not jwk then
    return nil
  end

  if jwk.kty == "RSA" and jwk.n and jwk.e then
    local n = base64UrlDecode(jwk.n)
    local e = base64UrlDecode(jwk.e)
    if n == "" or e == "" then
      return nil
    end

    return constructPublicKeyFromComponents(n, e)
  end

  if jwk.kty == "RSA" and jwk.x5c and type(jwk.x5c) == "table" and jwk.x5c[1]
      and type(MM.rsaPkcs8decode) == "function" then
    local pem = "-----BEGIN CERTIFICATE-----\n" .. jwk.x5c[1] .. "\n-----END CERTIFICATE-----"
    local ok, decoded = pcall(MM.rsaPkcs8decode, pem)
    if ok and type(decoded) == "table" then
      return decoded
    end
  end

  return nil
end

function constructPublicKeyFromComponents(modulus, exponent)
  if not modulus or not exponent then
    return nil
  end

  -- keyTable fuer MM.rsaEncrypt: { n = ..., e = ... }
  return { n = modulus, e = exponent }
end

function SupportsBank(protocol, bankCode)
  return protocol == ProtocolWebBanking and bankCode == "MLP Versicherungen"
end

function InitializeSession2(protocol, bankCode, step, credentials, interactive)
  -- Die SecureGo-Freigabe wird in Schritt 1 abgewartet. Einen zweiten Schritt gibt es nicht mehr.
  if step == 1 then
    return loginStep1(credentials, interactive)
  end

  return CONSTANTS.mfaSessionExpired
end

function restoreConnection(accountKey)
  local storage = rawget(_G, "LocalStorage")
  accountKey = accountKey or ""
  local canReuse = false

  if storage then
    storage.connectionsByAccount = storage.connectionsByAccount or {}
    local entry = storage.connectionsByAccount[accountKey]
    -- Active single-slot is authoritative when the accountKey matches (legacy + tests).
    if storage.connection ~= nil and storage.connectionAccountKey == accountKey then
      entry = entry or {}
      entry.connection = storage.connection
      if type(storage.sessionCookies) == "table" and entry.sessionCookies == nil then
        entry.sessionCookies = storage.sessionCookies
      end
      storage.connectionsByAccount[accountKey] = entry
    end
    canReuse = entry ~= nil and entry.connection ~= nil
    if canReuse then
      connection = entry.connection
      session.persistedConnection = true
      MM.printStatus("MLP: Persistierte Connection wiederverwendet.")
    else
      connection = Connection()
      storage.connectionsByAccount[accountKey] = { connection = connection }
      session.persistedConnection = true
    end
    storage.connection = connection
    storage.connectionAccountKey = accountKey
  else
    connection = Connection()
    session.persistedConnection = false
  end

  connection.language = "de-DE"
  connection.useragent = CONSTANTS.userAgent

  return canReuse, storage
end

function restorePersistedSessionCookies(storage, canReuse)
  session.sessionCookies = {}
  if not canReuse or not storage then
    return
  end
  local accountKey = storage.connectionAccountKey or ""
  local entry = storage.connectionsByAccount
    and storage.connectionsByAccount[accountKey]
  local cookies = entry and entry.sessionCookies
  if type(cookies) ~= "table" and type(storage.sessionCookies) == "table" then
    -- Legacy single-slot upgrade into the active map entry.
    cookies = storage.sessionCookies
    if entry then
      entry.sessionCookies = cookies
    end
  end
  if type(cookies) ~= "table" then
    return
  end
  for name, value in pairs(cookies) do
    session.sessionCookies[name] = value
  end
  MM.printStatus("MLP: Session-Cookies aus LocalStorage wiederhergestellt.")
end

function persistSessionCookies(storage)
  if not storage or not session.sessionCookies then
    return
  end
  local accountKey = storage.connectionAccountKey or ""
  storage.connectionsByAccount = storage.connectionsByAccount or {}
  local entry = storage.connectionsByAccount[accountKey]
  if not entry then
    entry = { connection = connection }
    storage.connectionsByAccount[accountKey] = entry
  end
  entry.sessionCookies = session.sessionCookies
  storage.sessionCookies = session.sessionCookies
end

function tryPersistedAuth(storage)
  collectSessionCookies()

  -- nil (keine Antwort) fällt wie false auf den Passwort-Login zurück; der fordert keine Cookies an.
  if isAuthenticated() then
    MM.printStatus("MLP: Bestehende Session gültig (persistierte Connection).")
    persistSessionCookies(storage)
    if loadContracts() then
      return nil
    end
    return "Authentifiziert, aber keine Versicherungsverträge gefunden."
  end

  return false
end

local function isCredentialRejectionMessage(message)
  if type(message) ~= "string" then
    return false
  end
  local normalized = message:lower()
  return normalized:find("ungültige anmeldedaten", 1, true) ~= nil
    or normalized:find("invalid_grant", 1, true) ~= nil
    or normalized:find("invalid credentials", 1, true) ~= nil
end

function loginStep1(credentials, interactive)
  local username = credentials[1]
  local password = credentials[2]

  local accountKey = username or ""
  local canReuse, storage = restoreConnection(accountKey)

  restorePersistedSessionCookies(storage, canReuse)

  MM.printStatus("MLP: Initialisiere Session...")

  local initContent = connection:get(CONSTANTS.authBaseUrl .. "/services_auth/auth-backend/public/session-lifetime-extension.html")
  if initContent then
    collectSessionCookies()
  end

  -- Persistierte Connection: Cookie-Jar (ggf. HttpOnly) wiederverwenden
  if canReuse then
    local persistedResult = tryPersistedAuth(storage)
    if persistedResult ~= false then
      return persistedResult
    end
  end

  if not username or username == "" or not password or password == "" then
    return "Bitte Benutzername und Passwort eingeben."
  end

  -- Die gespeicherte Verbindung bleibt erhalten: Das Geräte-Cookie CAS_DEVICE_SESSION ("Trust this browser")
  -- soll weiter gesendet werden. Die alte CAS_S_SESSION bleibt dabei im Cookie-Jar.
  if canReuse then
    -- Veraltete Session-Werte aus dem Speicher verwerfen, sonst bleibt eine alte VUSESSIONID aktiv.
    session.sessionCookies = {}
  end
  MM.printStatus("MLP: Authentifiziere mit Username/Passwort...")
  local loginResult = performLogin(username, password, interactive)

  if loginResult.success then
    local storage = rawget(_G, "LocalStorage")
    persistSessionCookies(storage)
    if loadContracts() then
      return nil
    else
      return "Login erfolgreich, aber keine Versicherungsverträge gefunden."
    end
  end

  if loginResult.requiresBrowserTan then
    return completeBrowserDetectionTan()
  end

  if isCredentialRejectionMessage(loginResult.error) then
    return LoginFailed
  end
  return loginResult.error or "Login fehlgeschlagen."
end

function performLogin(username, password, interactive)
  if canUseJweLogin() then
    MM.printStatus("MLP: Versuche JWE-verschlüsselten Login...")
    local jweResult = performJweLogin(username, password, interactive)
    if jweResult.success or jweResult.requiresBrowserTan then
      return jweResult
    end
    if jweResult.cryptoIncomplete then
      MM.printStatus("MLP: JWE-Krypto unvollständig — Klartext-Login...")
      return performPlaintextLogin(username, password, interactive)
    end
    return jweResult
  end

  -- Username/Passwort auch ohne JWE-APIs: Klartext-Login.
  MM.printStatus("MLP: JWE-Krypto-APIs nicht verfügbar — Klartext-Login...")
  return performPlaintextLogin(username, password, interactive)
end

function isEmptyLoginSuccess(content)
  return content == nil or content == "" or trim(content) == ""
end

function parseLoginResponse(content)
  if isEmptyLoginSuccess(content) then
    return { success = true, emptyBody = true }
  end

  local response = parseJson(content)
  if not response then
    return { success = false, error = "Ungültige Server-Antwort." }
  end

  if response.access_token then
    return { success = true }
  end

  if response.error then
    if response.error == "invalid_grant" then
      return { success = false, error = "Ungültige Anmeldedaten." }
    end
    if response.error == "invalid_request" then
      return { success = false, error = "Token-Anfrage vom Server abgelehnt." }
    end
    return { success = false, error = response.error_description or response.error }
  end

  if response.success or response.authenticated or authProcessCompleted(response) then
    return { success = true }
  end

  return { success = false, error = "Unbekannter Login-Status." }
end

-- Nach akzeptiertem Passwort-Login: Consent und Vue-Session herstellen, wie im Browser.
function completeAcceptedLogin()
  MM.printStatus("MLP: Login akzeptiert, schließe Post-Login-Flow ab...")
  if completePostLoginFlow() then
    return { success = true }
  end
  if isAuthenticated() then
    return { success = true }
  end
  return { success = false, error = "Login erfolgreich, aber Vue-Session nicht herstellbar." }
end

function extractIframeUrlFromPortalResponse(content)
  if not content or content == "" then
    return nil
  end

  -- api/app/vu liefert XML (<IframePageDto><iframeUrl>…</iframeUrl>), der Query-String ist XML-escaped.
  local xmlIframeUrl = content:match("<iframeUrl>([^<]+)</iframeUrl>")
  if xmlIframeUrl then
    local unescaped = xmlIframeUrl:gsub("&amp;", "&")
    return (assertAllowedMlpUrl(unescaped))
  end

  local iframeUrl = content:match('"iframeUrl"%s*:%s*"([^"]+)"')
  if iframeUrl then
    iframeUrl = iframeUrl:gsub("\\/", "/")
    local allowed = assertAllowedMlpUrl(iframeUrl)
    return allowed
  end

  local appUrl = content:match('"appUrl"%s*:%s*"([^"]+)"')
  local token = content:match('"token"%s*:%s*"([^"]+)"')
  if appUrl and token then
    appUrl = appUrl:gsub("\\/", "/")
    local allowedApp = assertAllowedMlpUrl(appUrl)
    if not allowedApp then
      return nil
    end
    local built = allowedApp .. "index.html?source=" .. urlEncode(CONSTANTS.baseUrl) .. "&token=" .. token
    local allowedBuilt = assertAllowedMlpUrl(built)
    return allowedBuilt
  end

  return nil
end

-- Übergibt den Autorisierungscode aus der Consent-Antwort an kp.mlp.de (wie der Browser).
function establishKundenportalSession(authParameters)
  MM.printStatus("MLP: Stelle Kundenportal-Session her...")
  local content = connection:get(CONSTANTS.authRedirectUri .. "?" .. authParameters)
  if content then
    collectSessionCookies()
  end

  local portalContent = connection:get(CONSTANTS.baseUrl .. "/")
  if portalContent then
    collectSessionCookies()
  end

  return content ~= nil or portalContent ~= nil
end

function fetchVueIframeUrl()
  MM.printStatus("MLP: Lade Vue-Client-URL...")
  local content = connection:get(CONSTANTS.baseUrl .. CONSTANTS.portalVuApi)
  if not content or content == "" then
    return nil
  end

  collectSessionCookies()
  return extractIframeUrlFromPortalResponse(content)
end

-- Liest einen Query-Parameter aus einer URL. Der Wert wird unverändert übernommen (wie im Browser).
function queryParamFromUrl(url, name)
  local query = url:match("%?([^#]*)")
  if not query then
    return nil
  end
  for key, value in query:gmatch("([^&=]+)=([^&]*)") do
    if key == name then
      return (value:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex, 16)) end))
    end
  end
  return nil
end

function establishVueSession(iframeUrl)
  if not iframeUrl or iframeUrl == "" then
    return false
  end
  local allowed, allowErr = assertAllowedMlpUrl(iframeUrl)
  if not allowed then
    MM.printStatus("MLP: Vue-iframe URL abgelehnt: " .. tostring(allowErr))
    return false
  end
  local token = queryParamFromUrl(allowed, "token")
  local source = queryParamFromUrl(allowed, "source")
  if not token or token == "" or not source or source == "" then
    MM.printStatus("MLP: Vue-iframe URL ohne token oder source.")
    return false
  end

  MM.printStatus("MLP: Initialisiere Vue-Session...")
  local clientContent = connection:get(allowed)
  if clientContent then
    collectSessionCookies()
  end

  -- Der Browser sendet Source und X-Authorization aus der Iframe-URL (HAR: token/set am vk-Client).
  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json, text/plain, */*",
    ["Accept-Language"] = "de-DE,de;q=0.9",
    ["Referer"] = CONSTANTS.vueApiBase .. "/vu/client/",
    ["Origin"] = CONSTANTS.vueApiBase,
    ["User-Agent"] = CONSTANTS.userAgent,
    ["Source"] = source,
    ["X-Authorization"] = token
  }

  local cookieHeader = buildCookieHeader(true)
  if cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  local success, tokenResponse = pcall(function()
    return connection:request(
      "POST",
      CONSTANTS.vueApiBase .. CONSTANTS.vueTokenEndpoint,
      "",
      "application/json",
      headers
    )
  end)
  if not success or not tokenResponse then
    MM.printStatus("MLP: Vue-Token-Aufruf ohne Antwort.")
    return false
  end

  -- Der Server meldet Fehler als JSON mit "status" (z. B. 403). Das ist kein Erfolg.
  local tokenError = parseJson(tokenResponse)
  if type(tokenError) == "table" and type(tokenError.status) == "number" and tokenError.status >= 400 then
    MM.printStatus("MLP: Vue-Token-Aufruf abgelehnt (Status " .. tokenError.status .. ").")
    return false
  end

  collectSessionCookies()
  return true
end

function completePostLoginFlow()
  local consentContent, consentError = callConsent()
  if not consentContent then
    MM.printStatus("MLP: " .. consentError)
    return false
  end
  local authParameters, parameterError = consentAuthorizationParameters(consentContent)
  if not authParameters then
    MM.printStatus("MLP: " .. parameterError)
    return false
  end

  if not establishKundenportalSession(authParameters) then
    MM.printStatus("MLP: Kundenportal-Session konnte nicht hergestellt werden.")
    return false
  end

  local iframeUrl = fetchVueIframeUrl()
  if not iframeUrl then
    MM.printStatus("MLP: Vue-iframeUrl nicht verfügbar.")
    return false
  end

  if not establishVueSession(iframeUrl) then
    MM.printStatus("MLP: Vue-Session konnte nicht initialisiert werden.")
    return false
  end

  return isAuthenticated()
end

function performJweLogin(username, password, interactive)
  -- 1. Hole den PIN-Verschlüsselungsschlüssel (OAuth-authorize + init-ui)
  mlpDebugLog("MLP-DEBUG: performJweLogin startet")
  local publicKey, pinNonce, keyError = fetchPinEncryptionKey()
  if not publicKey then
    return { success = false, error = keyError }
  end
  mlpDebugLog("MLP-DEBUG: Public Key erfolgreich geholt, Typ=" .. type(publicKey))

  -- 2. Bereite Login-Payload vor
  -- Klartext wie der Browser (Login-Bundle, pinEncryptionService.encrypt):
  -- netkey = VR-NetKey/Login-Name, pin = Passwort, nonce = pinEncryptionNonce aus init-ui.
  local loginPayload = {
    netkey = username,
    pin = password,
    nonce = pinNonce
  }

  -- 3. Generiere JWE
  mlpDebugLog("MLP-DEBUG: Generiere JWE mit PublicKey...")
  local jwe, errorMsg = generateJwe(loginPayload, publicKey)
  if not jwe then
    MM.printStatus("MLP: JWE-Generierung fehlgeschlagen: " .. (errorMsg or "Unbekannter Fehler"))
    return {
      success = false,
      error = errorMsg or "JOSE",
      cryptoIncomplete = true,
    }
  end
  mlpDebugLog("MLP-DEBUG: JWE erfolgreich generiert, Länge=" .. #jwe)

  MM.printStatus("MLP: JWE generiert, sende Authentifizierung...")

  local headers = {
    ["Content-Type"] = "application/jose",
    ["Accept"] = "application/json",
    ["Origin"] = "https://financepilot-pe.mlp.de",
    ["Referer"] = "https://financepilot-pe.mlp.de/"
  }

  local cookieHeader = buildCookieHeader(false)
  if cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  local content = connection:request(
    "POST",
    CONSTANTS.authBaseUrl .. CONSTANTS.loginEndpoint,
    jwe,
    "application/jose",
    headers
  )

  if not content then
    return { success = false, error = "Keine Antwort vom Token-Server." }
  end

  collectSessionCookies()

  local tanResult = browserDetectionLoginResult(content, interactive)
  if tanResult then
    return tanResult
  end

  local loginResult = parseLoginResponse(content)
  if not loginResult.success then
    return loginResult
  end

  return completeAcceptedLogin()
end

function performPlaintextLogin(username, password, interactive)
  local started, startError = startPortalAuthorization()
  if not started then
    return { success = false, error = startError }
  end

  local loginPayload = {
    username = username,
    password = password,
    deviceInfo = { deviceType = "BROWSER", userAgent = CONSTANTS.userAgent }
  }

  local jsonBody = encodeJson(loginPayload)
  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json, text/plain, */*",
    ["Origin"] = "https://financepilot-pe.mlp.de",
    ["Referer"] = "https://financepilot-pe.mlp.de/"
  }

  local cookieHeader = buildCookieHeader(false)
  if cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  local content = connection:request(
    "POST",
    CONSTANTS.authBaseUrl .. "/services_auth/auth-backend/api/authentication/login",
    jsonBody,
    "application/json",
    headers
  )

  if not content then
    return { success = false, error = "Keine Antwort vom Login-Server." }
  end

  collectSessionCookies()

  local tanResult = browserDetectionLoginResult(content, interactive)
  if tanResult then
    return tanResult
  end
  if content:find('"error":') and content:find("403") then
    return { success = false, error = "Der Login-Server hat die Anfrage abgelehnt (403). Bitte später erneut versuchen." }
  end

  local response = parseJson(content)
  if not response then
    if isAuthenticated() then
      return { success = true }
    end
    return { success = false, error = "Ungültige Server-Antwort." }
  end

  if response.error or response.errorMessage then
    return { success = false, error = response.errorMessage or response.error }
  end

  if response.success or response.authenticated or authProcessCompleted(response) then
    return completeAcceptedLogin()
  end
  if isAuthenticated() then
    return { success = true }
  end

  return { success = false, error = "Login-Status unbekannt." }
end

function urlEncode(str)
  if not str then return "" end
  str = tostring(str)
  -- Ersetze nicht-alphanumerische Zeichen (außer -_.~) mit %XX
  return str:gsub("([^%w%-%.%_%~])", function(c)
    return string.format("%%%02X", string.byte(c))
  end)
end

-- Der Server verlangt nach dem Passwort-Login die Browser-Erkennung mit SecureGo-Plus-Freigabe.
-- Die Schrittfolge entspricht dem Browser-Ablauf aus der HAR.
function requiresBrowserDetectionTan(content)
  local response = parseJson(content)
  local auth = type(response) == "table" and response.authenticationProcessResponse or nil
  local nextStep = type(auth) == "table" and auth.nextAuthenticationProcessStep or nil
  if type(nextStep) ~= "table" or type(nextStep.actions) ~= "table" then
    return false
  end
  for _, action in ipairs(nextStep.actions) do
    if action.stepType == "START_TAN_PROCESS_FOR_BROWSER_DETECTION_AUTH" then
      return true
    end
  end
  return false
end

-- Liefert das Login-Ergebnis, wenn die Browser-Erkennung nötig ist; sonst nil.
-- Ohne Benutzerinteraktion (Hintergrund-Refresh) startet keine SecureGo-Freigabe; der Login bricht ab.
function browserDetectionLoginResult(content, interactive)
  if not requiresBrowserDetectionTan(content) then
    return nil
  end
  if not interactive then
    return { success = false, error = "MLP: SecureGo-Freigabe nötig. Bitte den Login in MoneyMoney manuell starten." }
  end
  local tanError = startBrowserDetectionTan()
  if tanError then
    return { success = false, error = tanError }
  end
  return { success = false, requiresBrowserTan = true }
end

-- Ruft einen Schritt des Auth-Prozesses auf. Liefert die geparste Antwort oder nil plus Fehlermeldung.
function callAuthProcess(method, path, body)
  local headers = {
    ["Accept"] = "application/json",
    ["Origin"] = "https://financepilot-pe.mlp.de",
    ["Referer"] = "https://financepilot-pe.mlp.de/"
  }
  local hasBody = body ~= nil and body ~= ""
  if hasBody then
    headers["Content-Type"] = "application/json"
  end
  local cookieHeader = buildCookieHeader(false)
  if cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  local content = connection:request(
    method,
    CONSTANTS.authBaseUrl .. path,
    body,
    hasBody and "application/json" or nil,
    headers
  )
  if not content then
    return nil, "Keine Antwort vom Server (" .. path .. ")."
  end
  collectSessionCookies()

  local response = parseJson(content)
  if not response then
    return nil, "Ungültige Antwort vom Server (" .. path .. ")."
  end
  return response
end

function authProcessCompleted(response)
  local auth = response.authenticationProcessResponse
  return type(auth) == "table" and auth.authenticationProcessCompleted == true
end

function hasSecureGoPlusMethod(delivery)
  if type(delivery.tanVerfahren) ~= "table" then
    return false
  end
  for _, method in ipairs(delivery.tanVerfahren) do
    if method.typ == "SECUREGO_PLUS" then
      return true
    end
  end
  return false
end

-- Schritt 1: TAN-Verfahren prüfen und die SecureGo-Freigabe anstoßen.
-- Liefert nil bei Erfolg, sonst eine Fehlermeldung.
function startBrowserDetectionTan()
  MM.printStatus("MLP: Starte Browser-Erkennung mit SecureGo Plus...")

  local methods, err = callAuthProcess("POST", CONSTANTS.tanMethodsCheckPath, "{}")
  if not methods then
    return err
  end
  if methods.hasTanMethods ~= true then
    return "MLP: Für diesen Zugang ist kein TAN-Verfahren hinterlegt."
  end

  local started
  started, err = callAuthProcess("POST", CONSTANTS.browserDetectionStartPath, '{"locale":"de-DE"}')
  if not started then
    return err
  end
  local current = started.authenticationProcessResponse
    and started.authenticationProcessResponse.resultOfCurrentAuthenticationProcessStep
  local tanProcessId = type(current) == "table" and current.tanProzessId or nil
  if type(tanProcessId) ~= "string" or tanProcessId == "" then
    return "MLP: TAN-Prozess-ID fehlt in der Antwort."
  end

  local delivery
  delivery, err = callAuthProcess("POST", CONSTANTS.tanDeliveryPath, encodeJson({ tanProzessId = tanProcessId }))
  if not delivery then
    return err
  end
  if not hasSecureGoPlusMethod(delivery) then
    return "MLP: SecureGo Plus ist für diesen Zugang nicht verfügbar."
  end

  local approval
  approval, err = callAuthProcess(
    "POST",
    CONSTANTS.directApprovalPath,
    encodeJson({ tanProzessId = tanProcessId, sprachschluessel = "de-DE" })
  )
  if not approval then
    return err
  end
  if approval.status ~= "DIREKTFREIGABE_OFFEN" or type(approval.transaktionsIdDirektfreigabe) ~= "string" then
    return "MLP: SecureGo-Freigabe konnte nicht gestartet werden (Status: " .. tostring(approval.status) .. ")."
  end

  -- Der Browser fragt den Freigabestatus mit der tanProzessId ab (HAR), nicht mit transaktionsIdDirektfreigabe.
  session.browserTanProcessId = tanProcessId
  return nil
end

-- Wartet ohne Eingabe in MoneyMoney auf die Freigabe in der SecureGo-Plus-App.
-- Liefert nil, sobald die Freigabe bestätigt ist, sonst eine Fehlermeldung.
-- Die Abfrage nutzt die tanProzessId, wie der Browser (siehe HAR).
function waitForSecureGoApproval(tanProcessId, maxAttempts)
  MM.printStatus("MLP: Warte auf die Freigabe in der SecureGo-Plus-App...")
  local consecutiveErrors = 0
  for attempt = 1, maxAttempts do
    local status, err = callAuthProcess("GET", CONSTANTS.directApprovalPath .. "/" .. tanProcessId, nil)
    if not status then
      -- Ein kurzer Netzwerkfehler darf die Freigabe nicht abbrechen; erst mehrere Fehler in Folge.
      consecutiveErrors = consecutiveErrors + 1
      if consecutiveErrors >= CONSTANTS.secureGoMaxConsecutiveErrors then
        return err
      end
    else
      consecutiveErrors = 0
      if status.status == "DIREKTFREIGABE_BESTAETIGT" then
        return nil
      end
      if status.status ~= "DIREKTFREIGABE_OFFEN" then
        return "SecureGo-Freigabe nicht bestätigt (Status: " .. tostring(status.status) .. ")."
      end
    end
    if attempt < maxAttempts then
      MM.sleep(CONSTANTS.secureGoPollSeconds)
    end
  end
  return "SecureGo-Freigabe wurde in der Wartezeit nicht bestätigt. Bitte den Login erneut starten."
end

-- Wartet auf die SecureGo-Freigabe, schließt die Browser-Erkennung ab und markiert den Browser als
-- vertrauenswürdig (useBrowserDetection = true, wie "Trust this browser" im Browser).
function completeBrowserDetectionTan()
  local tanProcessId = session.browserTanProcessId
  session.browserTanProcessId = nil
  if not tanProcessId then
    return CONSTANTS.mfaSessionExpired
  end

  local approvalError = waitForSecureGoApproval(tanProcessId, CONSTANTS.secureGoPollAttempts)
  if approvalError then
    return approvalError
  end

  local termination, err = callAuthProcess("POST", CONSTANTS.browserDetectionTerminationPath, "")
  if not termination then
    return err
  end
  if not authProcessCompleted(termination) then
    return "MLP: Browser-Erkennung konnte nicht abgeschlossen werden."
  end

  local choice
  choice, err = callAuthProcess("POST", CONSTANTS.browserDetectionChoosePath, '{"useBrowserDetection":true}')
  if not choice then
    return err
  end
  if not authProcessCompleted(choice) then
    return "MLP: Browser konnte nicht als vertrauenswürdig gespeichert werden."
  end

  if not completePostLoginFlow() then
    return "Login erfolgreich, aber Kundenportal-Session konnte nicht hergestellt werden."
  end
  persistSessionCookies(rawget(_G, "LocalStorage"))
  if loadContracts() then
    return nil
  end
  return "Login erfolgreich, aber keine Versicherungsverträge gefunden."
end

function collectSessionCookies()
  local success, cookies = pcall(function()
    return connection:getCookies()
  end)
  if success and cookies and cookies ~= "" then
    collectSessionCookiesFromText(cookies)
  end
end

function collectSessionCookiesFromText(cookieText)
  if not cookieText then return end

  local jsession = cookieText:match("JSESSIONID=([^;,%s]+)")
  if jsession then session.sessionCookies.JSESSIONID = jsession end

  local casSession = cookieText:match("CAS_SESSION=([^;,%s]+)")
  if casSession then session.sessionCookies.CAS_SESSION = casSession end

  local casSSession = cookieText:match("CAS_S_SESSION=([^;,%s]+)")
  if casSSession then session.sessionCookies.CAS_S_SESSION = casSSession end

  local casDevice = cookieText:match("CAS_DEVICE_SESSION=([^;,%s]+)")
  if casDevice then session.sessionCookies.CAS_DEVICE_SESSION = casDevice end

  for vuSession in cookieText:gmatch("VUSESSIONID=([^;,%s]+)") do
    if not session.sessionCookies.VUSESSIONID or session.sessionCookies.VUSESSIONID == "" then
      session.sessionCookies.VUSESSIONID = vuSession
    elseif session.sessionCookies.VUSESSIONID2 == nil or session.sessionCookies.VUSESSIONID2 == "" then
      session.sessionCookies.VUSESSIONID2 = vuSession
    end
  end

  local bigipServer = cookieText:match("BIGipServervue%.mlp%.de=([^;,%s]+)")
  if bigipServer then session.sessionCookies.BIGipServervue_mlp_de = bigipServer end
end

function cookieWireName(storageName)
  if storageName == "VUSESSIONID2" then
    return "VUSESSIONID"
  end
  if storageName == "BIGipServervue_mlp_de" then
    return "BIGipServervue.mlp.de"
  end
  return storageName
end

function buildCookieHeader(forVueApi)
  if forVueApi == nil then forVueApi = true end
  if forVueApi == false then
    -- Für Auth-/SecureGo-Endpoints muss der komplette Cookie-Jar
    -- (inkl. "trusted browser"-Cookies) mitgesendet werden.
    if connection and type(connection.getCookies) == "function" then
      local cookies = connection:getCookies()
      return cookies or ""
    end
    return ""
  end
  local parts = {}

  if forVueApi then
    local vuSessionId = session.sessionCookies.VUSESSIONID
    if vuSessionId and vuSessionId ~= "" then
      table.insert(parts, "VUSESSIONID=" .. vuSessionId)
      if session.sessionCookies.VUSESSIONID2 and session.sessionCookies.VUSESSIONID2 ~= "" then
        table.insert(parts, "VUSESSIONID=" .. session.sessionCookies.VUSESSIONID2)
      end
    end
    for name, value in pairs(session.sessionCookies) do
      if name:find("^BIGipServervue") or name:find("^TS01") then
        table.insert(parts, cookieWireName(name) .. "=" .. value)
      end
    end
  else
    for name, value in pairs(session.sessionCookies) do
      if not name:find("^VUSESSIONID") and not name:find("^BIGipServervue") then
        table.insert(parts, name .. "=" .. value)
      end
    end
  end

  return table.concat(parts, "; ")
end

-- Ruft den Consent-Schritt auf. Liefert die Antwort oder nil plus Fehlermeldung.
function callConsent()
  local authCookieHeader = buildCookieHeader(false)
  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json, text/plain, */*",
    ["Accept-Language"] = "de-DE,de;q=0.9",
    ["Origin"] = "https://financepilot-pe.mlp.de",
    ["Referer"] = "https://financepilot-pe.mlp.de/",
    ["Sec-Fetch-Site"] = "same-origin",
    ["Sec-Fetch-Mode"] = "cors",
    ["Sec-Fetch-Dest"] = "empty",
    ["User-Agent"] = CONSTANTS.userAgent
  }
  if authCookieHeader ~= "" then
    headers["Cookie"] = authCookieHeader
  end

  local payload = '{"useBrowserDetection":false}'

  local success, contentOrError = pcall(function()
    return connection:request(
      "POST",
      CONSTANTS.authBaseUrl .. CONSTANTS.consentEndpoint,
      payload,
      "application/json",
      headers
    )
  end)

  if not success then
    return nil, "Consent-Aufruf fehlgeschlagen: " .. tostring(contentOrError)
  end
  if not contentOrError then
    return nil, "Consent-Aufruf ohne Antwort."
  end
  collectSessionCookies()
  return contentOrError
end

function tryConsentCall()
  return callConsent() ~= nil
end

-- Liest die OAuth-Parameter (code, state, iss) aus der Consent-Antwort als Query-String.
function consentAuthorizationParameters(content)
  local response = parseJson(content)
  local post = type(response) == "table" and response.postAuthenticationProcessResponse or nil
  local step = type(post) == "table" and post.resultOfCurrentPostAuthenticationProcessStep or nil
  local parameter = type(step) == "table" and step.parameter or nil
  if type(parameter) ~= "string" or not parameter:find("code=", 1, true) then
    return nil, "Consent-Antwort enthält keinen Autorisierungscode."
  end
  return parameter
end

function tryContractListAuth(cookieHeader)
  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json, text/plain, */*",
    ["Accept-Language"] = "de-DE,de;q=0.9",
    ["Referer"] = CONSTANTS.vueApiBase .. "/vu/client/",
    ["Sec-Fetch-Site"] = "same-origin",
    ["Sec-Fetch-Mode"] = "cors",
    ["Sec-Fetch-Dest"] = "empty",
    ["User-Agent"] = CONSTANTS.userAgent
  }
  if cookieHeader and cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  local success, contentOrError = pcall(function()
    return connection:request("GET", CONSTANTS.vueApiBase .. CONSTANTS.vueContractListPath, nil, nil, headers)
  end)

  if success and contentOrError then
    if contentOrError:find("403") or contentOrError:find("error") or contentOrError:find("<!doctype") then
      if tryConsentCall() then
        success, contentOrError = pcall(function()
          return connection:request("GET", CONSTANTS.vueApiBase .. CONSTANTS.vueContractListPath, nil, nil, headers)
        end)
      end
    end

    local data = parseJson(contentOrError)
    if (data and data.contractList) or (contentOrError and contentOrError:find('"contractList"')) then
      session.contractListContent = contentOrError
      return true
    end
  elseif tryConsentCall() then
    success, contentOrError = pcall(function()
      return connection:request("GET", CONSTANTS.vueApiBase .. CONSTANTS.vueContractListPath, nil, nil, headers)
    end)
    if success and contentOrError then
      local data = parseJson(contentOrError)
      if (data and data.contractList) or (contentOrError and contentOrError:find('"contractList"')) then
        session.contractListContent = contentOrError
        return true
      end
    end
  end

  -- Server hat geantwortet, aber ohne Vertragsliste: Sitzung ungültig.
  -- Keine Antwort (Fehler der Anfrage): Zustand unbekannt, nil.
  if success and type(contentOrError) == "string" then
    return false
  end
  return nil
end

-- true: Sitzung gültig. false: Server meldet Sitzung als ungültig. nil: keine Antwort.
function isAuthenticated()
  local hasVuSession = session.sessionCookies.VUSESSIONID and session.sessionCookies.VUSESSIONID ~= ""

  if hasVuSession then
    return tryContractListAuth(buildCookieHeader(true))
  end

  -- HttpOnly-Cookies (z. B. VUSESSIONID) sind in getCookies() unsichtbar,
  -- werden aber von der persistierten Connection automatisch mitgesendet.
  return tryContractListAuth(nil)
end

-- Übernimmt die Vertragsliste aus einer vue.mlp.de-Antwort. true, wenn mindestens ein Vertrag gefunden wurde.
function applyVueContractList(content)
  local apiData = parseJson(content)
  if not (apiData and apiData.contractList) then
    return false
  end
  local contracts = parseVueContracts(apiData.contractList)
  if #contracts == 0 then
    return false
  end
  session.contracts = contracts
  MM.printStatus("MLP: " .. #session.contracts .. " Vertrag(e) geladen.")
  return true
end

function loadContracts()
  MM.printStatus("MLP: Lade Vertragsdaten...")

  -- Hat die Session-Prüfung die Liste schon geholt, wird sie wiederverwendet (keine zweite Anfrage).
  local cachedContent = session.contractListContent
  session.contractListContent = nil
  if cachedContent and applyVueContractList(cachedContent) then
    return true
  end

  local vueCookieHeader = buildCookieHeader(true)
  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json, text/plain, */*",
    ["Accept-Language"] = "de-DE,de;q=0.9",
    ["Referer"] = CONSTANTS.vueApiBase .. "/vu/client/",
    ["Sec-Fetch-Site"] = "same-origin",
    ["Sec-Fetch-Mode"] = "cors",
    ["Sec-Fetch-Dest"] = "empty",
    ["User-Agent"] = CONSTANTS.userAgent
  }
  if vueCookieHeader ~= "" then
    headers["Cookie"] = vueCookieHeader
  end

  local success, content = pcall(function()
    return connection:request("GET", CONSTANTS.vueApiBase .. CONSTANTS.vueContractListPath, nil, nil, headers)
  end)

  if success and content then
    if content:find("403") or content:find("error") or content:find("<!doctype") then
      if tryConsentCall() then
        success, content = pcall(function()
          return connection:request("GET", CONSTANTS.vueApiBase .. CONSTANTS.vueContractListPath, nil, nil, headers)
        end)
      end
    end
  elseif not success or not content then
    if tryConsentCall() then
      success, content = pcall(function()
        return connection:request("GET", CONSTANTS.vueApiBase .. CONSTANTS.vueContractListPath, nil, nil, headers)
      end)
    end
  end

  if success and content and applyVueContractList(content) then
    return true
  end

  local authCookieHeader = buildCookieHeader(false)
  headers["Cookie"] = authCookieHeader
  content = connection:get(CONSTANTS.baseUrl .. "/api/vertraege", nil, headers)
  if content then
    local apiData = parseJson(content)
    if apiData then
      local contracts = parseApiContracts(apiData)
      if #contracts > 0 then
        session.contracts = contracts
        MM.printStatus("MLP: " .. #session.contracts .. " Vertrag(e) geladen.")
        return true
      end
    end
  end

  return false
end

function parseVueContracts(contractList)
  local contracts = {}
  if type(contractList) ~= "table" then return contracts end
  for _, item in ipairs(contractList) do
    if type(item) == "table" then
      local contract = mapVueContractToInternal(item)
      if contract then table.insert(contracts, contract) end
    end
  end
  return contracts
end

function parseApiContracts(apiData)
  local contracts = {}
  local items = apiData.contracts or apiData.vertraege or apiData.items or apiData
  if type(items) ~= "table" then return contracts end
  if #items == 0 and (items.id or items.number) then items = { items } end
  for _, item in ipairs(items) do
    if type(item) == "table" then
      local contract = mapApiContractToInternal(item)
      if contract then table.insert(contracts, contract) end
    end
  end
  return contracts
end

function mapVueContractToInternal(item)
  if not item then return nil end
  local contractNumber = item.number or item.id
  if not contractNumber then return nil end

  local contractType, tariff
  if item.posTypeList and type(item.posTypeList) == "table" and #item.posTypeList > 0 then
    local bestPos = item.posTypeList[1]
    for _, posType in ipairs(item.posTypeList) do
      if posType.type == "HV" then
        bestPos = posType
        break
      elseif posType.type == "BS" and bestPos.type ~= "HV" then
        bestPos = posType
      end
    end
    contractType = bestPos.contractType or bestPos.posType
    tariff = bestPos.posTypeShort
  end

  local shareValue = tonumber(item.shareValue)
  local contribution = tonumber(item.contribution)
  local specificAttributes = {}
  if contribution then
    specificAttributes.netContribution = {
      value = contribution,
      displayValue = formatCurrency(contribution)
    }
  end

  return {
    id = item.id or contractNumber,
    number = contractNumber,
    company = {
      shortName = item.companyShortName,
      longName = item.companyLongName or item.companyShortName
    },
    contribution = contribution,
    validFrom = item.created,
    state = item.state,
    tariff = tariff,
    contractType = contractType,
    shareValue = shareValue,
    currency = "EUR",
    specificAttributes = specificAttributes
  }
end

function mapApiContractToInternal(item)
  if not item then return nil end
  local company = item.company or {}
  local companyShort = company.shortName or company.name
  local contractNumber = item.number or item.contractNumber or item.vertragsnummer or item.id
  if not contractNumber then return nil end

  local contractType = item.contractType or item.vertragsArt or item.posType or item.type
  local shareValue = tonumber(item.shareValue or item.rueckkaufswert or item.value)
  local contribution = tonumber(item.contribution or item.beitrag or item.premium)

  local specificAttrs = item.specificAttributes or item.details or {}
  local deathSum = specificAttrs.deathInsuredSum or specificAttrs.todesfallsumme
  local lifeSum = specificAttrs.lifeInsuredSum or specificAttrs.erlebensfallsumme
  local endOfPayment = specificAttrs.endOfPayment or specificAttrs.beitragszahlungsende

  local normalizedAttributes = {
    deathInsuredSum = normalizeAttributeValue(deathSum),
    lifeInsuredSum = normalizeAttributeValue(lifeSum),
    endOfPayment = normalizeAttributeValue(endOfPayment)
  }
  if contribution then
    normalizedAttributes.netContribution = {
      value = contribution,
      displayValue = formatCurrency(contribution)
    }
  end

  return {
    id = item.id or contractNumber,
    number = contractNumber,
    company = { shortName = companyShort, longName = company.longName or companyShort },
    contribution = contribution,
    validFrom = item.validFrom or item.beginn,
    validUntil = item.validUntil or item.ende,
    state = item.state or item.status,
    tariff = item.tariff or item.tarif,
    contractType = contractType,
    shareValue = shareValue,
    currency = item.currency,
    specificAttributes = normalizedAttributes
  }
end

function normalizeAttributeValue(attr)
  if not attr then return nil end
  if type(attr) == "table" then
    return {
      value = attr.value or attr.wert,
      displayValue = attr.displayValue or attr.anzeigeWert or tostring(attr.value or attr.wert)
    }
  end
  return { value = attr, displayValue = tostring(attr) }
end

function ListAccounts(knownAccounts)
  if not session.contracts or #session.contracts == 0 then
    return "Keine Vertragsdaten verfügbar."
  end

  local accounts = {}
  for _, contract in ipairs(session.contracts) do
    if isPortfolioContract(contract) then
      table.insert(accounts, createAccountFromContract(contract))
    end
  end
  if #accounts == 0 then
    return "Keine bewertbaren Versicherungsverträge verfügbar."
  end
  return accounts
end

function isPortfolioContract(contract)
  return type(contract) == "table" and tonumber(contract.shareValue) ~= nil
end

function createAccountFromContract(contract)
  if type(contract.company) ~= "table"
      or type(contract.company.shortName) ~= "string"
      or contract.company.shortName == "" then
    error("MLP Versicherungen: Versicherer fehlt in den Vertragsdaten.")
  end
  if type(contract.currency) ~= "string" or contract.currency == "" then
    error("MLP Versicherungen: Währung fehlt in den Vertragsdaten.")
  end
  local accountNumber = contract.number or contract.id
  if type(accountNumber) ~= "string" or accountNumber == "" then
    error("MLP Versicherungen: Vertragsnummer fehlt in den Vertragsdaten.")
  end
  local companyName = contract.company.shortName
  local contractNumber = contract.number or accountNumber
  local tariff = contract.tariff or ""
  local endDate = ""
  if contract.specificAttributes and contract.specificAttributes.endOfPayment then
    endDate = formatDateDisplay(contract.specificAttributes.endOfPayment.value)
  end

  local displayName = companyName
  if contractNumber ~= "" then displayName = displayName .. " " .. contractNumber end
  if tariff ~= "" then displayName = displayName .. " (" .. tariff .. ")" end
  if endDate ~= "" then displayName = displayName .. " | Beitrag bis " .. endDate end

  return {
    name = displayName,
    accountNumber = accountNumber,
    portfolio = true,
    currency = contract.currency,
    type = AccountTypePortfolio,
    bankCode = contract.company.shortName
  }
end

function RefreshAccount(account, since)
  if not account or not account.accountNumber then
    error("MLP Versicherungen: Kontoabruf ohne Kontonummer nicht möglich.")
  end
  local contract = findContractByNumber(account.accountNumber)
  if not contract then
    error("MLP Versicherungen: Kontoabruf für unbekannten Vertrag nicht möglich.")
  end

  local shareValue = tonumber(contract.shareValue)
  if not shareValue then
    error("MLP Versicherungen: Vertragswert fehlt oder ist ungültig.")
  end
  local currency = contract.currency
  if type(currency) ~= "string" or currency == "" then
    error("MLP Versicherungen: Vertragswährung fehlt.")
  end
  local security = {
    name = buildSecurityName(contract),
    isin = "",
    securityNumber = contract.number or "",
    quantity = 1,
    price = shareValue,
    currencyOfPrice = currency,
    amount = shareValue,
    currencyOfOriginalAmount = currency,
    purchasePrice = calculateTotalContributions(contract)
  }

  return { balance = shareValue, securities = { security } }
end

function findContractByNumber(accountNumber)
  if not session.contracts then return nil end
  for _, contract in ipairs(session.contracts) do
    if contract.number == accountNumber or contract.id == accountNumber then return contract end
  end
  return nil
end

function buildSecurityName(contract)
  local parts = { getContractTypeName(contract.contractType) }
  if contract.tariff and contract.tariff ~= "" then table.insert(parts, "Tarif: " .. contract.tariff) end
  if contract.specificAttributes then
    local ds = contract.specificAttributes.deathInsuredSum
    if ds and ds.displayValue then table.insert(parts, "Todesfall: " .. ds.displayValue) end
    local ls = contract.specificAttributes.lifeInsuredSum
    if ls and ls.displayValue then table.insert(parts, "Erlebensfall: " .. ls.displayValue) end
  end
  if contract.contribution and contract.contribution > 0 then
    table.insert(parts, "Beitrag/Monat: " .. formatCurrency(contract.contribution))
  end
  return table.concat(parts, " | ")
end

local CONTRACT_TYPE_NAMES = {
  FLV = "Fondsgebundene Lebensversicherung",
  KLV = "Kapitallebensversicherung",
  LV = "Lebensversicherung",
  REN = "Rentenversicherung",
  BU = "Berufsunfähigkeitsversicherung",
  BUZ = "Berufsunfähigkeits-Zusatz",
  BAV = "Betriebliche Altersvorsorge",
  RIESTER = "Riester-Rente",
  RUERUP = "Rürup-Rente",
  DEFAULT = "Vorsorgevertrag"
}

function getContractTypeName(contractType)
  return CONTRACT_TYPE_NAMES[contractType or "DEFAULT"] or CONTRACT_TYPE_NAMES.DEFAULT
end

function calculateTotalContributions(contract)
  if not contract.contribution or contract.contribution <= 0 then return nil end
  local day, month, year = parseIsoDate(contract.validFrom)
  if not year then return nil end
  local currentDate = os.date("*t")
  local monthsElapsed = (currentDate.year - year) * 12 + (currentDate.month - month)
  return contract.contribution * math.max(0, monthsElapsed)
end

function EndSession()
  session = { contracts = {}, username = nil, password = nil, browserTanProcessId = nil, sessionCookies = {} }
  MM.printStatus("MLP: Session beendet.")
end

function trim(text)
  return text and (text:gsub("^%s*(.-)%s*$", "%1")) or ""
end

function formatCurrency(value)
  if not value then return "0,00 €" end
  local formatted = string.format("%.2f", value):gsub("(%d)%.(%d%d)$", "%1,%2")
  local intPart, decPart = formatted:match("^(%d+),(%d%d)$")
  if intPart then
    intPart = intPart:reverse():gsub("(%d%d%d)", "%1."):reverse():gsub("^%.", "")
    formatted = intPart .. "," .. decPart
  end
  return formatted .. " €"
end

function parseIsoDate(dateStr)
  if not dateStr then return nil end
  local y, m, d = dateStr:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)")
  return d and tonumber(d), m and tonumber(m), y and tonumber(y)
end

function formatDateDisplay(dateStr)
  local d, m, y = parseIsoDate(dateStr)
  return d and string.format("%02d.%02d.%04d", d, m, y) or dateStr or ""
end

function encodeJson(obj)
  if JSON then
    local success, result = pcall(function() return JSON():set(obj):json() end)
    if success and result then return result end
  end
  if type(obj) == "table" then
    local isArray, parts = #obj > 0, {}
    if isArray then
      for _, v in ipairs(obj) do table.insert(parts, encodeJson(v)) end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      for k, v in pairs(obj) do
        local val = type(v) == "table" and encodeJson(v) or (type(v) == "string" and string.format("%q", v) or (type(v) == "number" and tostring(v) or (type(v) == "boolean" and tostring(v) or "null")))
        table.insert(parts, string.format("%q", k) .. ":" .. val)
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  end
  return type(obj) == "string" and string.format("%q", obj) or tostring(obj)
end

function parseJson(jsonStr)
  if not jsonStr or jsonStr == "" then return nil end
  jsonStr = trim(jsonStr)
  if not jsonStr:match("^[%{%[]") then return nil end
  if not JSON then
    return nil
  end
  local success, result = pcall(function() return JSON(jsonStr):dictionary() end)
  if success and result then return result end
  success, result = pcall(function() return JSON(jsonStr):array() end)
  if success and result then return result end
  return nil
end

