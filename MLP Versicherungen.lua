-- Plugin Homepage: https://github.com/rosch100/MLP-Versicherungen-MoneyMoney
-- MLP Versicherungen — MoneyMoney Web Banking Extension
-- https://kundenportal.mlp.de
-- API: https://moneymoney.app/api/webbanking/
--
-- Authentifizierung: Cookie-Import (VUSESSIONID) — Beta 0.91
-- Version: 0.91 (Beta)

WebBanking{
  version     = 0.92,
  url         = "https://kundenportal.mlp.de",
  services    = {"MLP Versicherungen"},
  description = "MLP Versicherungen — Beta (Cookie-Import)"
}

local CONSTANTS = {
  baseUrl           = "https://kundenportal.mlp.de",
  authBaseUrl       = "https://financepilot-pe.mlp.de",
  loginPageUrl      = "https://kundenportal.mlp.de/login",
  userAgent         = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15",
  oidcConfigPath    = "/services_auth/oauth2/.well-known/openid-configuration",
  jwksFallbackPath  = "/services_auth/oauth2/jwks.json",
  loginEndpoint     = "/services_auth/auth-backend/api/authentication/login",
  consentEndpoint   = "/services_auth/auth-backend/api/consent/execution",
  vueApiBase        = "https://vue.mlp.de",
  vueTokenEndpoint  = "/vu/api/token",
  vueContractListPath = "/vu/api/contract/list",
  vueClientPath     = "/vu/client/index.html",
  portalVuApi       = "/api/app/vu",
  portalOkpLogin    = "/api/okp/login?backUrl=https://kundenportal.mlp.de/kunde",
  mfaSessionExpired = "MFA-Session abgelaufen. Bitte neu einloggen.",
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
  state = nil,
  username = nil,
  mfaToken = nil,
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

function base64UrlDecode(encoded)
  if not encoded or encoded == "" then return "" end
  if type(MM.base64urldecode) == "function" then
    return MM.base64urldecode(encoded)
  end
  return ""
end

function generateRandomBytes(length)
  if type(MM.random) == "function" then
    return MM.random(length)
  end
  error("MLP Versicherungen: MM.random ist für kryptografisch sichere Zufallsdaten erforderlich.")
end

function sha256(data)
  if type(MM.sha256) == "function" then
    return MM.sha256(data)
  end
  return nil
end

-- ============================================================================
-- JWE Compact Serialization (RSA-OAEP-512 + A256GCM)
-- ============================================================================

function canUseA256Gcm()
  return type(MM.aes256gcm) == "function" or type(MM.aesgcm) == "function"
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
  if type(MM.aes256gcm) == "function" then
    local ok, ciphertext, tag = pcall(function()
      if aad then
        return MM.aes256gcm(key, iv, plaintext, aad)
      end
      return MM.aes256gcm(key, iv, plaintext)
    end)
    if ok and type(ciphertext) == "string" then
      if type(tag) == "string" then
        return ciphertext, tag
      end
      return ciphertext, nil
    end
  end
  if type(MM.aesgcm) == "function" then
    local ok, ciphertext, tag = pcall(function()
      return MM.aesgcm(key, iv, plaintext, aad)
    end)
    if ok and type(ciphertext) == "string" then
      return ciphertext, tag
    end
  end
  return nil, nil
end

function generateJwe(payload, publicKey)
  mlpDebugLog("MLP-DEBUG: generateJwe startet, prüfe Krypto-Funktionen...")
  if not (type(MM.random) == "function" and
          type(MM.base64urlencode) == "function" and
          type(MM.rsaEncrypt) == "function") then
    mlpDebugLog("MLP-DEBUG: Fehlende Krypto-Funktionen!")
    return nil, "Kryptografische Funktionen nicht verfügbar. Cookie-Import erforderlich."
  end
  if not canUseA256Gcm() then
    mlpDebugLog("MLP-DEBUG: MM.aes256gcm nicht verfügbar!")
    return nil, "A256GCM nicht verfügbar (MM.aes256gcm fehlt). Cookie-Import erforderlich."
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

function jsonRequestHeaders()
  local headers = {
    ["Accept"] = "application/json",
    ["User-Agent"] = CONSTANTS.userAgent,
    ["Origin"] = "https://financepilot-pe.mlp.de",
    ["Referer"] = "https://financepilot-pe.mlp.de/"
  }

  local cookieHeader = buildCookieHeader(false)
  if cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  return headers
end

function isAuthErrorPayload(content)
  if type(content) ~= "string" or content == "" then
    return true
  end
  if content:find("RBAC:") then
    return true
  end
  if content:find('"httpStatus"%s*:%s*"UNAUTHORIZED"') then
    return true
  end
  if content:find('"httpStatusCode"%s*:%s*401') then
    return true
  end
  if content:find('"httpStatusCode"%s*:%s*403') then
    return true
  end
  return false
end

function fetchOidcJwksUri()
  local headers = jsonRequestHeaders()
  local configUrl = CONSTANTS.authBaseUrl .. CONSTANTS.oidcConfigPath
  mlpDebugLog("MLP-DEBUG: Lade OIDC-Konfiguration: " .. configUrl)

  local content = connection:request("GET", configUrl, nil, nil, headers)
  if isAuthErrorPayload(content) then
    mlpDebugLog("MLP-DEBUG: OIDC-Konfiguration nicht verfügbar")
    return CONSTANTS.authBaseUrl .. CONSTANTS.jwksFallbackPath
  end

  local parsed = parseJson(content)
  if parsed and type(parsed.jwks_uri) == "string" and parsed.jwks_uri ~= "" then
    local allowed, allowErr = assertAllowedMlpUrl(parsed.jwks_uri)
    if allowed then
      mlpDebugLog("MLP-DEBUG: jwks_uri aus OIDC (Allowlist OK)")
      return allowed
    end
    mlpDebugLog("MLP-DEBUG: jwks_uri abgelehnt: " .. tostring(allowErr))
  end

  return CONSTANTS.authBaseUrl .. CONSTANTS.jwksFallbackPath
end

function selectEncJwkFromJwks(jwks)
  if not jwks or type(jwks.keys) ~= "table" then
    return nil
  end

  local rsaEncKey = nil
  local anyEncKey = nil

  for _, key in ipairs(jwks.keys) do
    if type(key) == "table" and key.use == "enc" then
      if key.kty == "RSA" and key.n and key.e then
        return key
      end
      if key.kty == "RSA" and not rsaEncKey then
        rsaEncKey = key
      end
      if not anyEncKey then
        anyEncKey = key
      end
    end
  end

  return rsaEncKey or anyEncKey
end

function extractPublicKeyFromJwks(jwks)
  local jwk = selectEncJwkFromJwks(jwks)
  if not jwk then
    return nil
  end

  session.publicKeyKid = jwk.kid or "default"
  mlpDebugLog("MLP-DEBUG: enc-JWK gewählt, kid=" .. tostring(jwk.kid) .. ", kty=" .. tostring(jwk.kty))
  return extractPublicKeyFromJwk(jwk)
end

function parseJwksContent(content)
  if type(content) ~= "string" or content == "" then
    return nil
  end

  if content:find("BEGIN PUBLIC KEY") then
    return content
  end

  local parsed = parseJson(content)
  if parsed and type(parsed) == "table" then
    local pub = extractPublicKeyFromJwks(parsed)
    if pub then
      return pub
    end
    if parsed.n and parsed.e then
      session.publicKeyKid = parsed.kid or "default"
      return extractPublicKeyFromJwk(parsed)
    end
  end

  if JSON then
    local ok, dict = pcall(function() return JSON(content):dictionary() end)
    if ok and type(dict) == "table" then
      local pub = extractPublicKeyFromJwks(dict)
      if pub then
        return pub
      end
    end
  end

  return nil
end

function fetchPublicKey()
  MM.printStatus("MLP: Lade öffentlichen Schlüssel für JWE...")

  if not connection then
    mlpDebugLog("MLP-DEBUG: connection ist nil!")
    return nil
  end

  local jwksUri = fetchOidcJwksUri()
  local headers = jsonRequestHeaders()

  mlpDebugLog("MLP-DEBUG: Lade JWKS: " .. jwksUri)
  local content = connection:request("GET", jwksUri, nil, nil, headers)

  if isAuthErrorPayload(content) then
    mlpDebugLog("MLP-DEBUG: JWKS-Antwort ist Fehler (Status/Payload)")
    return nil
  end

  local publicKey = parseJwksContent(content)
  if publicKey then
    mlpDebugLog("MLP-DEBUG: Public Key erfolgreich aus JWKS extrahiert")
    return publicKey
  end

  mlpDebugLog("MLP-DEBUG: Kein enc-RSA-Key im JWKS gefunden")
  return nil
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

    session.jwkModulus = n
    session.jwkExponent = e
    session.jwkKid = jwk.kid or "default"
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
  if step == 1 then
    return loginStep1(credentials, interactive)
  end

  if session.state == "awaitingMfa" then
    local canReuse, storage = restoreConnection(session.username or "")
    restorePersistedSessionCookies(storage, canReuse)
    applySessionCookiesToConnection()
    return submitMfaCode(credentials[1])
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

function applySessionCookiesToConnection()
  if not connection or type(connection.setCookie) ~= "function" then
    return
  end

  for name, value in pairs(session.sessionCookies) do
    if type(name) == "string" and type(value) == "string" and name ~= "" then
      local wireName = name
      if wireName == "VUSESSIONID2" then
        wireName = "VUSESSIONID"
      elseif wireName:find("^BIGipServervue") then
        wireName = "BIGipServervue.mlp.de"
      end
      pcall(function()
        connection:setCookie(wireName .. "=" .. value)
      end)
    end
  end
end

function tryPersistedAuth(storage)
  collectSessionCookies()

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

  session.username = username
  session.state = nil
  restorePersistedSessionCookies(storage, canReuse)

  MM.printStatus("MLP: Initialisiere Session...")

  local initContent = connection:get(CONSTANTS.authBaseUrl .. "/services_auth/auth-backend/public/session-lifetime-extension.html")
  if initContent then
    collectSessionCookies()
  end

  -- Persistierte Connection: Cookie-Jar (ggf. HttpOnly) ohne erneuten COOKIE:-Import
  if canReuse then
    local persistedResult = tryPersistedAuth(storage)
    if persistedResult ~= false then
      return persistedResult
    end
  end

  if password and password:match("^COOKIE:") then
    parseCookieString(password:sub(8))
    applySessionCookiesToConnection()
    local cookieResult = tryCookieAuth()
    if cookieResult == nil then
      persistSessionCookies(storage)
    end
    return cookieResult
  end

  if not username or username == "" or not password or password == "" then
    return tryCookieAuth()
  end

  MM.printStatus("MLP: Authentifiziere mit Username/Passwort...")
  local loginResult = performLogin(username, password)

  if loginResult.success then
    session.state = nil
    local storage = rawget(_G, "LocalStorage")
    persistSessionCookies(storage)
    if loadContracts() then
      return nil
    else
      return "Login erfolgreich, aber keine Versicherungsverträge gefunden."
    end
  end

  if loginResult.requiresMfa then
    session.state = "awaitingMfa"
    session.mfaToken = loginResult.mfaToken
    return {
      title     = "SecureGo Plus Bestätigung",
      challenge = "Bitte bestätigen Sie den Login in Ihrer SecureGo Plus App auf Ihrem Smartphone.\n\nÖffnen Sie die SecureGo Plus App und bestätigen Sie die Push-Benachrichtigung.",
      label     = "TAN (falls Push nicht funktioniert)"
    }
  end

  if isCredentialRejectionMessage(loginResult.error) then
    return LoginFailed
  end
  if loginResult.needsCookie or (loginResult.error and (loginResult.error:find("403") or loginResult.error:find("JOSE"))) then
    return tryCookieAuth()
  end
  return loginResult.error or "Login fehlgeschlagen."
end

function tryCookieAuth()
  local hasVuSession = session.sessionCookies.VUSESSIONID and session.sessionCookies.VUSESSIONID ~= ""

  if not hasVuSession then
    local cookieHeader = buildCookieHeader()
    if cookieHeader == "" then
      return "Cookie-Import erforderlich:\n\n" ..
             "1. Melden Sie sich im Browser am MLP Kundenportal an\n" ..
             "2. Öffnen Sie die Vertragsübersicht (damit vue.mlp.de geladen wird)\n" ..
             "3. DevTools → Application → Cookies → https://vue.mlp.de\n" ..
             "4. Kopieren Sie VUSESSIONID und BIGipServervue.mlp.de\n" ..
             "5. Fügen Sie sie in MoneyMoney als 'Cookies' ein (Format: Name=Wert; Name2=Wert2)"
    else
      return "Cookie-Import: VUSESSIONID fehlt\n\n" ..
             "Für die MLP Versicherungen-API wird VUSESSIONID von vue.mlp.de benötigt.\n\n" ..
             "Bitte stellen Sie sicher, dass Sie:\n" ..
             "1. Am MLP Kundenportal angemeldet sind\n" ..
             "2. Die Vertragsübersicht geöffnet haben (für vue.mlp.de Cookies)\n" ..
             "3. VUSESSIONID aus https://vue.mlp.de kopiert haben\n\n" ..
             "Hinweis: Ein reines Dashboard-HAR (nur kundenportal.mlp.de ohne vue.mlp.de) " ..
             "enthält keine VUSESSIONID. Login-HAR mit Vertragsübersicht verwenden."
    end
  end

  MM.printStatus("MLP: Versuche Authentifizierung mit Cookies...")

  if isAuthenticated() then
    local storage = rawget(_G, "LocalStorage")
    persistSessionCookies(storage)
    if loadContracts() then
      return nil
    else
      return "Authentifiziert, aber keine Versicherungsverträge gefunden."
    end
  end

  return "Cookie-Authentifizierung fehlgeschlagen.\n\n" ..
         "Mögliche Ursachen:\n" ..
         "- Cookies sind abgelaufen (Session nur kurze Zeit gültig)\n" ..
         "- VUSESSIONID fehlt oder ist ungültig\n" ..
         "- SSL-Zertifikat für vue.mlp.de nicht bestätigt\n\n" ..
         "Bitte frische Cookies aus dem Browser exportieren."
end

function performLogin(username, password)
  if canUseJweLogin() then
    MM.printStatus("MLP: Versuche JWE-verschlüsselten Login...")
    local jweResult = performJweLogin(username, password)
    if jweResult.success or jweResult.requiresMfa then
      return jweResult
    end
    if jweResult.cryptoIncomplete then
      MM.printStatus("MLP: JWE-Krypto unvollständig — Klartext-Login...")
      return performPlaintextLogin(username, password)
    end
    return jweResult
  end

  -- Username/Passwort bleibt auch ohne JWE-APIs: Klartext versuchen, sonst Cookie.
  MM.printStatus("MLP: JWE-Krypto-APIs nicht verfügbar — Klartext-Login...")
  return performPlaintextLogin(username, password)
end

function isEmptyLoginSuccess(content)
  return content == nil or content == "" or trim(content) == ""
end

function parseLoginResponse(content)
  if isEmptyLoginSuccess(content) then
    return { success = true, emptyBody = true }
  end

  if content:find("challenge") or content:find("mfa") or content:find("tan") or
     content:find("SecureGo") then
    return {
      success = false,
      requiresMfa = true,
      mfaToken = extractMfaToken(content)
    }
  end

  local response = parseJson(content)
  if not response then
    return { success = false, error = "Ungültige Server-Antwort." }
  end

  if response.access_token then
    session.accessToken = response.access_token
    session.refreshToken = response.refresh_token
    session.tokenExpires = response.expires_in and (os.time() + response.expires_in) or nil
    return { success = true }
  end

  if response.error then
    if response.error == "invalid_grant" then
      return { success = false, error = "Ungültige Anmeldedaten." }
    end
    if response.error == "invalid_request" then
      return { success = false, error = "Token-Anfrage vom Server abgelehnt." }
    end
    if response.error == "mfa_required" or response.error == "second_factor_required" then
      return {
        success = false,
        requiresMfa = true,
        mfaToken = response.challenge_token or response.challengeToken or extractMfaToken(content)
      }
    end
    return { success = false, error = response.error_description or response.error }
  end

  if response.challengeType or response.mfaRequired or response.requiresSecondFactor then
    return {
      success = false,
      requiresMfa = true,
      mfaToken = response.challengeToken or extractMfaToken(content)
    }
  end

  if response.success or response.authenticated then
    return { success = true }
  end

  return { success = false, error = "Unbekannter Login-Status." }
end

function extractIframeUrlFromPortalResponse(content)
  if not content or content == "" then
    return nil
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

function establishKundenportalSession()
  MM.printStatus("MLP: Stelle Kundenportal-Session her...")
  local okpUrl = CONSTANTS.baseUrl .. CONSTANTS.portalOkpLogin
  local content = connection:get(okpUrl)
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

function establishVueSession(iframeUrl)
  if not iframeUrl or iframeUrl == "" then
    return false
  end
  local allowed, allowErr = assertAllowedMlpUrl(iframeUrl)
  if not allowed then
    MM.printStatus("MLP: Vue-iframe URL abgelehnt: " .. tostring(allowErr))
    return false
  end

  MM.printStatus("MLP: Initialisiere Vue-Session...")
  local clientContent = connection:get(allowed)
  if clientContent then
    collectSessionCookies()
  end

  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json, text/plain, */*",
    ["Accept-Language"] = "de-DE,de;q=0.9",
    ["Referer"] = CONSTANTS.vueApiBase .. "/vu/client/",
    ["Origin"] = CONSTANTS.vueApiBase,
    ["User-Agent"] = CONSTANTS.userAgent
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

  if success and tokenResponse then
    collectSessionCookies()
    return true
  end

  return clientContent ~= nil
end

function completePostLoginFlow()
  if not tryConsentCall() then
    MM.printStatus("MLP: Consent-Aufruf fehlgeschlagen oder nicht erforderlich.")
  end

  if not establishKundenportalSession() then
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

function performJweLogin(username, password)
  -- 1. Hole Public Key für RSA-Verschlüsselung
  mlpDebugLog("MLP-DEBUG: performJweLogin startet")
  local publicKey = fetchPublicKey()
  if not publicKey then
    MM.printStatus("MLP: Kein Public Key verfügbar, fallback zu Cookie-Import...")
    return { success = false, error = "JOSE", needsCookie = true }
  end
  mlpDebugLog("MLP-DEBUG: Public Key erfolgreich geholt, Typ=" .. type(publicKey))

  -- 2. Bereite Login-Payload vor
  local loginPayload = {
    username = username,
    password = password,
    grant_type = "password",
    deviceInfo = {
      deviceType = "BROWSER",
      userAgent = CONSTANTS.userAgent
    }
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

  local loginResult = parseLoginResponse(content)
  if loginResult.requiresMfa then
    return loginResult
  end
  if not loginResult.success then
    return loginResult
  end

  MM.printStatus("MLP: Login akzeptiert, schließe Post-Login-Flow ab...")
  if completePostLoginFlow() then
    return { success = true }
  end

  if isAuthenticated() then
    return { success = true }
  end

  return {
    success = false,
    error = "Login erfolgreich, aber Vue-Session nicht herstellbar.",
    needsCookie = true
  }
end

function performPlaintextLogin(username, password)
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

  if content:find('"error":') and content:find("403") then
    return { success = false, error = "JOSE", needsCookie = true }
  end

  local response = parseJson(content)
  if not response then
    if content:find("challenge") or content:find("mfa") or content:find("tan") then
      return { success = false, requiresMfa = true, mfaToken = extractMfaToken(content) }
    end
    if isAuthenticated() then
      return { success = true }
    end
    return { success = false, error = "Ungültige Server-Antwort." }
  end

  if response.challengeType or response.mfaRequired or response.requiresSecondFactor then
    return { success = false, requiresMfa = true, mfaToken = response.challengeToken }
  end

  if response.error or response.errorMessage then
    return { success = false, error = response.errorMessage or response.error }
  end

  if response.success or response.authenticated or isAuthenticated() then
    return { success = true }
  end

  return { success = false, error = "Login-Status unbekannt." }
end

function extractMfaToken(content)
  -- Extrahiert MFA Token aus verschiedenen Response-Formaten
  if not content then
    return nil
  end
  local token = content:match('"challengeToken"%s*:%s*"([^"]+)"') or
                content:match('"challenge_token"%s*:%s*"([^"]+)"') or
                content:match('"mfaToken"%s*:%s*"([^"]+)"') or
                content:match('"mfa_token"%s*:%s*"([^"]+)"') or
                content:match('"challengeId"%s*:%s*"([^"]+)"') or
                content:match('"challenge_id"%s*:%s*"([^"]+)"') or
                content:match('"secureGoPlusToken"%s*:%s*"([^"]+)"') or
                content:match('"secureGoPlus_challenge_token"%s*:%s*"([^"]+)"') or
                content:match('"transactionId"%s*:%s*"([^"]+)"') or
                content:match('"tanSession"%s*:%s*"([^"]+)"') or
                content:match('"tan_session"%s*:%s*"([^"]+)"') or
                content:match('"token"%s*:%s*"([^"]+)"')

  return token
end

function urlEncode(str)
  if not str then return "" end
  str = tostring(str)
  -- Ersetze nicht-alphanumerische Zeichen (außer -_.~) mit %XX
  return str:gsub("([^%w%-%.%_%~])", function(c)
    return string.format("%%%02X", string.byte(c))
  end)
end

function submitMfaCode(tanCode)
  if not session.mfaToken then
    return CONSTANTS.mfaSessionExpired
  end

  MM.printStatus("MLP: Übermittle MFA...")

  local mfaPayload = {
    challengeToken = session.mfaToken,
    tan = tanCode and trim(tanCode) or nil,
    confirmPush = not tanCode or trim(tanCode) == ""
  }

  local jsonBody = encodeJson(mfaPayload)
  local headers = {
    ["Content-Type"] = "application/json",
    ["Accept"] = "application/json"
  }

  local cookieHeader = buildCookieHeader(false)
  if cookieHeader ~= "" then
    headers["Cookie"] = cookieHeader
  end

  local content = connection:request(
    "POST",
    CONSTANTS.authBaseUrl .. "/services_auth/auth-backend/api/authentication/mfa",
    jsonBody,
    "application/json",
    headers
  )

  if not content then
    return "Keine Antwort bei MFA."
  end

  collectSessionCookies()

  local response = parseJson(content)
  if not response then
    if isAuthenticated() then
      session.state = nil
      if loadContracts() then return nil end
    end
    return "Ungültige MFA-Antwort."
  end

  if response.error then
    session.state = "awaitingMfa"
    return {
      title = "SecureGo Plus",
      challenge = "Fehler: " .. (response.errorMessage or response.error) .. "\n\nBitte erneut versuchen:",
      label = "TAN"
    }
  end

  if response.success or response.authenticated then
    session.state = nil
    if completePostLoginFlow() and loadContracts() then
      return nil
    end
    if loadContracts() then
      return nil
    end
    return "MFA erfolgreich, aber keine Vertragsdaten."
  end

  if response.pending or response.waiting then
    session.state = "awaitingMfa"
    return {
      title = "SecureGo Plus",
      challenge = "Warte auf Bestätigung...\n\nBitte in der App bestätigen oder TAN eingeben:",
      label = "TAN"
    }
  end

  return "Unbekannter MFA-Status."
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

function parseCookieString(cookieString)
  if not cookieString or cookieString == "" then return end

  local seen = {}
  local pos = 1
  local len = #cookieString

  while pos <= len do
    local nextSemi = cookieString:find(";", pos) or len + 1
    local part = cookieString:sub(pos, nextSemi - 1)

    local eqPos = part:find("=", 1, true)
    if eqPos then
      local name = trim(part:sub(1, eqPos - 1))
      local value = trim(part:sub(eqPos + 1))

      if name ~= "" then
        local storageName = name
        if storageName == "VUSESSIONID" and seen["VUSESSIONID"] then
          storageName = "VUSESSIONID2"
        end
        seen[storageName] = true
        session.sessionCookies[storageName] = value
      end
    end

    pos = nextSemi + 1
  end
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

function tryConsentCall()
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

  if success and contentOrError then
    collectSessionCookies()
    return true
  end
  return false
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
      return true
    end
  elseif tryConsentCall() then
    success, contentOrError = pcall(function()
      return connection:request("GET", CONSTANTS.vueApiBase .. CONSTANTS.vueContractListPath, nil, nil, headers)
    end)
    if success and contentOrError then
      local data = parseJson(contentOrError)
      if (data and data.contractList) or (contentOrError and contentOrError:find('"contractList"')) then
        return true
      end
    end
  end

  return false
end

function isAuthenticated()
  local hasVuSession = session.sessionCookies.VUSESSIONID and session.sessionCookies.VUSESSIONID ~= ""

  if hasVuSession then
    return tryContractListAuth(buildCookieHeader(true))
  end

  -- HttpOnly-Cookies (z. B. VUSESSIONID) sind in getCookies() unsichtbar,
  -- werden aber von der persistierten Connection automatisch mitgesendet.
  return tryContractListAuth(nil)
end

function loadContracts()
  MM.printStatus("MLP: Lade Vertragsdaten...")

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

  if success and content then
    local apiData = parseJson(content)
    if apiData and apiData.contractList then
      local contracts = parseVueContracts(apiData.contractList)
      if #contracts > 0 then
        session.contracts = contracts
        MM.printStatus("MLP: " .. #session.contracts .. " Vertrag(e) geladen.")
        return true
      end
    end
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
  session = { contracts = {}, state = nil, username = nil, password = nil, mfaToken = nil, sessionCookies = {} }
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

