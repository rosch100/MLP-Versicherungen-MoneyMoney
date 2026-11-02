-- Tests für MLP Versicherungen Extension v1.0
-- Testet Hilfsfunktionen, Login-State-Machine und Datenstrukturen

-- WebBanking/Connection/MM stubben
function WebBanking(_) end

ProtocolWebBanking = "WebBanking"
AccountTypePortfolio = 5
LoginFailed = "LoginFailed"

-- JSON-Stub für die Tests: kleiner rekursiver Decoder (Objekte, Arrays, Strings, Zahlen, true/false/null).
local function decodeJsonValue(text, pos)
  pos = text:find("%S", pos) or error("JSON: unerwartetes Ende")
  local c = text:sub(pos, pos)
  if c == "{" then
    local obj = {}
    pos = text:find("%S", pos + 1)
    if text:sub(pos, pos) == "}" then return obj, pos + 1 end
    while true do
      local key
      key, pos = decodeJsonValue(text, pos)
      pos = text:find(":", pos, true) + 1
      obj[key], pos = decodeJsonValue(text, pos)
      pos = text:find("%S", pos)
      local sep = text:sub(pos, pos)
      pos = pos + 1
      if sep == "}" then return obj, pos end
      if sep ~= "," then error("JSON: ',' oder '}' erwartet") end
    end
  elseif c == "[" then
    local arr = {}
    pos = text:find("%S", pos + 1)
    if text:sub(pos, pos) == "]" then return arr, pos + 1 end
    while true do
      arr[#arr + 1], pos = decodeJsonValue(text, pos)
      pos = text:find("%S", pos)
      local sep = text:sub(pos, pos)
      pos = pos + 1
      if sep == "]" then return arr, pos end
      if sep ~= "," then error("JSON: ',' oder ']' erwartet") end
    end
  elseif c == '"' then
    local close = text:find('"', pos + 1, true) or error("JSON: String ohne Ende")
    return text:sub(pos + 1, close - 1), close + 1
  end
  local literal, endPos = text:match("^([%w%.%-%+]+)()", pos)
  if literal == "true" then return true, endPos end
  if literal == "false" then return false, endPos end
  if literal == "null" then return nil, endPos end
  return tonumber(literal), endPos
end

JSON = function(jsonStr)
  return {
    dictionary = function()
      local value = decodeJsonValue(jsonStr, 1)
      return type(value) == "table" and value or nil
    end,
    array = function()
      local value = decodeJsonValue(jsonStr, 1)
      return type(value) == "table" and value or nil
    end
  }
end

local sleepCalls = 0

MM = {
  printStatus = function(msg) io.stderr:write("[STATUS] " .. msg .. "\n") end,
  sleep = function() sleepCalls = sleepCalls + 1 end,
  urlencode = function(s)
    return (tostring(s):gsub("([^%w%-%.%_%~])", function(c)
      return string.format("%%%02X", string.byte(c))
    end))
  end
}

-- ============================================================
-- Hilfsfunktionen (werden in Extension definiert)
-- ============================================================

function trim(text)
  if not text then return "" end
  return (text:gsub("^%s*(.-)%s*$", "%1"))
end

function formatCurrency(value)
  if not value then return "0,00 €" end
  local formatted = string.format("%.2f", value)
  formatted = formatted:gsub("(%d)%.(%d%d)$", "%1,%2")
  local intPart, decPart = formatted:match("^(%d+),(%d%d)$")
  if intPart then
    intPart = intPart:reverse():gsub("(%d%d%d)", "%1."):reverse()
    if intPart:sub(1, 1) == "." then intPart = intPart:sub(2) end
    formatted = intPart .. "," .. decPart
  end
  return formatted .. " €"
end

function parseIsoDate(dateStr)
  if not dateStr then return nil end
  local year, month, day = dateStr:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)")
  if year and month and day then
    return tonumber(day), tonumber(month), tonumber(year)
  end
  return nil
end

function formatDateDisplay(dateStr)
  local day, month, year = parseIsoDate(dateStr)
  if day and month and year then
    return string.format("%02d.%02d.%04d", day, month, year)
  end
  return dateStr or ""
end

-- ============================================================
-- Test-Hilfsfunktionen
-- ============================================================

local function assertEq(actual, expected, label)
  if actual == expected then
    print("OK    " .. label .. " = " .. tostring(actual))
  else
    print("FAIL  " .. label .. ": expected=" .. tostring(expected) .. ", actual=" .. tostring(actual))
    os.exit(1)
  end
end

local function assertNear(actual, expected, label)
  local eps = 0.01
  if math.abs((actual or 0) - expected) < eps then
    print("OK    " .. label .. " = " .. tostring(actual))
  else
    print("FAIL  " .. label .. ": expected~" .. tostring(expected) .. ", actual=" .. tostring(actual))
    os.exit(1)
  end
end

local function assertContains(str, substr, label)
  if str and str:find(substr, 1, true) then
    print("OK    " .. label .. " contains '" .. substr .. "'")
  else
    print("FAIL  " .. label .. ": expected to contain '" .. substr .. "', actual=" .. tostring(str))
    os.exit(1)
  end
end

-- ============================================================
-- Extension laden (für SupportsBank)
-- ============================================================

dofile("MLP Versicherungen.lua")

-- ============================================================
-- Tests: Grundlegende Funktionen
-- ============================================================

print()
print("=== Test: Grundlegende Funktionen ===")

local d1, m1, y1 = parseIsoDate("2026-01-01T00:00:00.000+00:00")
assertEq(d1, 1, "parseIsoDate.day")
assertEq(m1, 1, "parseIsoDate.month")
assertEq(y1, 2026, "parseIsoDate.year")
assertEq(parseIsoDate(nil), nil, "parseIsoDate.nil")

local display1 = formatDateDisplay("2040-01-01T00:00:00.000+00:00")
assert(display1 == "01.01.2040", "formatDateDisplay")
print("OK    formatDateDisplay = " .. display1)

assertEq(formatDateDisplay(nil), "", "formatDateDisplay.nil")
assertEq(SupportsBank("WebBanking", "MLP Versicherungen"), true, "SupportsBank.mlp")
assertEq(SupportsBank("FinTS", "MLP Versicherungen"), false, "SupportsBank.fints")
assertEq(SupportsBank("WebBanking", "Andere Bank"), false, "SupportsBank.wrong-service")

assertEq(formatCurrency(50000.00), "50.000,00 €", "formatCurrency.gross")
assertEq(formatCurrency(50.00), "50,00 €", "formatCurrency.klein")
assertEq(formatCurrency(0), "0,00 €", "formatCurrency.null")

local randomOk, randomError = pcall(generateRandomBytes, 16)
assertEq(randomOk, false, "generateRandomBytes.requiresSecureRandom")
assertContains(randomError, "MM.random", "generateRandomBytes.secureRandomMessage")
local vueWithoutValue = mapVueContractToInternal({
  id = "vue-missing-value",
  number = "vue-missing-value",
})
if not vueWithoutValue then
  error("mapVueContractToInternal unexpectedly rejected valid contract identity")
end
assertEq(vueWithoutValue.shareValue, nil, "mapVueContractToInternal.noDummyValue")
local apiWithoutValue = mapApiContractToInternal({
  id = "api-missing-value",
  number = "api-missing-value",
})
if not apiWithoutValue then
  error("mapApiContractToInternal unexpectedly rejected valid contract identity")
end
assertEq(apiWithoutValue.shareValue, nil, "mapApiContractToInternal.noDummyValue")

-- ============================================================
-- Tests: Login-State-Machine (Post-Login-Flow Vorbereitung)
-- ============================================================

print()
print("=== Test: Login-State-Machine ===")

assertEq(isEmptyLoginSuccess(nil), true, "isEmptyLoginSuccess.nil")
assertEq(isEmptyLoginSuccess(""), true, "isEmptyLoginSuccess.empty")
assertEq(isEmptyLoginSuccess("   "), true, "isEmptyLoginSuccess.whitespace")
assertEq(isEmptyLoginSuccess('{"access_token":"x"}'), false, "isEmptyLoginSuccess.json")

local emptyLogin = parseLoginResponse("")
assertEq(emptyLogin.success, true, "parseLoginResponse.empty.success")
assertEq(emptyLogin.emptyBody, true, "parseLoginResponse.empty.body")

-- Browser-Erkennung: Login-Antwort aus der HAR verlangt die SecureGo-Freigabe.
assertEq(
  requiresBrowserDetectionTan('{"authenticationProcessResponse":{"authenticationProcessCompleted":false,'
    .. '"nextAuthenticationProcessStep":{"actions":[{"stepType":"START_TAN_PROCESS_FOR_BROWSER_DETECTION_AUTH",'
    .. '"urlOfResource":"x"}]}}}'),
  true,
  "browserTan.required")
assertEq(requiresBrowserDetectionTan('{"access_token":"tok","expires_in":3600}'), false, "browserTan.notRequired")

local tokenLogin = parseLoginResponse('{"access_token":"tok","expires_in":3600}')
assertEq(tokenLogin.success, true, "parseLoginResponse.token.success")
local invalidRequest = parseLoginResponse('{"error":"invalid_request"}')
assertEq(
  invalidRequest.error,
  "Token-Anfrage vom Server abgelehnt.",
  "parseLoginResponse.invalidRequest.technical")

local iframeJson = '{"iframeUrl":"https://vue.mlp.de/vu/client/index.html?source=https://kundenportal.mlp.de&token=eyJtest"}'
local iframeUrl = extractIframeUrlFromPortalResponse(iframeJson)
assertContains(iframeUrl, "vue.mlp.de", "extractIframeUrl.host")
assertContains(iframeUrl, "token=eyJtest", "extractIframeUrl.token")
-- api/app/vu liefert XML (wie im Log), nicht JSON. Der Query-Parameter ist XML-escaped (&amp;).
local iframeXml = '<IframePageDto><appUrl>https://vue.mlp.de/vu/client/</appUrl>'
  .. '<iframeUrl>https://vue.mlp.de/vu/client/index.html?source=https://kundenportal.mlp.de&amp;token=eyJtest</iframeUrl>'
  .. '</IframePageDto>'
assertEq(extractIframeUrlFromPortalResponse(iframeXml),
  "https://vue.mlp.de/vu/client/index.html?source=https://kundenportal.mlp.de&token=eyJtest",
  "extractIframeUrl.xml")

-- ============================================================
-- Tests: Cookie-Parsing
-- ============================================================

print()
print("=== Test: Cookie-Parsing ===")

Connection = function()
  return {
    language = "",
    useragent = "test",
    get = function() return nil end,
    request = function() return nil end,
    setCookie = function() end,
    getCookies = function() return "" end,
  }
end
startFreshConnection("cookie-parsing")
collectSessionCookiesFromText("VUSESSIONID=first;BIGipServervue.mlp.de=lb1;VUSESSIONID=second")
local cookieHeader = buildCookieHeader(true)
assertContains(cookieHeader, "VUSESSIONID=first", "parseCookie.vu1")
assertContains(cookieHeader, "VUSESSIONID=second", "parseCookie.vu2")
assertContains(cookieHeader, "BIGipServervue.mlp.de=lb1", "parseCookie.bigip")

startFreshConnection("cookie-jar")
collectSessionCookiesFromText("VUSESSIONID=jar1; VUSESSIONID=jar2; BIGipServervue.mlp.de=jarlb")
local jarHeader = buildCookieHeader(true)
assertContains(jarHeader, "VUSESSIONID=jar1", "collectCookies.vu1")
assertContains(jarHeader, "VUSESSIONID=jar2", "collectCookies.vu2")

-- ============================================================
-- Test-Daten: Verschiedene Versicherungstypen
-- ============================================================

local testContracts = {
  {
    id = "00000000000000000000000000000001",
    number = "123456789",
    company = { shortName = "Versicherung AG", longName = "Versicherung AG" },
    contribution = 100.00, paymentMethod = "MONAT",
    validFrom = "2000-01-01T00:00:00.000+00:00", validUntil = "2050-01-01T00:00:00.000+00:00",
    state = "aktiv", category = "Vorsorge", tariff = "TARIF-A",
    contractType = "FLV", posType = "FLV",
    shareValue = 50000.00, dateOfShareValue = "2026-01-01T00:00:00.000+00:00",
    currency = "EUR",
    specificAttributes = {
      deathInsuredSum = { value = 100000.00, displayValue = "100.000,00 €" },
      endOfPayment = { value = "2040-01-01T00:00:00.000+00:00", displayValue = "01.01.2040" },
      netContribution = { value = 90.00, displayValue = "90,00 €" }
    }
  },
  {
    id = "00000000000000000000000000000002",
    number = "987654321",
    company = { shortName = "Versicherung GmbH", longName = "Versicherung GmbH" },
    contribution = 50.00, paymentMethod = "MONAT",
    validFrom = "2010-01-01T00:00:00.000+00:00", validUntil = "2060-01-01T00:00:00.000+00:00",
    state = "aktiv", category = "Vorsorge", tariff = "TARIF-B",
    contractType = "KLV", posType = "KLV",
    shareValue = 10000.00, dateOfShareValue = "2026-01-01T00:00:00.000+00:00",
    currency = "EUR",
    specificAttributes = {
      deathInsuredSum = { value = 20000.00, displayValue = "20.000,00 €" },
      lifeInsuredSum = { value = 15000.00, displayValue = "15.000,00 €" },
      endOfPayment = { value = "2050-01-01T00:00:00.000+00:00", displayValue = "01.01.2050" },
      netContribution = { value = 50.00, displayValue = "50,00 €" }
    }
  }
}

-- ============================================================
-- Lokale Test-Implementationen
-- ============================================================

local CONTRACT_TYPE_NAMES = {
  FLV = "Fondsgebundene Lebensversicherung",
  KLV = "Kapitallebensversicherung",
  LV = "Lebensversicherung",
  REN = "Rentenversicherung",
  BU = "Berufsunfähigkeitsversicherung",
  DEFAULT = "Vorsorgevertrag"
}

local function getContractTypeName(contractType)
  return CONTRACT_TYPE_NAMES[contractType or "DEFAULT"] or CONTRACT_TYPE_NAMES.DEFAULT
end

local function buildSecurityName(contract)
  local parts = {}
  local typeDesc = getContractTypeName(contract.contractType)
  table.insert(parts, typeDesc)
  if contract.tariff and contract.tariff ~= "" then
    table.insert(parts, "Tarif: " .. contract.tariff)
  end
  if contract.specificAttributes then
    local deathSum = contract.specificAttributes.deathInsuredSum
    if deathSum and deathSum.displayValue then
      table.insert(parts, "Todesfall: " .. deathSum.displayValue)
    end
    local lifeSum = contract.specificAttributes.lifeInsuredSum
    if lifeSum and lifeSum.displayValue then
      table.insert(parts, "Erlebensfall: " .. lifeSum.displayValue)
    end
  end
  if contract.contribution and contract.contribution > 0 then
    table.insert(parts, "Beitrag/Monat: " .. formatCurrency(contract.contribution))
  end
  return table.concat(parts, " | ")
end

local function createAccountFromContract(contract)
  local companyName = contract.company.shortName or "Unbekannt"
  local contractNumber = contract.number or ""
  local tariff = contract.tariff or ""
  local endDate = ""
  if contract.specificAttributes and contract.specificAttributes.endOfPayment then
    endDate = formatDateDisplay(contract.specificAttributes.endOfPayment.value)
  end
  local displayName = companyName
  if contractNumber ~= "" then
    displayName = displayName .. " " .. contractNumber
  end
  if tariff ~= "" then
    displayName = displayName .. " (" .. tariff .. ")"
  end
  if endDate ~= "" then
    displayName = displayName .. " | Beitrag bis " .. endDate
  end
  return {
    name = displayName,
    accountNumber = contract.number or contract.id,
    portfolio = true,
    currency = contract.currency or "EUR",
    type = AccountTypePortfolio,
    bankCode = contract.company.shortName or "MLP"
  }
end

-- ============================================================
-- Tests: Vertragstyp-Mapping
-- ============================================================

print()
print("=== Test: Vertragstyp-Mapping ===")

assertEq(getContractTypeName("FLV"), "Fondsgebundene Lebensversicherung", "typeMapping.FLV")
assertEq(getContractTypeName("KLV"), "Kapitallebensversicherung", "typeMapping.KLV")
assertEq(getContractTypeName("REN"), "Rentenversicherung", "typeMapping.REN")
assertEq(getContractTypeName("BU"), "Berufsunfähigkeitsversicherung", "typeMapping.BU")
assertEq(getContractTypeName("UNKNOWN"), "Vorsorgevertrag", "typeMapping.unknown")
assertEq(
  isPortfolioContract({shareValue = 100}),
  true,
  "isPortfolioContract.valuedContract")
assertEq(
  isPortfolioContract({shareValue = nil}),
  false,
  "isPortfolioContract.nonValuedContract")

-- ============================================================
-- Tests: Vertragsverarbeitung
-- ============================================================

print()
print("=== Test: Vertragsverarbeitung ===")

for i, contract in ipairs(testContracts) do
  print()
  print("Vertrag " .. i .. ": " .. contract.company.shortName)
  
  local account = createAccountFromContract(contract)
  print("  Konto-Name: " .. account.name)
  print("  Vertragsnr: " .. tostring(account.accountNumber))
  
  assertEq(account.portfolio, true, "contract" .. i .. ".portfolio")
  assertEq(account.type, AccountTypePortfolio, "contract" .. i .. ".type")
  assertEq(account.currency, "EUR", "contract" .. i .. ".currency")
  
  local secName = buildSecurityName(contract)
  print("  Security-Name: " .. secName)
  
  if contract.contractType == "FLV" then
    assertContains(secName, "Fondsgebundene Lebensversicherung", "contract" .. i .. ".type")
  elseif contract.contractType == "KLV" then
    assertContains(secName, "Kapitallebensversicherung", "contract" .. i .. ".type")
  end
end

-- ============================================================
-- Tests: JSON-Encoding
-- ============================================================

print()
print("=== Test: JSON-Encoding ===")

local function encodeJson(obj)
  if type(obj) == "table" then
    local parts = {}
    for k, v in pairs(obj) do
      local key = string.format("%q", k)
      local value
      if type(v) == "table" then value = encodeJson(v)
      elseif type(v) == "string" then value = string.format("%q", v)
      elseif type(v) == "number" then value = tostring(v)
      elseif type(v) == "boolean" then value = v and "true" or "false"
      else value = "null" end
      table.insert(parts, key .. ":" .. value)
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

local testObj = { name = "Test", value = 123 }
local jsonStr = encodeJson(testObj)
assertContains(jsonStr, "name", "encodeJson.hasName")
assertContains(jsonStr, "Test", "encodeJson.hasValue")

-- Ohne JWE-APIs bleibt Username/Passwort aktiv (Klartext), kein stiller Cookie-Only-Skip.
do
  local plaintextCalled = false
  local realPlaintext = performPlaintextLogin
  performPlaintextLogin = function(username, password)
    plaintextCalled = true
    assertEq(username, "mlp-user", "performLogin.plaintextFallback.username")
    assertEq(password, "secret", "performLogin.plaintextFallback.password")
    return { success = false, error = "Klartext-Ergebnis" }
  end
  MM.random = nil
  MM.aes256encrypt = nil
  MM.rsaEncrypt = nil
  MM.base64urlencode = nil
  local result = performLogin("mlp-user", "secret")
  performPlaintextLogin = realPlaintext
  assertEq(plaintextCalled, true, "performLogin.plaintextFallback.called")
  assertEq(type(result), "table", "performLogin.plaintextFallback.result")
  assertEq(result.error, "Klartext-Ergebnis", "performLogin.plaintextFallback.error")
end

-- JWE CEK: nur OAEP-SHA-512 (Header alg RSA-OAEP-512), kein SHA-256-Fallback.
do
  local seenPadding = {}
  MM.rsaEncrypt = function(_key, _cek, padding)
    seenPadding[#seenPadding + 1] = padding
    if padding == "pkcs1-oaep sha256" then
      return "wrong-padding-must-not-be-used"
    end
    if padding == "pkcs1-oaep sha512" then
      return "cek-encrypted-sha512"
    end
    error("unsupported padding")
  end
  local encrypted = encryptCekWithRsa(string.rep("A", 32), { n = "01", e = "010001" })
  assertEq(encrypted, "cek-encrypted-sha512", "encryptCekWithRsa.sha512")
  assertEq(#seenPadding, 1, "encryptCekWithRsa.singleAttempt")
  assertEq(seenPadding[1], "pkcs1-oaep sha512", "encryptCekWithRsa.padding")
end

-- AES-GCM über dokumentierte MM.aes256encrypt(..., "aes256 gcm", aad)-API (MM ≥ 2.5.2).
do
  local seen = {}
  MM.aes256encrypt = function(key, iv, data, algorithm, aad)
    seen.key = key
    seen.iv = iv
    seen.data = data
    seen.algorithm = algorithm
    seen.aad = aad
    return "ct-bytes", "tag-bytes"
  end
  local ciphertext, tag = aesGcmEncrypt("k32", "iv12", "plain", "aad-header")
  assertEq(ciphertext, "ct-bytes", "aesGcmEncrypt.ciphertext")
  assertEq(tag, "tag-bytes", "aesGcmEncrypt.tag")
  assertEq(seen.algorithm, "aes256 gcm", "aesGcmEncrypt.algorithm")
  assertEq(seen.aad, "aad-header", "aesGcmEncrypt.aad")
  local _, _ = aesGcmEncrypt("k32", "iv12", "plain", nil)
  assertEq(seen.aad, "", "aesGcmEncrypt.nilAadBecomesEmpty")
end

-- Wenn JWE-APIs da sind, aber Generierung cryptoIncomplete → Klartext-Fallback.
do
  local plaintextCalled = false
  local realPlaintext = performPlaintextLogin
  local realJwe = performJweLogin
  performJweLogin = function()
    return { success = false, error = "CEK-Verschlüsselung mit RSA-OAEP-512 fehlgeschlagen", cryptoIncomplete = true }
  end
  performPlaintextLogin = function()
    plaintextCalled = true
    return { success = false, error = "Klartext-Ergebnis" }
  end
  MM.random = function(n) return string.rep("\0", n) end
  MM.base64urlencode = function(s) return "b64u" end
  MM.rsaEncrypt = function() return "x" end
  MM.aes256encrypt = function() return "ct", "tag" end
  assertEq(canUseJweLogin(), true, "canUseJweLogin.whenApisPresent")
  local result = performLogin("mlp-user", "secret")
  performPlaintextLogin = realPlaintext
  performJweLogin = realJwe
  assertEq(plaintextCalled, true, "performLogin.cryptoIncomplete.fallsBackToPlaintext")
  assertEq(result.error, "Klartext-Ergebnis", "performLogin.cryptoIncomplete.plaintextResult")
end

local missingMfaState = InitializeSession2(
  ProtocolWebBanking,
  "MLP Versicherungen",
  2,
  {"123456"},
  true)
assertEq(type(missingMfaState), "string", "InitializeSession2.missingMfaState.type")
assertEq(missingMfaState, "MFA-Session abgelaufen. Bitte neu einloggen.",
  "InitializeSession2.missingMfaState.message")

-- Schritt 1 wartet auf die SecureGo-Freigabe und schließt den Login ab (kein Dialog, kein zweiter Schritt).
local firstCalls = {}
local firstConnection = {
  language = "",
  useragent = "test",
  get = function() return nil end,
  getCookies = function() return "" end,
  request = function(self, method, url)
    table.insert(firstCalls, url)
    if url:find("tan-methods-check", 1, true) then
      return '{"hasTanMethods":true}'
    end
    if url:find("browser-detection-auth/start", 1, true) then
      return '{"authenticationProcessResponse":{"authenticationProcessCompleted":false,'
        .. '"resultOfCurrentAuthenticationProcessStep":{"tanProzessId":"tp-1"}}}'
    end
    if url:find("liefereTanVerfahren", 1, true) then
      return '{"tanVerfahren":[{"typ":"SECUREGO_PLUS"}]}'
    end
    if url:find("direktfreigabe/authentication/tp-1", 1, true) then
      return '{"status":"DIREKTFREIGABE_BESTAETIGT"}'
    end
    if url:find("direktfreigabe/authentication", 1, true) then
      return '{"status":"DIREKTFREIGABE_OFFEN","transaktionsIdDirektfreigabe":"tx-1"}'
    end
    return '{"authenticationProcessResponse":{"authenticationProcessCompleted":true}}'
  end,
}
local originalPerformLogin = performLogin
local originalCompletePostLoginFlow = completePostLoginFlow
local originalLoadContracts = loadContracts
Connection = function()
  return firstConnection
end
LocalStorage = {}
performLogin = function(username, password, interactive)
  return browserDetectionLoginResult(
    '{"authenticationProcessResponse":{"nextAuthenticationProcessStep":{"actions":'
      .. '[{"stepType":"START_TAN_PROCESS_FOR_BROWSER_DETECTION_AUTH"}]}}}',
    interactive)
end
completePostLoginFlow = function() return true end
loadContracts = function() return true end
local step1 = InitializeSession2(
  ProtocolWebBanking,
  "MLP Versicherungen",
  1,
  {"mlp-user", "password"},
  true)
assertEq(step1, nil, "InitializeSession2.step1.completesAfterApproval")
assertEq(firstCalls[#firstCalls - 1]:find("browser-detection-auth/termination", 1, true) ~= nil, true,
  "InitializeSession2.step1.terminates")
assertEq(firstCalls[#firstCalls]:find("browser-detection/choose", 1, true) ~= nil, true,
  "InitializeSession2.step1.trustsBrowser")

-- Hintergrund-Refresh (interactive=false): keine SecureGo-Freigabe auslösen, sondern einen manuellen Login verlangen.
firstCalls = {}
local backgroundResult = InitializeSession2(
  ProtocolWebBanking,
  "MLP Versicherungen",
  1,
  {"mlp-user", "password"},
  false)
assertEq(type(backgroundResult), "string", "InitializeSession2.background.requiresManualLogin")
local startedApproval = false
for _, url in ipairs(firstCalls) do
  if url:find("browser-detection-auth/start", 1, true) or url:find("direktfreigabe", 1, true) then
    startedApproval = true
  end
end
assertEq(startedApproval, false, "InitializeSession2.background.noApprovalStarted")

-- Echter Login-Pfad ohne Stub: Mit interactive=true muss die Browser-TAN ausgelöst werden.
local chainCalls = {}
local chainConnection = {
  language = "",
  useragent = "test",
  get = function(self, url)
    table.insert(chainCalls, url)
    if url:find("okp/login", 1, true) then
      return ""
    end
    return nil
  end,
  getCookies = function() return "" end,
  setCookie = function() end,
  request = function(self, method, url)
    table.insert(chainCalls, url)
    if url:find("/api/authentication/login", 1, true) then
      return '{"authenticationProcessResponse":{"nextAuthenticationProcessStep":{"actions":'
        .. '[{"stepType":"START_TAN_PROCESS_FOR_BROWSER_DETECTION_AUTH"}]}}}'
    end
    if url:find("tan-methods-check", 1, true) then
      return '{"hasTanMethods":true}'
    end
    if url:find("browser-detection-auth/start", 1, true) then
      return '{"authenticationProcessResponse":{"authenticationProcessCompleted":false,'
        .. '"resultOfCurrentAuthenticationProcessStep":{"tanProzessId":"tp-2"}}}'
    end
    if url:find("liefereTanVerfahren", 1, true) then
      return '{"tanVerfahren":[{"typ":"SECUREGO_PLUS"}]}'
    end
    if url:find("direktfreigabe/authentication", 1, true) then
      return '{"status":"DIREKTFREIGABE_OFFEN","transaktionsIdDirektfreigabe":"tx-2"}'
    end
    return '{}'
  end,
}
local previousConnection = Connection
Connection = function()
  return chainConnection
end
startFreshConnection("mlp-chain-interactive")
local chainResult = performPlaintextLogin("mlp-user", "password", true)
assertEq(chainResult.requiresBrowserTan, true, "performPlaintextLogin.interactive.requiresBrowserTan")
local chainStarted = false
for _, url in ipairs(chainCalls) do
  if url:find("browser-detection-auth/start", 1, true) then
    chainStarted = true
  end
end
assertEq(chainStarted, true, "performPlaintextLogin.interactive.startsApproval")
local chainPortalStarted = false
for _, url in ipairs(chainCalls) do
  if url:find("okp/login", 1, true) then
    chainPortalStarted = true
  end
end
assertEq(chainPortalStarted, true, "performPlaintextLogin.startsPortalLogin")

-- Vertrauenswürdiger Browser: Der Login ist ohne TAN abgeschlossen, Consent und Vue-Session folgen.
local completedAuthJson = '{"authenticationProcessResponse":{"authenticationProcessCompleted":true,'
  .. '"resultOfCurrentAuthenticationProcessStep":null,"nextAuthenticationProcessStep":null}}'
assertEq(parseLoginResponse(completedAuthJson).success, true, "parseLoginResponse.authCompleted")

local trustedConnection = {
  language = "",
  useragent = "test",
  get = function(self, url)
    if url:find("okp/login", 1, true) then
      return ""
    end
    return nil
  end,
  getCookies = function() return "" end,
  setCookie = function() end,
  request = function(self, method, url)
    if url:find("/api/authentication/login", 1, true) then
      return completedAuthJson
    end
    return nil
  end,
}
Connection = function()
  return trustedConnection
end
startFreshConnection("mlp-trusted-plaintext")
local postLoginCalls = 0
completePostLoginFlow = function()
  postLoginCalls = postLoginCalls + 1
  return true
end
local trustedResult = performPlaintextLogin("mlp-user", "password", true)
completePostLoginFlow = originalCompletePostLoginFlow
assertEq(type(trustedResult) == "table" and trustedResult.success, true, "performPlaintextLogin.trusted.success")
assertEq(postLoginCalls, 1, "performPlaintextLogin.trusted.completesPostLogin")
Connection = previousConnection
performLogin = originalPerformLogin
completePostLoginFlow = originalCompletePostLoginFlow
loadContracts = originalLoadContracts
assertEq(InitializeSession2(ProtocolWebBanking, "MLP Versicherungen", 2, {"123456"}, true),
  "MFA-Session abgelaufen. Bitte neu einloggen.", "InitializeSession2.step2.unsupported")

Connection = function()
  return {
    language = "",
    useragent = "test",
    get = function() return nil end,
    getCookies = function() return "" end,
  }
end
LocalStorage = {}
performLogin = function()
  return {success = false, error = "Ungültige Anmeldedaten."}
end
local rejectedCredentials = InitializeSession2(
  ProtocolWebBanking,
  "MLP Versicherungen",
  1,
  {"mlp-user", "wrong"},
  true)
assertEq(rejectedCredentials, LoginFailed, "InitializeSession2.rejectedCredentials")

local missingAccountOk, missingAccountError = pcall(RefreshAccount, nil, nil)
assertEq(missingAccountOk, false, "RefreshAccount.rejectsMissingAccount")
assertContains(missingAccountError, "Kontoabruf", "RefreshAccount.missingAccountMessage")

local invalidRefreshOk, invalidRefreshError = pcall(
  RefreshAccount,
  {accountNumber = "missing-contract"},
  nil)
assertEq(invalidRefreshOk, false, "RefreshAccount.propagatesMissingContract")
assertContains(invalidRefreshError, "Kontoabruf", "RefreshAccount.missingContractMessage")

findContractByNumber = function()
  return {
    number = "missing-value",
    currency = "EUR",
  }
end
local missingValueOk, missingValueError = pcall(
  RefreshAccount,
  {accountNumber = "missing-value"},
  nil)
assertEq(missingValueOk, false, "RefreshAccount.requiresShareValue")
assertContains(missingValueError, "Vertragswert", "RefreshAccount.shareValueMessage")

-- Passwort-Login nach fehlgeschlagenem Session-Check nutzt die gespeicherte Verbindung weiter,
-- damit das Geräte-Cookie (CAS_DEVICE_SESSION) erhalten bleibt. Es wird keine neue Verbindung erzeugt.
do
  local originalPersistedAuth = tryPersistedAuth
  local originalPerformLogin = performLogin
  local created = 0
  local function stubConnection(cookies)
    return {
      language = "",
      useragent = "",
      get = function() return nil end,
      request = function() return nil end,
      setCookie = function() end,
      getCookies = function() return cookies end,
    }
  end
  local storedConnection = stubConnection("CAS_S_SESSION=old; CAS_DEVICE_SESSION=old")
  Connection = function()
    created = created + 1
    return stubConnection("")
  end
  LocalStorage = {
    connection = storedConnection,
    connectionAccountKey = "mlp-reuse",
    connectionsByAccount = { ["mlp-reuse"] = { connection = storedConnection } },
  }
  tryPersistedAuth = function() return false end
  performLogin = function() return { success = false, error = "403 Invalid credentials" } end
  loginStep1({"mlp-reuse", "secret"})
  assertEq(LocalStorage.connection, storedConnection, "passwordLogin.reusesConnection")
  assertEq(created, 0, "passwordLogin.noNewConnection")
  tryPersistedAuth = originalPersistedAuth
  performLogin = originalPerformLogin
end

-- Veraltete VUSESSIONID aus dem Speicher darf den Passwort-Login nicht erreichen.
do
  local originalPersistedAuth = tryPersistedAuth
  local originalPerformLogin = performLogin
  local storedConnection = {
    language = "",
    useragent = "",
    get = function() return nil end,
    request = function() return nil end,
    setCookie = function() end,
    getCookies = function() return "" end,
  }
  Connection = function() return storedConnection end
  LocalStorage = {
    connection = storedConnection,
    connectionAccountKey = "mlp-stale-vu",
    connectionsByAccount = {
      ["mlp-stale-vu"] = { connection = storedConnection, sessionCookies = { VUSESSIONID = "stale-vu" } },
    },
  }
  local headerDuringLogin = nil
  tryPersistedAuth = function() return false end
  performLogin = function()
    headerDuringLogin = buildCookieHeader(true)
    return { success = false, error = "Login fehlgeschlagen" }
  end
  loginStep1({"mlp-stale-vu", "secret"})
  assertEq(headerDuringLogin ~= nil and headerDuringLogin:find("stale-vu", 1, true) == nil, true,
    "passwordLogin.staleVuSessionDropped")
  tryPersistedAuth = originalPersistedAuth
  performLogin = originalPerformLogin
  LocalStorage = {}
end

performLogin = function()
  return {
    success = false,
    error = "403 Invalid credentials",
  }
end
assertEq(
  loginStep1({"mlp-user", "wrong"}),
  LoginFailed,
  "loginStep1.classifiesCredentialsRejected")

-- Ohne Passwort gibt es keinen Cookie-Rückfall mehr, sondern eine klare Meldung.
LocalStorage = {}
assertEq(
  loginStep1({"mlp-user", ""}),
  "Bitte Benutzername und Passwort eingeben.",
  "loginStep1.missingPassword.message")

local incompleteVueContract = mapVueContractToInternal({
  number = "VUE-1",
  shareValue = 100,
})
local vueCompany = incompleteVueContract and incompleteVueContract.company
if type(vueCompany) ~= "table" then
  error("mapVueContract.result.company must be a table")
end
assertEq(vueCompany.shortName, nil, "mapVueContract.noDummyCompany")
assertEq(
  incompleteVueContract and incompleteVueContract.contribution,
  nil,
  "mapVueContract.noDummyContribution")

local incompleteApiContract = mapApiContractToInternal({
  number = "API-1",
  shareValue = 100,
})
local apiCompany = incompleteApiContract and incompleteApiContract.company
if type(apiCompany) ~= "table" then
  error("mapApiContract.result.company must be a table")
end
assertEq(apiCompany.shortName, nil, "mapApiContract.noDummyCompany")
assertEq(
  incompleteApiContract and incompleteApiContract.contribution,
  nil,
  "mapApiContract.noDummyContribution")
assertEq(
  incompleteApiContract and incompleteApiContract.currency,
  nil,
  "mapApiContract.noDummyCurrency")
assertEq(
  incompleteApiContract and incompleteApiContract.state,
  nil,
  "mapApiContract.noDummyState")

local missingCompanyOk, missingCompanyError = pcall(
  _G.createAccountFromContract,
  {number = "MISSING-COMPANY", currency = "EUR"})
assertEq(missingCompanyOk, false, "createAccountFromContract.requiresCompany")
assertContains(missingCompanyError, "Versicherer", "createAccountFromContract.companyMessage")

local missingCurrencyOk, missingCurrencyError = pcall(
  _G.createAccountFromContract,
  {number = "MISSING-CURRENCY", company = {shortName = "Versicherer"}})
assertEq(missingCurrencyOk, false, "createAccountFromContract.requiresCurrency")
assertContains(missingCurrencyError, "Währung", "createAccountFromContract.currencyMessage")

local missingNumberOk, missingNumberError = pcall(
  _G.createAccountFromContract,
  {company = {shortName = "Versicherer"}, currency = "EUR"})
assertEq(missingNumberOk, false, "createAccountFromContract.requiresNumber")
assertContains(missingNumberError, "Vertragsnummer", "createAccountFromContract.numberMessage")

assertEq(
  calculateTotalContributions({}),
  nil,
  "calculateTotalContributions.omitsUnknownPurchasePrice")

-- Multi-login: two accountKeys keep distinct connections and cookies
do
  local function newConn()
    return {
      language = "",
      useragent = "test",
      get = function() return nil end,
      getCookies = function() return "" end,
      setCookie = function() end,
    }
  end
  Connection = newConn
  LocalStorage = {}
  restoreConnection("mlp-user-a")
  local storedA = LocalStorage.connectionsByAccount["mlp-user-a"].connection
  LocalStorage.connectionsByAccount["mlp-user-a"].sessionCookies = { VUSESSIONID = "A" }
  restoreConnection("mlp-user-b")
  local storedB = LocalStorage.connectionsByAccount["mlp-user-b"].connection
  LocalStorage.connectionsByAccount["mlp-user-b"].sessionCookies = { VUSESSIONID = "B" }
  assertEq(storedA ~= storedB, true, "multiLogin.map.distinct")
  assertEq(
    LocalStorage.connectionsByAccount["mlp-user-a"].sessionCookies.VUSESSIONID,
    "A",
    "multiLogin.cookies.userA")
  assertEq(
    LocalStorage.connectionsByAccount["mlp-user-b"].sessionCookies.VUSESSIONID,
    "B",
    "multiLogin.cookies.userB")
  restoreConnection("mlp-user-a")
  assertEq(LocalStorage.connection, storedA, "multiLogin.reusesUserA")
  assertEq(LocalStorage.connectionAccountKey, "mlp-user-a", "multiLogin.activeKey.userA")
  restorePersistedSessionCookies(LocalStorage, true)
  assertEq(
    LocalStorage.connectionsByAccount["mlp-user-a"].sessionCookies.VUSESSIONID,
    "A",
    "multiLogin.cookies.userA.afterRestore")
end

-- base64UrlDecode: nutzt das offizielle MM.base64decode (Base64URL -> Base64 mit Padding).
do
  local seen = nil
  MM.base64urldecode = nil
  MM.base64decode = function(s) seen = s; return "decoded" end
  assertEq(base64UrlDecode("ab-_"), "decoded", "base64UrlDecode.returnsDecoded")
  assertEq(seen, "ab+/", "base64UrlDecode.alphabet")
  base64UrlDecode("ab-")
  assertEq(seen, "ab+=", "base64UrlDecode.padding")
  local rsaKey = extractPublicKeyFromJwk({kty = "RSA", n = "ab-_", e = "AQAB", kid = "k"})
  assertEq(rsaKey and rsaKey.n, "decoded", "extractPublicKeyFromJwk.rsaKeyKept")
  MM.base64decode = nil
  local ok = pcall(base64UrlDecode, "ab")
  assertEq(ok, false, "base64UrlDecode.missingApiFails")
end

-- Browser-Erkennung: TAN-Prüfung, SecureGo-Freigabe, dann "Trust this browser" (useBrowserDetection = true).
do
  local calls = {}
  local directStatus = "DIREKTFREIGABE_OFFEN"
  local hasTanMethods = true
  local originalConnection = Connection
  local originalComplete = completePostLoginFlow
  local originalLoadContracts = loadContracts
  Connection = function()
    return {
      get = function() return nil end,
      request = function(self, method, url, body, contentType, headers)
        local path = url:gsub("^https://financepilot%-pe%.mlp%.de", "")
        table.insert(calls, {method = method, path = path, body = body, contentType = contentType})
        if path:find("tan-methods-check", 1, true) then
          return hasTanMethods and '{"hasTanMethods":true}' or '{"hasTanMethods":false}'
        end
        if path:find("browser-detection-auth/start", 1, true) then
          return '{"authenticationProcessResponse":{"authenticationProcessCompleted":false,'
            .. '"resultOfCurrentAuthenticationProcessStep":{"tanProzessId":"tp-123"}}}'
        end
        if path:find("liefereTanVerfahren", 1, true) then
          return '{"tanVerfahren":[{"typ":"SECUREGO_PLUS"}]}'
        end
        if method == "GET" then
          -- Der Browser fragt den Status mit der tanProzessId ab (wie in der HAR), nicht mit der Transaktions-ID.
          if path:sub(-#"/tp-123") == "/tp-123" and path:find("direktfreigabe/authentication", 1, true) then
            return '{"status":"' .. directStatus .. '"}'
          end
          return nil
        end
        if path:find("direktfreigabe/authentication", 1, true) then
          return '{"status":"DIREKTFREIGABE_OFFEN","transaktionsIdDirektfreigabe":"tx-1"}'
        end
        if path:find("browser-detection-auth/termination", 1, true)
            or path:find("browser-detection/choose", 1, true) then
          return '{"authenticationProcessResponse":{"authenticationProcessCompleted":true}}'
        end
        return nil
      end,
      setCookie = function() end,
      getCookies = function() return "" end,
    }
  end

  startFreshConnection("mlp-browser-tan")
  assertEq(startBrowserDetectionTan(), nil, "browserTan.start.ok")
  assertEq(calls[1].path:find("tan-methods-check", 1, true) ~= nil, true, "browserTan.start.order.methods")
  assertEq(calls[2].path:find("browser-detection-auth/start", 1, true) ~= nil, true, "browserTan.start.order.start")
  assertEq(calls[3].path:find("liefereTanVerfahren", 1, true) ~= nil, true, "browserTan.start.order.delivery")
  assertEq(calls[4].method, "POST", "browserTan.start.order.approval.post")
  assertContains(calls[4].body, "tp-123", "browserTan.start.approval.usesProcessId")

  -- Bleibt die Freigabe offen, endet das Warten mit einer Fehlermeldung (ohne Dialog).
  local pending = completeBrowserDetectionTan()
  assertContains(pending, "Wartezeit", "browserTan.complete.timeoutMessage")
  assertEq(sleepCalls > 0, true, "browserTan.complete.waitsBetweenPolls")

  directStatus = "DIREKTFREIGABE_BESTAETIGT"
  assertEq(startBrowserDetectionTan(), nil, "browserTan.restart.ok")
  completePostLoginFlow = function() return true end
  loadContracts = function() return true end
  assertEq(completeBrowserDetectionTan(), nil, "browserTan.complete.success")
  local termination = calls[#calls - 1]
  assertContains(termination.path, "browser-detection-auth/termination", "browserTan.termination.path")
  assertEq(termination.body, "", "browserTan.termination.emptyBody")
  assertEq(termination.contentType, nil, "browserTan.termination.noContentType")
  local choose = calls[#calls]
  assertEq(choose.path:find("browser-detection/choose", 1, true) ~= nil, true, "browserTan.complete.chooseLast")
  assertEq(choose.body, '{"useBrowserDetection":true}', "browserTan.complete.trustThisBrowser")

  -- Ohne TAN-Verfahren: expliziter Fehler, kein Trust-Schritt.
  calls = {}
  hasTanMethods = false
  assertContains(startBrowserDetectionTan(), "kein TAN-Verfahren", "browserTan.noMethods.fails")
  assertEq(#calls, 1, "browserTan.noMethods.stopsAfterCheck")

  Connection = originalConnection
  completePostLoginFlow = originalComplete
  loadContracts = originalLoadContracts
end

-- PIN-Verschlüsselungsschlüssel: kommt aus init-ui (nach OAuth-authorize mit PKCE), nicht aus dem JWKS.
do
  local requested = {}
  local initUiBody = '{"pinEncryptionNonce":"nonce1","pinEncryptionPublicKey":'
    .. '{"kty":"RSA","e":"AQAB","use":"enc","kid":"cas-pin-encryption-prod-v2","n":"ab-_"}}'
  local originalConnection = Connection
  Connection = function()
    return {
      get = function(self, url)
        table.insert(requested, {method = "GET", url = url})
        return "ok"
      end,
      request = function(self, method, url, body, contentType, headers)
        table.insert(requested, {method = method, url = url})
        if url:find("api/init-ui", 1, true) then
          return initUiBody
        end
        return nil
      end,
      setCookie = function() end,
      getCookies = function() return "" end,
    }
  end
  startFreshConnection("mlp-pin-key")
  MM.random = function(n) return string.rep("\1", n) end
  MM.sha256 = function() return string.rep("ab", 32) end
  MM.hexToBin = function(h) return h end
  MM.base64urlencode = function(s) return "b64" end
  MM.base64decode = function(s) return "decoded" end
  local key, pinNonce = fetchPinEncryptionKey()
  assertEq(type(key) == "table" and key.n, "decoded", "pinEncryptionKey.usesInitUiKey")
  assertEq(pinNonce, "nonce1", "pinEncryptionKey.nonceFromInitUi")
  -- Der Login startet am Kundenportal (wie im Browser): dort entstehen PKCE und State für kp.mlp.de.
  assertEq(requested[1] and requested[1].url,
    "https://kundenportal.mlp.de/api/okp/login?backUrl=https://kundenportal.mlp.de/kunde",
    "pinEncryptionKey.startsAtKundenportal")
  assertEq(requested[2] and requested[2].method, "POST", "pinEncryptionKey.initUiPost")
  assertContains(
    requested[2] and requested[2].url or "",
    "api/init-ui?client_id=mlp&redirect_uri=https%3A%2F%2Fkp.mlp.de%2Fokp%2Flogin",
    "pinEncryptionKey.initUiQuery")

  -- Ohne Schlüssel in init-ui: expliziter Fehler, kein Fallback auf das JWKS.
  initUiBody = '{"pinEncryptionNonce":"nonce1"}'
  local missing, _, missingReason = fetchPinEncryptionKey()
  assertEq(missing, nil, "pinEncryptionKey.missingFails")
  assertContains(missingReason or "", "PIN-Verschlüsselungsschlüssel", "pinEncryptionKey.missingReason")

  -- Fehlt der Schlüssel, endet der JWE-Login mit Fehler.
  local noKeyLogin = performJweLogin("user", "pw")
  assertEq(noKeyLogin.success, false, "performJweLogin.noKey.fails")
  assertContains(noKeyLogin.error or "", "PIN-Verschlüsselungsschlüssel", "performJweLogin.noKey.error")

  -- Fehlt die Nonce, endet der Login mit Fehler (sie gehört in den verschlüsselten Klartext).
  initUiBody = '{"pinEncryptionPublicKey":{"kty":"RSA","e":"AQAB","use":"enc",'
    .. '"kid":"cas-pin-encryption-prod-v2","n":"ab-_"}}'
  local noNonceLogin = performJweLogin("user", "pw")
  assertContains(noNonceLogin.error or "", "pinEncryptionNonce", "performJweLogin.noNonce.error")

  -- Klartext wie im Browser: netkey = Nutzername, pin = Passwort, nonce = pinEncryptionNonce aus init-ui.
  initUiBody = '{"pinEncryptionNonce":"nonce1","pinEncryptionPublicKey":'
    .. '{"kty":"RSA","e":"AQAB","use":"enc","kid":"cas-pin-encryption-prod-v2","n":"ab-_"}}'
  local capturedPayload = nil
  local originalGenerateJwe = generateJwe
  generateJwe = function(payload)
    capturedPayload = payload
    return nil, "payload captured"
  end
  performJweLogin("user", "pw")
  generateJwe = originalGenerateJwe
  assertEq(capturedPayload ~= nil and capturedPayload.netkey, "user", "performJweLogin.payload.netkey")
  assertEq(capturedPayload ~= nil and capturedPayload.pin, "pw", "performJweLogin.payload.pin")
  assertEq(capturedPayload ~= nil and capturedPayload.nonce, "nonce1", "performJweLogin.payload.nonce")
  assertEq(capturedPayload ~= nil and capturedPayload.grant_type, nil, "performJweLogin.payload.noGrantType")
  Connection = originalConnection
end

-- Consent-Antwort: OAuth-Parameter für kp.mlp.de/okp/login.
do
  local consentWithCode = '{"postAuthenticationProcessResponse":{"resultOfCurrentPostAuthenticationProcessStep":'
    .. '{"parameter":"code=abc&state=st&iss=iss1"}}}'
  assertEq(consentAuthorizationParameters(consentWithCode), "code=abc&state=st&iss=iss1", "consent.parameters.parsed")
  local params, paramsError = consentAuthorizationParameters('{"postAuthenticationProcessResponse":{}}')
  assertEq(params, nil, "consent.parameters.missing.nil")
  assertContains(paramsError, "Autorisierungscode", "consent.parameters.missing.error")
end

-- Kundenportal-Login übergibt den Consent-Code an kp.mlp.de (wie der Browser), nicht über api/okp/login.
do
  local getUrls = {}
  local originalConnection = Connection
  Connection = function()
    return {
      get = function(_, url)
        table.insert(getUrls, url)
        return ""
      end,
      request = function() return nil end,
      setCookie = function() end,
      getCookies = function() return "" end
    }
  end
  startFreshConnection("mlp-kp-login")
  assertEq(establishKundenportalSession("code=abc&state=st&iss=iss1"), true, "kundenportal.redirectWithCode.ok")
  assertEq(getUrls[1], "https://kp.mlp.de/okp/login?code=abc&state=st&iss=iss1", "kundenportal.redirectWithCode.url")
  assertEq(getUrls[2], "https://kundenportal.mlp.de/", "kundenportal.redirectWithCode.portalRoot")
  Connection = originalConnection
end

-- Vue-Token: wie der Browser (HAR) mit Source und X-Authorization aus der Iframe-URL.
do
  local iframe = "https://vue.mlp.de/vu/client/index.html?source=https://kundenportal.mlp.de&token=tok-1"
  assertEq(queryParamFromUrl(iframe, "token"), "tok-1", "queryParam.token")
  assertEq(queryParamFromUrl(iframe, "source"), "https://kundenportal.mlp.de", "queryParam.source")
  assertEq(queryParamFromUrl(iframe, "missing"), nil, "queryParam.missing")
-- Prozentkodierte Werte (Fallback-Pfad) werden wie im Browser dekodiert.
assertEq(queryParamFromUrl("https://vue.mlp.de/vu/client/index.html?source=https%3A%2F%2Fkundenportal.mlp.de&token=t",
  "source"), "https://kundenportal.mlp.de", "queryParam.percentDecoded")

  local tokenHeaders = nil
  local originalConnection = Connection
  Connection = function()
    return {
      get = function() return "" end,
      request = function(self, method, url, body, contentType, headers)
        if url:find("/vu/api/token", 1, true) then
          tokenHeaders = headers
          return '{"ok":true}'
        end
        return nil
      end,
      setCookie = function() end,
      getCookies = function() return "" end
    }
  end
  startFreshConnection("mlp-vue-token")
  assertEq(establishVueSession(iframe), true, "vueToken.ok")
  assertEq(tokenHeaders and tokenHeaders["X-Authorization"], "tok-1", "vueToken.xAuthorization")
  assertEq(tokenHeaders and tokenHeaders["Source"], "https://kundenportal.mlp.de", "vueToken.source")

  -- Ein 403 des Token-Endpunkts ist ein Fehler, kein Erfolg.
  Connection = function()
    return {
      get = function() return "" end,
      request = function(self, method, url)
        if url:find("/vu/api/token", 1, true) then
          return '{"timestamp":"t","status":403,"error":"Forbidden","path":"/vu/api/token"}'
        end
        return nil
      end,
      setCookie = function() end,
      getCookies = function() return "" end
    }
  end
  startFreshConnection("mlp-vue-token-403")
  assertEq(establishVueSession(iframe), false, "vueToken.forbiddenFails")
  Connection = originalConnection
end

-- Session-Prüfung und Laden der Vertragsliste teilen sich eine Anfrage.
do
  local contractRequests = 0
  local originalConnection = Connection
  Connection = function()
    return {
      get = function() return "" end,
      request = function(self, method, url)
        if url:find("contract/list", 1, true) then
          contractRequests = contractRequests + 1
          return '{"contractList":[{"id":"c-1","number":"N1","shareValue":"10","contribution":"5","posTypeList":[]}]}'
        end
        return nil
      end,
      setCookie = function() end,
      getCookies = function() return "" end
    }
  end
  startFreshConnection("mlp-contract-once")
  assertEq(isAuthenticated(), true, "contractList.probeValid")
  assertEq(loadContracts(), true, "contractList.loadsFromProbe")
  assertEq(contractRequests, 1, "contractList.singleRequest")
  Connection = originalConnection
end

print()
print("ALL TESTS PASSED")
