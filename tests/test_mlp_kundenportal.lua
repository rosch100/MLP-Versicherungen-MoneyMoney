-- Tests für MLP Versicherungen Extension v0.91
-- Testet Hilfsfunktionen, Login-State-Machine und Datenstrukturen

-- WebBanking/Connection/MM stubben
function WebBanking(_) end

ProtocolWebBanking = "WebBanking"
AccountTypePortfolio = 5
LoginFailed = "LoginFailed"

-- Minimaler JSON-Stub für parseLoginResponse-Tests
JSON = function(jsonStr)
  return {
    dictionary = function()
      local result = {}
      for key, value in jsonStr:gmatch('"([^"]+)"%s*:%s*"([^"]*)"') do
        result[key] = value
      end
      for key, value in jsonStr:gmatch('"([^"]+)"%s*:%s*(%d+)') do
        result[key] = tonumber(value)
      end
      for key, value in jsonStr:gmatch('"([^"]+)"%s*:%s*(true|false)') do
        result[key] = (value == "true")
      end
      return result
    end,
    array = function() return {} end
  }
end

MM = {
  printStatus = function(msg) io.stderr:write("[STATUS] " .. msg .. "\n") end,
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

local mfaLogin = parseLoginResponse('{"challengeToken":"abc123","mfaRequired":true}')
assertEq(mfaLogin.requiresMfa, true, "parseLoginResponse.mfa.required")
assertEq(mfaLogin.mfaToken, "abc123", "parseLoginResponse.mfa.token")

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

-- ============================================================
-- Tests: Cookie-Parsing
-- ============================================================

print()
print("=== Test: Cookie-Parsing ===")

parseCookieString("VUSESSIONID=first;BIGipServervue.mlp.de=lb1;VUSESSIONID=second")
local cookieHeader = buildCookieHeader(true)
assertContains(cookieHeader, "VUSESSIONID=first", "parseCookie.vu1")
assertContains(cookieHeader, "VUSESSIONID=second", "parseCookie.vu2")
assertContains(cookieHeader, "BIGipServervue.mlp.de=lb1", "parseCookie.bigip")

parseCookieString("VUSESSIONID=jar1; VUSESSIONID=jar2; BIGipServervue.mlp.de=jarlb")
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

local missingMfaState = InitializeSession2(
  ProtocolWebBanking,
  "MLP Versicherungen",
  2,
  {"123456"},
  true)
assertEq(type(missingMfaState), "string", "InitializeSession2.missingMfaState.type")
assertEq(missingMfaState, "MFA-Session abgelaufen. Bitte neu einloggen.",
  "InitializeSession2.missingMfaState.message")

local firstConnection = {
  language = "",
  useragent = "test",
  get = function() return nil end,
  getCookies = function() return "" end,
  request = function()
    return '{"pending":true}'
  end,
}
local restoredMfaCalls = 0
local restoredConnection = {
  language = "",
  useragent = "test",
  get = function() return nil end,
  getCookies = function() return "" end,
  request = function()
    restoredMfaCalls = restoredMfaCalls + 1
    return '{"pending":true}'
  end,
}
Connection = function()
  return firstConnection
end
LocalStorage = {}
performLogin = function()
  return {success = false, requiresMfa = true, mfaToken = "mfa-token"}
end
local mfaChallenge = InitializeSession2(
  ProtocolWebBanking,
  "MLP Versicherungen",
  1,
  {"mlp-user", "password"},
  true)
assertEq(type(mfaChallenge), "table", "InitializeSession2.mfaChallenge")
LocalStorage.connection = restoredConnection
LocalStorage.connectionAccountKey = "mlp-user"
InitializeSession2(
  ProtocolWebBanking,
  "MLP Versicherungen",
  2,
  {"123456"},
  true)
assertEq(restoredMfaCalls, 1, "InitializeSession2.restoresConnectionForStep2")

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

performLogin = function()
  return {
    success = false,
    error = "403 Invalid credentials",
    needsCookie = true,
  }
end
tryCookieAuth = function()
  return "Cookie-Import erforderlich"
end
assertEq(
  loginStep1({"mlp-user", "wrong"}),
  LoginFailed,
  "loginStep1.classifiesCredentialsBeforeCookieFallback")

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

print()
print("ALL TESTS PASSED")
