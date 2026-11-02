# MLP Versicherungen — MoneyMoney-Erweiterung

MLP-Versicherungsverträge (Kundenportal) in MoneyMoney.

Version: **1.0**
Repository: https://github.com/rosch100/MLP-Versicherungen-MoneyMoney
Gemeinsame Infos: https://github.com/rosch100/moneymoney-extensions

Das ist nicht das FinTS-Giro der MLP Bank, sondern nur die Versicherungen
im Kundenportal.

## Installation

Noch nicht auf [moneymoney.app/extensions](https://moneymoney.app/extensions/) —
Veröffentlichung mit dem nächsten MoneyMoney-Update (Whitelist).

Unsignierte Datei:
[MLP Versicherungen.lua](https://raw.githubusercontent.com/rosch100/MLP-Versicherungen-MoneyMoney/main/MLP%20Versicherungen.lua)

Datei nach
`~/Library/Containers/com.moneymoney-app.retail/Data/Library/Application Support/MoneyMoney/Extensions`
kopieren, oder im Klon `./link_ext.sh` ausführen.

Unsignierte Erweiterungen laufen nur, wenn die Signaturprüfung unter
*MoneyMoney → Einstellungen → Erweiterungen* ausgeschaltet ist.

## Einrichten

*Konto hinzufügen* → *Andere* → **MLP Versicherungen**.

Anmelden mit Benutzername und Passwort des MLP-Kundenportals. Danach bestätigen
Sie den Login in der **SecureGo-Plus-App**. MoneyMoney wartet dort bis zu zwei
Minuten auf Ihre Freigabe. Danach lädt die Erweiterung die Verträge.

Cookie-Import (`COOKIE:…`) gibt es in Version 1.0 nicht.

## Nutzung

Nach dem Einrichten den Zugang aktualisieren.

- Jeder Versicherungsvertrag mit Anteilswert erscheint als eigenes Konto. Der
  Kontoname enthält Versicherer, Vertragsnummer, Tarif und, falls vorhanden, das
  Datum „Beitrag bis“. Verträge ohne Anteilswert werden nicht angelegt.
- Solange die gespeicherte Sitzung gilt, ist keine neue SecureGo-Freigabe nötig.
- Ein Abruf ohne Ihre Eingabe, etwa eine Hintergrund-Aktualisierung, startet
  keine Freigabe. Ist die Sitzung abgelaufen, bricht der Abruf mit der Meldung
  ab, den Login in MoneyMoney manuell zu starten. Dann den Zugang aktualisieren
  und die Freigabe in der App bestätigen.

## Fehler & Ideen

Issues bitte über GitHub melden:
[Neues Issue](https://github.com/rosch100/MLP-Versicherungen-MoneyMoney/issues/new/choose).
Keine MoneyMoney-Logdateien anhängen — Details stehen im Bug-Formular.

## Lizenz

MIT — siehe [LICENSE](LICENSE).
