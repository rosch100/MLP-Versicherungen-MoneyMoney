# MLP Versicherungen — MoneyMoney Extension
Plugin Homepage: https://github.com/rosch100/MLP-Versicherungen-MoneyMoney
Bank/Portal: https://kundenportal.mlp.de
Version: **0.91**
Status: Beta — Cookie-Import; JWE/SecureGo wenn MM-Krypto-APIs da
Hub (gemeinsame Tools/Doku): https://github.com/rosch100/moneymoney-extensions
## Installation
Unsignierte Datei: [MLP Versicherungen.lua](https://raw.githubusercontent.com/rosch100/MLP-Versicherungen-MoneyMoney/main/MLP%20Versicherungen.lua)
Datei nach `~/Library/Containers/com.moneymoney-app.retail/Data/Library/Application Support/MoneyMoney/Extensions` kopieren, oder im Klon `./link_ext.sh` ausführen.
Unsignierte Plugins: MoneyMoney-**Beta**, Signaturprüfung in den Erweiterungseinstellungen aus.
## Tests
`sh
python3 tests/test_conformance.py
luajit tests/test_mlp_kundenportal.lua

`
Aus dem Repo-Root ausführen.

