# testi-poista

|   | Lainaus <br>merkeittä | "Lainaus" <br>merkeissä | 'Puolilainaus' <br>merkeissä |
|:--- |:--- |:--- |:--- |
| **Selkoteksti:**<br>teksti | <br>teksti | <br>teksti | <br>teksti |
| **Tilde-laajennus:**<br>~/\*.txt | <br>**/home/tuula/\*.txt** | <br>~/\*.txt | <br>~/\*.txt |
| **Sulku-laajennus:**<br>{a,b}<br>{001..003} | <br>**a b**<br>**001 002 003** | <br>{a,b}<br>{001..003} | <br>{a,b}<br>{001..003} |
| **Komennon-korvaus:**<br>$(uname ‑o)<br>\`uname ‑o\` | <br>**GNU/Linux**<br>**GNU/Linux** | <br>**GNU/Linux**<br>**GNU/Linux** | <br>$(uname ‑o)<br>\`uname ‑o\` |
| **Lasku-laajennus:**<br>$((2+2)) | <br>**4** | <br>**4** | <br>$((2+2)) |
| **Parametri-laajennus:**<br>$USER | <br>**tuula** | <br>**tuula** | <br>$USER |

|   | Lainaus <br>merkeittä | "Lainaus" <br>merkeissä | 'Puolilainaus' <br>merkeissä |
|:--- |:--- |:--- |:--- |
| **Simple string:**<br>teksti | <br>teksti | <br>teksti | <br>teksti |
| **Tilde expansion:**<br>~/\*.txt | <br>**/home/tuula/\*.txt** | <br>~/\*.txt | <br>~/\*.txt |
| **Brace expansion:**<br>{a,b}<br>{001..003} | <br>**a b**<br>**001 002 003** | <br>{a,b}<br>{001..003} | <br>{a,b}<br>{001..003} |
| **Command substitution:**<br>$(uname ‑o)<br>\`uname ‑o\` | <br>**GNU/Linux**<br>**GNU/Linux** | <br>**GNU/Linux**<br>**GNU/Linux** | <br>$(uname ‑o)<br>\`uname ‑o\` |
| **Arithmetic expansion:**<br>$((2+2)) | <br>**4** | <br>**4** | <br>$((2+2)) |
| **Parameter expansion:**<br>$USER | <br>**tuula** | <br>**tuula** | <br>$USER |

|   | Esimerkki | Lainaus <br>merkeittä | "Lainaus" <br>merkeissä | 'Puolilainaus' <br>merkeissä |
|:--- |:--- |:--- |:--- |:--- |
| Teksti | teksti | teksti | teksti | teksti |
| **Tilde expansion** | ~/\*.txt | **/home/tuula/\*.txt** | ~/\*.txt | ~/\*.txt |
| **Brace expansion** | {a,b}<br>{001..003} | **a b**<br>**001 002 003** | {a,b}<br>{001..003} | {a,b}<br>{001..003} |
| **Command substitution** | $(uname ‑o)<br>\`uname ‑o\` | **GNU/Linux**<br>**GNU/Linux** | **GNU/Linux**<br>**GNU/Linux** | $(uname ‑o)<br>\`uname ‑o\` |
| **Arithmetic expansion** | $((2+2)) | **4** | **4** | $((2+2)) |
| **Parameter expansion** | $USER | **tuula** | **tuula** | $USER |

| Esimerkki | Lainaus <br>merkeittä | "Lainaus" <br>merkeissä | 'Puolilainaus' <br>merkeissä |
|:--- |:--- |:--- |:--- |
| teksti | teksti | teksti | teksti |
| ~/\*.txt | **/home/tuula/\*.txt** | ~/\*.txt | ~/\*.txt |
| {a,b}<br>{001..003} | **a b**<br>**001 002 003** | {a,b}<br>{001..003} | {a,b}<br>{001..003} |
| $(uname ‑o)<br>\`uname ‑o\` | **GNU/Linux**<br>**GNU/Linux** | **GNU/Linux**<br>**GNU/Linux** | $(uname ‑o)<br>\`uname ‑o\` |
| $((2+2)) | **4** | **4** | $((2+2)) |
| $USER | **tuula** | **tuula** | $USER |
