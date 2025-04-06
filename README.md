# testi-poista

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
