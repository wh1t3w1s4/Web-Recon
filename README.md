# Web-Recon-v0.1.2-alpha
The web reconnaissance tool by w1s4

**Estado del proyecto: alpha (v0.1.2)** — en fase de pruebas con feedback de terceros. Puede tener bugs, comportamiento inconsistente entre targets, y cambiar bastante entre versiones. No recomendado todavía para uso en entornos críticos sin supervisión.

Web-Recon es un script en bash para automatizar la fase de reconocimiento (pasivo y activo) sobre un dominio objetivo. Encadena varias herramientas estándar de recon y aplica algo de lógica propia para reducir ruido en los resultados (filtrado de falsos positivos en fuzzing, detección de wildcard, agrupación de patrones repetidos, detección de versiones vulnerables conocidas, etc.).

Esta herramienta está pensada únicamente para uso en auditorías, CTFs, bug bounty o programas de pentesting donde se cuenta con autorización explícita sobre el objetivo.

## Qué hace

El script se divide en dos fases. En modo normal se ejecutan ambas; en modo subdominio (`-s`) solo se ejecuta la parte de la Fase 2 que tiene sentido sobre un host concreto (ver más abajo).

### Fase 1 — Reconocimiento pasivo

- **WHOIS**: información de registro del dominio.
- **Resolución DNS**: registros A vía `dig`, limitado a las primeras IPs resueltas.
- **Registros DNS adicionales**: MX, NS, TXT, SOA, CNAME y CAA, con un intérprete que anota automáticamente patrones conocidos (SPF/DKIM/DMARC en TXT, proveedores de correo y DNS habituales, posibles candidatos a subdomain takeover en CNAME, autoridades de certificación en CAA, etc.).
- **IP info**: script propio de geolocalización aproximada y datos de cada IP resuelta (ISP, ASN, DNS inverso).

### Fase 2 — Reconocimiento activo

- **Detección de protocolo**: comprueba si el objetivo responde por HTTP, HTTPS o ninguno de los dos, antes de lanzar el resto de módulos.
- **Fingerprinting web**: `whatweb` en modo verbose. Si detecta un bloqueo de Cloudflare (403 + challenge), omite la salida completa y avisa en su lugar.
- **Detección de vulnerabilidades conocidas por versión**: cruza las tecnologías y versiones detectadas por `whatweb` contra una base de datos local de CVEs comprobables (jQuery, Bootstrap, nginx, Apache, OpenSSL, PHP, etc.), reportando coincidencias con su CVE y referencia.
- **Detección de WordPress**: si `whatweb` detecta el CMS, lanza `wpscan` automáticamente en modo pasivo (detección por rastro en HTML, sin barrido activo de slugs) en busca de plugins/temas vulnerables y usuarios, con límite de tiempo (`timeout`) como salvaguarda.
- **WAF detection**: `wafw00f` para identificar si hay un WAF delante del objetivo.
- **Fuzzing de directorios**: `ffuf` contra el objetivo, con:
  - Autocalibración (`-ac`) para mitigar comportamiento wildcard.
  - Reducción automática de hilos (de 80 a 20) si se detecta rate-limiting (códigos 429/503/508).
  - Agrupación de resultados por status/words/lines para detectar patrones repetidos (falsos positivos).
  - Resultados "limpios" mostrados directamente; resultados "sospechosos" (patrón repetido) resueltos con `httpx` o `curl` como fallback.
  - Matches visibles en tiempo real a medida que se encuentran.
- **robots.txt**: extracción de rutas `Disallow`/`Allow`, filtrando comentarios y líneas irrelevantes.
- **Descubrimiento de subdominios** *(solo en modo normal, omitido con `-s`)*:
  - `subfinder` como fuente principal.
  - `crt.sh` (Certificate Transparency) como fuente complementaria, con reintentos, backoff y parseo robusto de CSV/JSON (vía Python, evita el ruido de campos con comas internas).
  - Unión y deduplicación de ambas fuentes.
  - Verificación de cuáles subdominios responden realmente, filtrando 404s.

## Modo subdominio (`-s`)

Pensado para cuando el objetivo ya es un subdominio conocido (por ejemplo, tras descubrirlo en un escaneo anterior) y no tiene sentido repetir WHOIS, registros DNS del dominio raíz, ni volver a buscar subdominios de un subdominio.

Con `-s` se omiten: WHOIS, registros DNS adicionales, y todo el bloque de descubrimiento de subdominios (subfinder/crt.sh/verificación de vivos).

Se mantienen: IP + geolocalización, detección de protocolo, whatweb, detección de vulnerabilidades por versión, WordPress/wpscan, wafw00f, fuzzing de directorios y robots.txt.

## Kill switch

En cualquier momento de la ejecución, **Ctrl+K** finaliza el script de forma inmediata y limpia (restaura la configuración del terminal antes de salir). Útil para escaneos que se alargan más de lo esperado sin tener que cerrar la terminal.

## Requisitos del sistema

Probado en **Debian/Ubuntu**. No hay soporte todavía para Arch, Fedora o macOS — el instalador (`setup.sh`) asume `apt` como gestor de paquetes.

## Instalación / Dependencias

La forma recomendada es usar el script de instalación incluido, que resuelve todas las dependencias automáticamente (paquetes de sistema, herramientas Go, wafw00f, wpscan con su base de datos actualizada, la wordlist de fuzzing e `ipinfo`):

```bash
git clone https://github.com/wh1t3w1s4/Web-Recon
cd Web-Recon
chmod +x setup.sh
./setup.sh
```

Al terminar, `setup.sh` muestra un resumen indicando qué dependencias quedaron instaladas correctamente y cuáles requieren atención manual.

Si prefieres instalar todo a mano, consulta la tabla de dependencias a continuación.

| Herramienta | Uso | Instalación manual |
|---|---|---|
| `whois` | Fase 1 | `apt install whois` |
| `dig` | Fase 1 | `apt install dnsutils` |
| `curl` | Todas las fases | `apt install curl` |
| `jq` | Parseo de JSON (ffuf, crt.sh) | `apt install jq` |
| `python3` | Parseo robusto de CSV (fallback de crt.sh) | `apt install python3` |
| `whatweb` | Fase 2 | `apt install whatweb` |
| `wafw00f` | Fase 2 | `pip install wafw00f` |
| `wpscan` | Fase 2 (si detecta WordPress) | `gem install wpscan` |
| `ffuf` | Fase 2 | `go install github.com/ffuf/ffuf/v2@latest` |
| `subfinder` | Fase 2 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` (ProjectDiscovery) | Fase 2 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `dirb` | Wordlist de fuzzing (`big.txt`) | `apt install dirb` |

Si falta alguna dependencia, el script avisa al inicio e indica el comando de instalación. Las fases que dependen de una herramienta ausente se omiten o caen a un fallback (por ejemplo, `curl` en lugar de `httpx`) en vez de interrumpir la ejecución completa.

> Nota: `httpx` de ProjectDiscovery puede entrar en conflicto con el paquete de Python del mismo nombre (`pip install httpx`, un cliente HTTP). El script referencia el binario por ruta absoluta (`$HOME/.go/bin/httpx` por defecto) para evitar ambigüedad. Si lo tienes en otra ubicación, puedes indicarlo con la variable de entorno `HTTPX_BIN`.

### Token de la API de WPScan (opcional)

Si tienes un token gratuito de [wpscan.com](https://wpscan.com/), el script lo usa automáticamente para consultar su base de datos de vulnerabilidades. Expórtalo antes de ejecutar el script:

```bash
export WPSCAN_API_TOKEN="tu_token_aqui"
```

Sin token, wpscan sigue funcionando igual para detección de plugins/temas/usuarios, solo sin el cruce contra la base de datos de CVEs de WPScan.

## Uso

```bash
./web_recon.sh [opciones] <dominio>
```

| Opción | Descripción |
|---|---|
| `-o, --output <ruta>` | Carpeta base donde se guardarán los resultados (por defecto: `./resultados`) |
| `-n, --no-export` | No crea carpeta ni exporta nada, solo muestra en pantalla |
| `-s, --subdomain` | Modo subdominio: omite WHOIS, DNS extra y descubrimiento de subdominios |
| `-h, --help` | Muestra la ayuda de uso |

Ejemplos:

```bash
./web_recon.sh ejemplo.com
./web_recon.sh -o /home/user/pentest ejemplo.com
./web_recon.sh -n ejemplo.com
./web_recon.sh -s admin.ejemplo.com
```

Si el dominio no responde por HTTP ni HTTPS, la Fase 2 se omite automáticamente, el script informa del motivo y se finaliza la ejecución.

## Resultados exportados

Salvo que uses `-n`, cada ejecución crea una carpeta `<ruta_base>/<target>_<timestamp>/` con:

- **`reporte_final.md`** — resumen completo del escaneo en Markdown, con jerarquía por fase y módulo.
- **`subdominios_vivos.txt`** — subdominios que respondieron correctamente, tras verificación con `httpx` (no se genera en modo `-s`).
- **`wordpress.txt`** — solo se genera si se detecta WordPress y `wpscan` reporta hallazgos.

### Ejemplo de salida completa

```
[ Pega aquí un escaneo de ejemplo actualizado, con el dominio real anonimizado,
  que refleje ya el bloque de vulnerabilidades por versión y el intérprete de DNS ]
```

## Wordlists

Por defecto el script usa wordlists locales para fuzzing de directorios y subdominios (ajustables directamente en el script). Revisa las rutas configuradas antes de ejecutar si tu wordlist está en otra ubicación:

- Directorios: `big.txt` (ruta por defecto: `/usr/share/dirb/wordlists/big.txt`, instalada vía el paquete `dirb`). También existe en [SecLists](https://github.com/danielmiessler/SecLists), con un catálogo más amplio, si prefieres cambiar la ruta manualmente.
- Subdominios (vía subfinder): no requiere wordlist propia, usa fuentes OSINT

## Vulnerabilidades conocidas por versión

El script incluye una pequeña base de datos local (editable directamente en el script, variable `VULN_DB`) que compara las versiones detectadas por `whatweb` contra rangos de versiones con CVEs documentados. Es una comprobación determinista (versión detectada < versión con fix conocido → aviso), no un escáner de vulnerabilidades completo.

Limitaciones a tener en cuenta:
- Un backport de seguridad (parche aplicado sin cambiar el número de versión reportado) puede generar un falso positivo.
- Solo cubre las tecnologías añadidas manualmente a `VULN_DB` — no es una base de datos exhaustiva ni se actualiza automáticamente.
- Un WAF u otra mitigación externa puede impedir la explotación real aunque la versión coincida.

## Pendiente / roadmap

Próximo en la lista:
- **Análisis de headers HTTP y cookies de seguridad**: ausencia de `HttpOnly`, `Secure`, `SameSite`, `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, documentando el riesgo concreto de cada ausencia (ej. cookie sin `HttpOnly` → robable vía `document.cookie` en caso de XSS).

Más adelante:
- Cruce con `searchsploit` para detectar exploits públicos conocidos sobre las versiones identificadas (más allá del CVE documentado en `VULN_DB` — esto sería "¿hay una PoC pública ahora mismo?").
- Ampliar la base de datos de vulnerabilidades por versión (`VULN_DB`).
- Export adicional en JSON, para post-procesado o integración con otras herramientas.
- Comparación entre escaneos de un mismo target en distintas fechas (qué cambió: subdominios nuevos, versiones, directorios).
- Comparación de postura de seguridad entre el dominio principal y sus subdominios — detectar subdominios con protecciones sensiblemente más débiles que el dominio raíz.
- Mejorar la fiabilidad de la detección/análisis de WordPress en casos límite.
- Screenshots de subdominios/directorios vivos.
- Listado detallado de los resultados "sospechosos" del fuzzing en el reporte (actualmente solo se indica el conteo).

## Feedback y reporte de bugs

Este proyecto está en fase alpha y agradece cualquier feedback. Si encuentras un bug, un comportamiento raro, o algo que no funciona como esperabas, abre un **Issue** en este repositorio incluyendo:

- El comando exacto que ejecutaste
- La salida obtenida (o el error completo)
- El sistema operativo y versión donde lo probaste

Esto ayuda muchísimo más que el feedback informal, y queda trazado para futuras versiones.

## Uso responsable

Esta herramienta está pensada para usarse únicamente contra objetivos sobre los que se tiene autorización explícita (programas de bug bounty, pentesting contratado, laboratorios propios, CTFs). El escaneo de dominios sin autorización puede ser ilegal según la jurisdicción. El autor no se hace responsable del uso indebido de este script.

## Licencia

Este proyecto está licenciado bajo **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)**.

En resumen:
- Puedes usar, modificar y redistribuir el código libremente.
- Debes dar crédito al autor original.
- No está permitido ningún uso comercial ni con ánimo de lucro.
- Cualquier versión modificada debe distribuirse bajo esta misma licencia.

Texto completo: https://creativecommons.org/licenses/by-nc-sa/4.0/deed.es
