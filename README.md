# Web-Recon

**v0.2.0-beta** — primera versión fuera de pruebas puramente internas.

> ⚠️ Puede tener comportamiento inconsistente en targets con configuraciones poco habituales (wildcard DNS agresivo, SPAs con enrutado del lado del cliente, WAFs muy agresivos). No recomendada para entornos críticos sin supervisión.

Web-Recon es un script en bash para automatizar la fase de reconocimiento (pasivo y activo) sobre un dominio objetivo. Encadena varias herramientas estándar de recon y aplica lógica propia para reducir ruido en los resultados: filtrado de falsos positivos en fuzzing, detección de wildcard, agrupación de patrones repetidos, detección de versiones vulnerables conocidas, análisis de cabeceras/cookies, bypass de 403, y rotación de User-Agent.

Esta herramienta está pensada únicamente para uso en auditorías, CTFs, bug bounty o programas de pentesting donde se cuenta con autorización explícita sobre el objetivo.

---

## Índice

- [Instalación](#instalación)
- [Uso](#uso)
- [Qué hace](#qué-hace)
  - [Fase 1 — Reconocimiento pasivo](#fase-1--reconocimiento-pasivo)
  - [Fase 2 — Reconocimiento activo](#fase-2--reconocimiento-activo)
- [Modo subdominio (`-s`)](#modo-subdominio--s)
- [Bypass de 403 — comportamiento según el modo](#bypass-de-403--comportamiento-según-el-modo)
- [Rotación de User-Agent](#rotación-de-user-agent)
- [Dependencias](#dependencias)
- [Token de la API de WPScan (opcional)](#token-de-la-api-de-wpscan-opcional)
- [Resultados exportados](#resultados-exportados)
- [Ejemplo de salida](#ejemplo-de-salida)
- [Wordlists](#wordlists)
- [Vulnerabilidades conocidas por versión](#vulnerabilidades-conocidas-por-versión)
- [Feedback y reporte de bugs](#feedback-y-reporte-de-bugs)
- [Uso responsable](#uso-responsable)
- [Licencia](#licencia)

---

## Instalación

```bash
git clone https://github.com/wh1t3w1s4/Web-Recon
cd Web-Recon
chmod +x setup.sh
./setup.sh
```

`setup.sh` instala todas las dependencias automáticamente (paquetes de sistema, herramientas Go, wafw00f, wpscan con su base de datos actualizada, la wordlist de fuzzing e ipinfo) y muestra un resumen al final indicando qué quedó instalado correctamente y qué requiere atención manual.

## Uso

```bash
./web_recon.sh [opciones] <dominio>
```

### Opciones

| Opción | Descripción |
| --- | --- |
| `-o`, `--output <ruta>` | Carpeta base donde se guardarán los resultados (por defecto: `./resultados`) |
| `-n`, `--no-export` | No crea carpeta ni exporta nada, solo muestra en pantalla. Habilita la pregunta interactiva de bypass de 403 |
| `-s`, `--subdomain` | Modo subdominio: omite WHOIS, DNS extra y descubrimiento de subdominios |
| `-h`, `--help` | Muestra la ayuda de uso |

### Ejemplos

```bash
./web_recon.sh ejemplo.com
./web_recon.sh -o /home/user/pentest ejemplo.com
./web_recon.sh -n ejemplo.com
./web_recon.sh -s admin.ejemplo.com
```

Si el dominio no responde por HTTP ni HTTPS, la Fase 2 se omite automáticamente, el script informa del motivo y finaliza.

`Ctrl+K` corta la ejecución de forma inmediata y limpia en cualquier momento del escaneo.

## Qué hace

El script se divide en dos fases. En modo normal se ejecutan ambas; en modo subdominio (`-s`) solo se ejecuta la parte de la Fase 2 que tiene sentido sobre un host concreto.

### Fase 1 — Reconocimiento pasivo

- **WHOIS:** información de registro del dominio.
- **Resolución DNS:** registros A vía `dig`, limitado a las primeras IPs resueltas.
- **Registros DNS adicionales:** MX, NS, TXT, SOA, CNAME y CAA, con un intérprete que anota automáticamente patrones conocidos: SPF/DKIM/DMARC en TXT, proveedores de correo y DNS habituales, posibles candidatos a subdomain takeover en CNAME, autoridades de certificación en CAA.
- **IP info:** script propio de geolocalización aproximada y datos de cada IP resuelta (ISP, ASN, DNS inverso).

### Fase 2 — Reconocimiento activo

- **Detección de protocolo:** comprueba si el objetivo responde por HTTP, HTTPS o ninguno de los dos, antes de lanzar el resto de módulos.
- **Fingerprinting web:** `whatweb` en modo verbose. Si detecta un bloqueo de Cloudflare (403 + challenge), omite la salida completa y avisa en su lugar.
- **Vulnerabilidades conocidas por versión:** cruza las tecnologías y versiones detectadas por `whatweb` contra una base de datos local de CVEs comprobables (jQuery, Bootstrap, nginx, Apache, OpenSSL, PHP, etc.), reportando coincidencias con su CVE y referencia.
- **Cabeceras de seguridad y cookies:** en una única pasada analiza HSTS, X-Frame-Options/frame-ancestors, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, configuración de CORS, y exposición de información vía X-Powered-By/Server. Sobre las cookies de sesión evalúa HttpOnly, Secure y SameSite, documentando el riesgo concreto de cada ausencia (por ejemplo, cookie sin HttpOnly → robable vía `document.cookie` en caso de XSS). Si no hay cookies en la raíz, reintenta contra `/login`.
- **Detección de WordPress:** si `whatweb` detecta el CMS, lanza `wpscan` automáticamente en modo pasivo (detección por rastro en HTML, sin barrido activo de slugs) en busca de plugins/temas vulnerables y usuarios, con límite de tiempo como salvaguarda.
- **WAF detection:** `wafw00f` para identificar si hay un WAF delante del objetivo.
- **Fuzzing de directorios:** `ffuf` contra el objetivo, con:
  - Autocalibración (`-ac`) para mitigar comportamiento wildcard.
  - Reducción automática de hilos (de 80 a 20) si se detecta rate-limiting (códigos 429/503/508).
  - Agrupación de resultados por status/words/lines para detectar patrones repetidos (falsos positivos).
  - Resultados "limpios" mostrados directamente; resultados "sospechosos" (patrón repetido) resueltos con `httpx` o `curl` como fallback.
  - Matches visibles en tiempo real a medida que se encuentran.
- **Bypass de 403:** si el fuzzing detecta rutas con código 403, prueba variaciones de ruta (barra final, doble barra, encoding, mayúsculas, `..;/`) y de cabeceras (`X-Original-URL`, `X-Forwarded-For`, `Referer`, etc.) para comprobar si el filtro es evitable. Solo se muestran variaciones con código distinto de 403/404, siguiendo redirecciones para descartar 301 que acaban en la misma pared.
- **`robots.txt`:** extracción de rutas Disallow/Allow, filtrando comentarios y líneas irrelevantes.
- **Descubrimiento de subdominios** (solo en modo normal):
  - `subfinder` como fuente principal.
  - `crt.sh` (Certificate Transparency) como fuente complementaria, con reintentos, backoff y parseo robusto de CSV/JSON (vía Python, evita el ruido de campos con comas internas).
  - Unión y deduplicación de ambas fuentes.
  - Verificación de cuáles subdominios responden realmente, filtrando 404s.

## Modo subdominio (`-s`)

Pensado para cuando el objetivo ya es un subdominio conocido (por ejemplo, tras descubrirlo en un escaneo anterior) y no tiene sentido repetir WHOIS, registros DNS del dominio raíz, ni volver a buscar subdominios de un subdominio.

- **Se omiten:** WHOIS, registros DNS adicionales, y todo el bloque de descubrimiento de subdominios.
- **Se mantienen:** IP + geolocalización, protocolo, `whatweb`, vulnerabilidades por versión, cabeceras/cookies, WordPress/`wpscan`, `wafw00f`, fuzzing de directorios, bypass de 403 y `robots.txt`.

## Bypass de 403 — comportamiento según el modo

- **Con `-n`:** si el fuzzing detecta al menos un 403, se pregunta interactivamente `¿Quieres intentar técnicas de bypass sobre ellas? [y/N]` (case-insensitive). Solo se ejecuta si se confirma.
- **En modo normal:** se informa de cuántas rutas con 403 se detectaron, sin preguntar ni ejecutar, para no interrumpir un flujo pensado para dejarse corriendo sin intervención.

## Rotación de User-Agent

Cada petición HTTP del script (`whatweb`, `ffuf`, `curl`, `wafw00f`, `robots.txt`, bypass de 403, análisis de cookies) usa un User-Agent aleatorio de una lista de navegadores/sistemas operativos reales y actuales, en vez de uno fijo. Reduce falsos negativos frente a WAFs con reglas simples basadas en User-Agent.

No es una técnica de evasión completa: WAFs más sofisticados (Cloudflare, Akamai) detectan mucho más allá del User-Agent — frecuencia de peticiones, orden de cabeceras, TLS fingerprinting. Esta mejora ayuda en el primer caso, no en el segundo.

## Dependencias

| Herramienta | Uso | Instalación manual |
| --- | --- | --- |
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
| `dirb` | Wordlist de fuzzing (big.txt) | `apt install dirb` |

Si falta alguna dependencia, el script avisa al inicio e indica el comando de instalación. Las fases que dependen de una herramienta ausente se omiten o caen a un fallback (por ejemplo, `curl` en lugar de `httpx`) en vez de interrumpir la ejecución.

> **Nota:** `httpx` de ProjectDiscovery puede entrar en conflicto con el paquete de Python del mismo nombre (`pip install httpx`). El script referencia el binario por ruta absoluta (`$HOME/.go/bin/httpx` por defecto). Si lo tienes en otra ubicación, indícalo con `HTTPX_BIN`.

## Token de la API de WPScan (opcional)

```bash
export WPSCAN_API_TOKEN="tu_token_aqui"
```

Con un token gratuito de [wpscan.com](https://wpscan.com), `wpscan` consulta su base de datos de CVEs. Sin token, sigue detectando plugins/temas/usuarios igualmente, solo sin ese cruce adicional.

## Resultados exportados

Salvo que uses `-n`, cada ejecución crea `<ruta_base>/<target>_<timestamp>/` con:

- `reporte_final.md` — resumen completo del escaneo en Markdown.
- `subdominios_vivos.txt` — subdominios que respondieron correctamente, tras verificación con `httpx` (no se genera en modo `-s`).
- `wordpress.txt` — solo si se detecta WordPress y `wpscan` reporta hallazgos.

## Ejemplo de salida

> [ Pega aquí un escaneo real anonimizado, actualizado con los módulos de vulnerabilidades por versión, cabeceras/cookies y bypass de 403 ]

## Wordlists

- **Directorios:** `big.txt` (ruta por defecto: `/usr/share/dirb/wordlists/big.txt`, instalada vía `dirb`). También disponible en SecLists si prefieres cambiar la ruta manualmente.
- **Subdominios (`subfinder`):** no requiere wordlist propia, usa fuentes OSINT.

## Vulnerabilidades conocidas por versión

`VULN_DB` (editable directamente en el script) compara versiones detectadas por `whatweb` contra rangos con CVEs documentados. Comprobación determinista (versión < versión con fix → aviso), no un escáner completo.

Limitaciones:

- Un backport de seguridad puede generar falso positivo.
- Solo cubre lo añadido manualmente a `VULN_DB`.
- Un WAF u otra mitigación puede impedir la explotación real aunque la versión coincida.

## Feedback y reporte de bugs

Abre un [Issue](https://github.com/wh1t3w1s4/Web-Recon/issues) con el comando exacto que ejecutaste, la salida obtenida (o error completo), y tu sistema operativo.

## Uso responsable

Solo contra objetivos con autorización explícita. El escaneo sin autorización puede ser ilegal según la jurisdicción. El autor no se hace responsable del uso indebido de este script.

## Licencia

Creative Commons Atribución-NoComercial-CompartirIgual 4.0 Internacional ([CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.es))

- Uso, modificación y redistribución libres.
- Atribución al autor original obligatoria.
- Sin uso comercial ni ánimo de lucro.
- Versiones modificadas deben distribuirse bajo la misma licencia.
