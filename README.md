# Web-Recon-v0.1.0-alpha
The web reconnaissance tool by w1s4

**Estado del proyecto: alpha (v0.1.0)** — en fase de pruebas con feedback de terceros. Puede tener bugs, comportamiento inconsistente entre targets, y cambiar bastante entre versiones. No recomendado todavía para uso en entornos críticos sin supervisión.

Web-Recon es un script en bash para automatizar la fase de reconocimiento (pasivo y activo) sobre un dominio objetivo. Encadena varias herramientas estándar de recon y aplica algo de lógica propia para reducir ruido en los resultados (filtrado de falsos positivos en fuzzing, detección de wildcard, agrupación de patrones repetidos, etc.).

Esta herramienta está pensada únicamente para uso en auditorías, CTFs, bug bounty o programas de pentesting donde se cuenta con autorización explícita sobre el objetivo.

## Qué hace

El script se divide en dos fases:

### Fase 1 — Reconocimiento pasivo

- **WHOIS**: información de registro del dominio.
- **Resolución DNS**: registros A vía `dig`, limitado a las primeras IPs resueltas.
- **IP info**: script propio de geolocalización aproximada y datos de cada IP resuelta (ISP, ASN, DNS inverso).

### Fase 2 — Reconocimiento activo

- **Detección de protocolo**: comprueba si el objetivo responde por HTTP, HTTPS o ninguno de los dos, antes de lanzar el resto de módulos.
- **WAF detection**: `wafw00f` para identificar si hay un WAF delante del objetivo.
- **Fingerprinting web**: `whatweb` en modo verbose. Si detecta un bloqueo de Cloudflare (403 + challenge), omite la salida completa y avisa en su lugar.
- **Fuzzing de directorios**: `ffuf` contra el objetivo, con:
  - Autocalibración (`-ac`) para mitigar comportamiento wildcard.
  - Agrupación de resultados por status/words/lines para detectar patrones repetidos (falsos positivos).
  - Resultados "limpios" mostrados directamente; resultados "sospechosos" (patrón repetido) resueltos con `httpx` o `curl` como fallback.
  - Aviso y corte automático si el volumen de resultados indica comportamiento wildcard generalizado.
- **robots.txt**: extracción de rutas `Disallow`/`Allow`, filtrando comentarios y líneas irrelevantes.
- **Descubrimiento de subdominios**:
  - `subfinder` como fuente principal.
  - `crt.sh` (Certificate Transparency) como fuente complementaria, con reintentos y backoff si el servicio da rate-limit, lo cual es común al realizarle peticiones desde curl.
  - Unión y deduplicación de ambas fuentes.
  - Verificación de cuáles subdominios responden realmente, filtrando 404s.

## Requisitos del sistema

Probado en **Debian/Ubuntu**. No hay soporte todavía para Arch, Fedora o macOS — el instalador (`setup.sh`) asume `apt` como gestor de paquetes.


## Instalación / Dependencias

La forma recomendada es usar el script de instalación incluido, que resuelve todas las dependencias automáticamente (paquetes de sistema, herramientas Go, wafw00f, wpscan, la wordlist de SecLists e `ipinfo`):

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
| `whatweb` | Fase 2 | `apt install whatweb` |
| `wafw00f` | Fase 2 | `pip install wafw00f` |
| `wpscan` | Fase 2 (si detecta WordPress) | `gem install wpscan` |
| `ffuf` | Fase 2 | `go install github.com/ffuf/ffuf/v2@latest` |
| `subfinder` | Fase 2 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` (ProjectDiscovery) | Fase 2 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |

Si falta alguna dependencia, el script avisa al inicio e indica el comando de instalación. Las fases que dependen de una herramienta ausente se omiten o caen a un fallback (por ejemplo, `curl` en lugar de `httpx`) en vez de interrumpir la ejecución completa.

> Nota: `httpx` de ProjectDiscovery puede entrar en conflicto con el paquete de Python del mismo nombre (`pip install httpx`, un cliente HTTP). El script referencia el binario por ruta absoluta (`$HOME/.go/bin/httpx` por defecto) para evitar ambigüedad. Si lo tienes en otra ubicación, puedes indicarlo con la variable de entorno `HTTPX_BIN`.

## Uso

```bash
./web_recon.sh <dominio>
```

Ejemplo:

```bash
./web_recon.sh ejemplo.com
```

Si el dominio no responde por HTTP ni HTTPS, la Fase 2 se omite automáticamente, el script informa del motivo y se finaliza la ejecución del script.

### Ejemplo de salida completa

```

 __        __   _      ____                       
 \ \      / /__| |__  |  _ \ ___  ___ ___  _ __    
  \ \ /\ / / _ \ '_ \ | |_) / _ \/ __/ _ \| '_ \   
   \ V  V /  __/ '_ \ | |  / __/  __\ (_) | | | |  
    \_/\_/ \___|_.__/_|_| \_\___|\___\___/|_| |_|  

         >> Web Reconnaissance Tool <<
         Version 0.1.0 - by w1s4
=========================================================


[+] Iniciando reconocimiento web para: domain.com
Fecha: sáb 25 jul 2026 23:07:00 CEST


[+] Iniciando reconocimiento pasivo para: domain.com


[+] Iniciando reconocimiento WHOIS
   Domain Name: DOMAIN.COM
   Registry Domain ID: 2726597102_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrar.eu
   Registrar URL: http://www.openprovider.com
   Updated Date: 2025-09-19T07:49:07Z
   Creation Date: 2022-09-20T16:52:01Z
   Registry Expiry Date: 2026-09-20T16:52:01Z
   Registrar: Hosting Concepts B.V. d/b/a Registrar.eu
   Registrar IANA ID: 1647
   Registrar Abuse Contact Email: abuse@registrar.eu
   Registrar Abuse Contact Phone: +31.1234567
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: EUROCORREO.EMPRESAWWW.COM
   Name Server: EUROCORREO2.EMPRESAWWW.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2026-07-25T21:06:39Z <<<



[+] Iniciando reconocimiento IP
IPs encontradas: 1
82.223.XXX.123

──────────────────────────────────────────────────
  Análisis de 82.223.XXX.123
──────────────────────────────────────────────────
  Versión               IPv4
  Tipo                  Pública
  Visibilidad           Enrutable en Internet
  DNS inverso           svr2k8-1.portaldetuciudad.es
  País                  Spain
  Región / Ciudad       Madrid / Madrid
  ISP                   arsys.es
  Organización          
  ASN                   AS8560 IONOS SE
  Hosting / Datacenter  Sí

  ✔  IP pública directa sin CDN conocida



[+] Iniciando reconocimiento activo para: domain.com




[+] Detectando protocolo (HTTP/HTTPS)


Protocolo detectado -> https


[+] Iniciando reconocimiento con Whatweb
-----------------------------INICIO WHATWEB--------------------------------------
WhatWeb report for https://domain.com
Status    : 200 OK
Title     : coches eléctricos SA - domain.com
IP        : 82.223.132.123
Country   : SPAIN, ES

Summary   : ASP_NET[4.0.30319], Bootstrap[3.3.7], Cookies[ASP.NET_SessionId], Email[johndoe22@gmail.com], HTML5, HTTPServer[Microsoft-IIS/8.0], HttpOnly[ASP.NET_SessionId], JQuery, Meta-Author[Portaldetuciudad.com], Microsoft-IIS[8.0], Open-Graph-Protocol[website], Script[javascript,text/javascript,text/plain], X-Powered-By[ASP.NET]

Detected Plugins:
[ ASP_NET ]
	ASP.NET is a free web framework that enables great Web 
	applications. Used by millions of developers, it runs some 
	of the biggest sites in the world. 

	Version      : 4.0.30319 (from X-AspNet-Version HTTP header)
	Google Dorks: (2)
	Website     : https://www.asp.net/

[ Bootstrap ]
	Bootstrap is an open source toolkit for developing with 
	HTML, CSS, and JS. 

	Version      : 3.3.7
	Website     : https://getbootstrap.com/

[ Cookies ]
	Display the names of cookies in the HTTP headers. The 
	values are not returned to save on space. 

	String       : ASP.NET_SessionId

[ Email ]
	Extract email addresses. Find valid email address and 
	syntactically invalid email addresses from mailto: link 
	tags. We match syntactically invalid links containing 
	mailto: to catch anti-spam email addresses, eg. bob at 
	gmail.com. This uses the simplified email regular 
	expression from 
	http://www.regular-expressions.info/email.html for valid 
	email address matching. 

	String       : johndoe22@gmail.com

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	String       : Microsoft-IIS/8.0 (from server string)

[ HttpOnly ]
	If the HttpOnly flag is included in the HTTP set-cookie 
	response header and the browser supports it then the cookie 
	cannot be accessed through client side script - More Info: 
	http://en.wikipedia.org/wiki/HTTP_cookie 

	String       : ASP.NET_SessionId

[ JQuery ]
	A fast, concise, JavaScript that simplifies how to traverse 
	HTML documents, handle events, perform animations, and add 
	AJAX. 

	Website     : http://jquery.com/

[ Meta-Author ]
	This plugin retrieves the author name from the meta name 
	tag - info: 
	http://www.webmarketingnow.com/tips/meta-tags-uncovered.html
	#author

	String       : Portaldetuciudad.com

[ Microsoft-IIS ]
	Microsoft Internet Information Services (IIS) for Windows 
	Server is a flexible, secure and easy-to-manage Web server 
	for hosting anything on the Web. From media streaming to 
	web application hosting, IIS's scalable and open 
	architecture is ready to handle the most demanding tasks. 

	Version      : 8.0
	Website     : http://www.iis.net/

[ Open-Graph-Protocol ]
	The Open Graph protocol enables you to integrate your Web 
	pages into the social graph. It is currently designed for 
	Web pages representing profiles of real-world things . 
	things like movies, sports teams, celebrities, and 
	restaurants. Including Open Graph tags on your Web page, 
	makes your page equivalent to a Facebook Page. 

	Version      : website

[ Script ]
	This plugin detects instances of script HTML elements and 
	returns the script language/type. 

	String       : javascript,text/javascript,text/plain

[ X-Powered-By ]
	X-Powered-By HTTP header 

	String       : ASP.NET (from x-powered-by string)

HTTP Headers:
	HTTP/1.1 200 OK
	Cache-Control: private
	Content-Type: text/html; charset=utf-8
	Content-Encoding: gzip
	Vary: Accept-Encoding
	Server: Microsoft-IIS/8.0
	Set-Cookie: ASP.NET_SessionId=r5345rjvpngetbowhlv; path=/; HttpOnly
	X-AspNet-Version: 4.0.30319
	X-Powered-By: ASP.NET
	Date: Sat, 25 Jul 2026 21:07:11 GMT
	Connection: close
	Content-Length: 14096
	
-----------------------------FINAL WHATWEB----------------------------------------


[+] Comprobando WAF (wafw00f)
[*] Checking https://domain.com
[+] The site https://domain.com is behind ASP.NET Generic (Microsoft) WAF.


[+] Iniciando fuzzing de directorios
Log
Resources
app_themes
favicon.ico
log
paginas
res
resources
sitemap.xml
sitemap_xml
[+] Resultados totales: 10


[+] Resultados únicos (patrón no repetido):
https://domain.com/Log
https://domain.com/Resources
https://domain.com/app_themes
https://domain.com/favicon.ico
https://domain.com/log
https://domain.com/paginas
https://domain.com/res
https://domain.com/resources
https://domain.com/sitemap.xml
https://domain.com/sitemap_xml
[+] No se detectaron grupos de ruido repetido


[+] Leyendo Robots.txt (si existe)


[+] Iniciando descubrimiento de subdominios


[+] Paso 1: subfinder
[+] Subdominios encontrados por subfinder: 7
https://mail.domain.com
https://webdisk.domain.com
https://webmail.domain.com
https://www.domain.com
https://cpanel.domain.com
https://cpcalendars.domain.com
https://cpcontacts.domain.com


[+] Paso 2: crt.sh
[+] crt.sh: 8 entradas encontradas
cpanel.domain.com
cpcalendars.domain.com
cpcontacts.domain.com
mail.domain.com
domain.com
webdisk.domain.com
webmail.domain.com
www.domain.com


[+] Resumen final de subdominios (subfinder + crt.sh)
[+] Total únicos combinados: 8
  - subfinder: 7
  - crt.sh:    8


cpanel.domain.com
cpcalendars.domain.com
cpcontacts.domain.com
mail.domain.com
domain.com
webdisk.domain.com
webmail.domain.com
www.domain.com


[+] Verificando cuáles subdominios responden (httpx)
https://mail.domain.com [301] [301 Moved Permanently]
https://webdisk.domain.com [401]
https://webmail.domain.com [200] [Nombre de usuario para el webmail]
https://cpanel.domain.com [200] [Acceso a cPanel]
https://www.domain.com [301] [Document Moved]
https://domain.com [200] [coches eléctricos SA - domain.com]
https://cpcontacts.domain.com [401]
https://cpcalendars.domain.com [401]


```

## Wordlists

Por defecto el script usa wordlists locales para fuzzing de directorios y subdominios (ajustables directamente en el script). Revisa las rutas configuradas antes de ejecutar si tu wordlist está en otra ubicación:

- Directorios: `big.txt` (SecLists de Daniel Miessler, ruta `Discovery/Web-Content/big.txt`)
- Subdominios (vía subfinder): no requiere wordlist propia, usa fuentes OSINT

## Pendiente / roadmap

- Exportación de resultados a un archivo/carpeta estructurada por dominio y timestamp.
- Reporte final consolidado (texto/markdown) con el resumen de todas las fases.
- Screenshots de subdominios/directorios vivos.

## Feedback y reporte de bugs

Este proyecto está en fase alpha y agradece cualquier feedback. Si encuentras un bug, un comportamiento raro, o algo que no funciona como esperabas, abre un **Issue** en este repositorio incluyendo:

- El comando exacto que ejecutaste
- La salida obtenida (o el error completo)
- El sistema operativo y versión donde lo probaste

Esto ayuda muchísimo más que el feedback informal, y queda trazado para futuras versiones.

## Uso responsable

Esta herramienta está pensada para usarse únicamente contra objetivos sobre los que se tiene autorización explícita (programas de bug bounty, pentesting contratado, laboratorios propios, CTFs). El escaneo de dominios sin autorización puede ser ilegal según la jurisdicción. El autor no se hace responsable del uso indebido de este script.

## Licencia

Este proyecto está licenciado bajo **Creative Commons Atribución-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)**.

En resumen:
- Puedes usar, modificar y redistribuir el código libremente.
- Debes dar crédito al autor original.
- No está permitido ningún uso comercial ni con ánimo de lucro.
- Cualquier versión modificada debe distribuirse bajo esta misma licencia.

Texto completo: https://creativecommons.org/licenses/by-nc-sa/4.0/deed.es
