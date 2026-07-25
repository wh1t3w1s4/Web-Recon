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

## Dependencias

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

## Requisitos del sistema

Probado en **Debian/Ubuntu**. No hay soporte todavía para Arch, Fedora o macOS — el instalador (`setup.sh`) asume `apt` como gestor de paquetes.

## Instalación

La forma recomendada es usar el script de instalación incluido, que resuelve todas las dependencias automáticamente (paquetes de sistema, herramientas Go, wafw00f, wpscan, la wordlist de SecLists e `ipinfo`):

```bash
git clone https://github.com/wh1t3w1s4/Web-Recon
cd Web-Recon
chmod +x setup.sh
./setup.sh
```

Al terminar, `setup.sh` muestra un resumen indicando qué dependencias quedaron instaladas correctamente y cuáles requieren atención manual.

Si prefieres instalar todo a mano, consulta la tabla de dependencias más arriba.

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
[ Pega aquí un escaneo de ejemplo, con el dominio real anonimizado/sustituido,
  mostrando el recorrido por ambas fases y el tipo de output que genera cada módulo ]
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
