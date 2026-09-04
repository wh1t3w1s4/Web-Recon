#!/bin/bash

#Colores
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
YELL='\033[0;33m'
GREEN_BOLD='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"

#--------------------------------BANNER-----------------------------------
banner() {
clear
echo -e "${CYAN}"
cat << "EOF"
 __        __   _      ____                       
 \ \      / /__| |__  |  _ \ ___  ___ ___  _ __    
  \ \ /\ / / _ \ '_ \ | |_) / _ \/ __/ _ \| '_ \   
   \ V  V /  __/ '_ \ | |  / __/  __\ (_) | | | |  
    \_/\_/ \___|_.__/_|_| \_\___|\___\___/|_| |_|  
EOF
echo -e "${NC}"
echo -e "${YELLOW}         >> Web Reconnaissance Tool <<${NC}"
echo -e "${GREEN}            Version 0.2.0 - by w1s4${NC}"
echo -e "${CYAN}=========================================================${NC}"
echo ""
}
#-------------------------------------------------------------------------

#--------------------------------AYUDA-------------------------------------
mostrar_ayuda() {
cat << EOF
Uso: $0 [opciones] <dominio>

Opciones:
  -o, --output <ruta>   Carpeta base donde se guardarán los resultados (por defecto: ./resultados)
  -n, --no-export       No crear carpeta ni exportar nada, solo mostrar en pantalla
  -h, --help            Muestra esta ayuda
  -s, --subdomain       Modo subdominio: omite WHOIS, DNS extra y descubrimiento de
                        subdominios sobre el target indicado.
Ejemplos:
  $0 ejemplo.com
  $0 -o /home/$USER/pentesting ejemplo.com
  $0 -n ejemplo.com
EOF
}
#-------------------------------------------------------------------------

# ------------------------------ ARGUMENTOS --------------------------------
EXPORT=true
OUTPUT_BASE="resultados"
SUBDOMAIN_MODE=false
target=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            mostrar_ayuda
            exit 0
            ;;
        -o|--output)
            OUTPUT_BASE="$2"
            shift 2
            ;;
        -n|--no-export)
            EXPORT=false
            shift
            ;;
        -s|--subdomain)
            SUBDOMAIN_MODE=true
            shift
            ;;
        -*)
            echo "Opción desconocida: $1"
            mostrar_ayuda
            exit 1
            ;;
        *)
            target="$1"
            shift
            ;;
    esac
done

if [[ -z "$target" ]]; then
    echo "Error: Debes proporcionar un dominio como argumento."
    mostrar_ayuda
    exit 1
fi
# ---------------------------------------------------------------------------

# ------------------------------ EXPORTACIÓN ---------------------------------
strip_ansi() {
    sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g'
}

if [[ "$EXPORT" == true ]]; then
    OUTDIR="${OUTPUT_BASE%/}/${target}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTDIR"
    SUBS_FILE="$OUTDIR/subdominios_vivos.txt"
    WP_FILE="$OUTDIR/wordpress.txt"
    REPORT_FILE="$OUTDIR/reporte_final.md"

    cat > "$REPORT_FILE" << EOF
# Reporte de reconocimiento - $target

**Fecha:** $(date '+%Y-%m-%d %H:%M:%S')
**Herramienta:** Web-Recon v0.1.0-alpha

---
EOF
else
    OUTDIR=""
fi

# Añade contenido al reporte markdown (no hace nada si -n)
md() {
    [[ "$EXPORT" == true ]] && echo -e "$1" | strip_ansi >> "$REPORT_FILE"
}

banner

if [[ "$EXPORT" == true ]]; then
    echo -e "${GREEN}[+] Resultados se exportarán a: $OUTDIR${NC}"
else
    echo -e "${YELLOW}[!] Exportación desactivada (-n), los resultados solo se mostrarán en pantalla${NC}"
fi
echo -e "\n"

#------------------------------------------------------------------------------------------------------------

#--------------------------------- DEFINIR FUNCIONES --------------------------------------------------------

# Kill switch: Ctrl+K finaliza la ejecución en cualquier momento
if [[ -t 0 ]]; then
    ORIG_STTY=$(stty -g)
    stty quit ^K
    trap 'stty "$ORIG_STTY" 2>/dev/null' EXIT
fi

trap 'echo -e "\n${RED}[!] Kill switch (Ctrl+K) activado, finalizando ejecución...${NC}"; exit 130' QUIT
#------------------------------------------------------------------------------------------------------------

# Función: detectar_protocolo
# Devuelve "https", "http" o "ninguno" según lo que responda el target
detectar_protocolo() {
    local domain="$1"
    domain="${domain//[$'\t\r\n ']/}"

    local ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    local code rc

    code=$(curl -s -k -L -A "$ua" \
            --connect-timeout 5 --max-time 10 \
            -o /dev/null -w "%{http_code}" "https://$domain")
    rc=$?

    if [[ $rc -eq 0 && "$code" =~ ^[2-4][0-9]{2}$ ]]; then
        echo "https"
        return 0
    fi

    code=$(curl -s -L -A "$ua" \
            --connect-timeout 5 --max-time 10 \
            -o /dev/null -w "%{http_code}" "http://$domain")
    rc=$?

    if [[ $rc -eq 0 && "$code" =~ ^[2-4][0-9]{2}$ ]]; then
        echo "http"
        return 0
    fi

    echo "ninguno"
    return 1
}
#-------------------------------------------------------------------------------------------------------------

# Función: consultar_dns_extra
# Registros MX, TXT, NS, SOA, CNAME, AAAA con +short.
# Filtra líneas vacías y limpia comillas en TXT.
consultar_dns_extra() {
    local domain="$1"

    for tipo in MX NS TXT SOA CNAME CAA; do
        echo -e "${GREEN}[+] ${tipo}${NC}"
        local resultado
        resultado=$(dig "$tipo" +short "$domain" | grep -v '^\s*$')

        if [[ -z "$resultado" ]]; then
            echo "  (sin registros)"
        else
            while IFS= read -r linea; do
                [[ "$tipo" == "TXT" ]] && linea=$(echo "$linea" | tr -d '"')
                local nota
                nota=$(interpretar_registro "$tipo" "$linea")
                if [[ -n "$nota" ]]; then
                    echo "  $linea"
                    echo "    → $nota"
                else
                    echo "  $linea"
                fi
            done <<< "$resultado"
        fi
        echo -e "\n"
    done
}
#-------------------------------------------------------------------------------------------------------------

# Función: interpretar_registro
# Devuelve una anotación legible para un valor de registro DNS, o cadena vacía si no reconoce el patrón.
interpretar_registro() {
    local tipo="$1"
    local valor="$2"
    local v_lower="${valor,,}"

    case "$tipo" in
        TXT)
            [[ "$v_lower" == v=spf1* ]] && { echo "SPF — define qué servidores pueden enviar correo en nombre del dominio"; return; }
            [[ "$v_lower" == v=dkim1* ]] && { echo "DKIM — firma criptográfica de autenticidad de correo"; return; }
            [[ "$v_lower" == v=dmarc1* ]] && { echo "DMARC — política de qué hacer si el correo falla SPF/DKIM"; return; }
            [[ "$v_lower" == google-site-verification=* ]] && { echo "Verificación de propiedad: Google Search Console"; return; }
            [[ "$v_lower" == ms=* ]] && { echo "Verificación de propiedad: Microsoft 365"; return; }
            [[ "$v_lower" == facebook-domain-verification=* ]] && { echo "Verificación de propiedad: Facebook Business"; return; }
            ;;
        NS)
            [[ "$v_lower" == *cloudflare.com* ]] && { echo "Cloudflare (probable proxy/CDN delante del origen real)"; return; }
            [[ "$v_lower" == *awsdns* ]] && { echo "AWS Route 53"; return; }
            [[ "$v_lower" == *domaincontrol.com* ]] && { echo "GoDaddy"; return; }
            ;;
        MX)
            [[ "$v_lower" == *google.com* || "$v_lower" == *googlemail.com* ]] && { echo "Google Workspace (correo corporativo)"; return; }
            [[ "$v_lower" == *outlook.com* || "$v_lower" == *protection.outlook.com* ]] && { echo "Microsoft 365"; return; }
            [[ "$v_lower" == *zoho.com* ]] && { echo "Zoho Mail"; return; }
            ;;
        CNAME)
            [[ "$v_lower" == *herokuapp.com* ]] && { echo "Apunta a Heroku — revisar posible subdomain takeover si el recurso no existe"; return; }
            [[ "$v_lower" == *github.io* ]] && { echo "Apunta a GitHub Pages — revisar posible subdomain takeover si el recurso no existe"; return; }
            [[ "$v_lower" == *s3.amazonaws.com* || "$v_lower" == *s3-website* ]] && { echo "Apunta a AWS S3 — revisar posible subdomain takeover si el bucket no existe"; return; }
            [[ "$v_lower" == *cloudfront.net* ]] && { echo "AWS CloudFront (CDN)"; return; }
            [[ "$v_lower" == *azurewebsites.net* ]] && { echo "Azure App Service — revisar posible subdomain takeover si el recurso no existe"; return; }
            ;;
        CAA)
            [[ "$v_lower" == *letsencrypt.org* ]] && { echo "Autoriza a Let's Encrypt a emitir certificados"; return; }
            [[ "$v_lower" == *digicert.com* ]] && { echo "Autoriza a DigiCert a emitir certificados"; return; }
            [[ "$v_lower" == *sectigo.com* || "$v_lower" == *comodoca.com* ]] && { echo "Autoriza a Sectigo/Comodo a emitir certificados"; return; }
            ;;
    esac
    echo ""
}
#-------------------------------------------------------------------------------------------------------------

# Función: resolver_con_curl
# Fallback si no está disponible httpx. Devuelve código HTTP + título.
resolver_con_curl() {
    local url="$1"
    local codigo titulo tmp_body

    tmp_body=$(mktemp)
    codigo=$(curl -s -k -L -o "$tmp_body" -w "%{http_code}" \
                  --connect-timeout 5 --max-time 10 -A "Mozilla/5.0" "$url")
    titulo=$(grep -oiPm1 '(?<=<title>)[^<]+' "$tmp_body" 2>/dev/null)
    rm -f "$tmp_body"

    echo "[$codigo] $url ${titulo:+- $titulo}"
}
#-------------------------------------------------------------------------------------------------------------

# Función: analizar_cookies
# Descarga los headers de la URL (y de /login si no hay cookies en la primera pasada),
#evalúa flags de seguridad de cookies, HSTS, y otras cabeceras de seguridad/exposición de información.
analizar_cookies() {
    local base_url="$1"
    local headers cookie_lines url_usada

    url_usada="$base_url"
    headers=$(curl -s -k -L -D - -o /dev/null --connect-timeout 5 --max-time 10 -A "Mozilla/5.0" "$url_usada")
    cookie_lines=$(echo "$headers" | grep -i '^set-cookie:')

    if [[ -z "$cookie_lines" ]]; then
        local login_url="${base_url%/}/login"
        local headers_login
        headers_login=$(curl -s -k -L -D - -o /dev/null --connect-timeout 5 --max-time 10 -A "Mozilla/5.0" "$login_url")
        local cookie_lines_login
        cookie_lines_login=$(echo "$headers_login" | grep -i '^set-cookie:')

        if [[ -n "$cookie_lines_login" ]]; then
            echo "(Sin cookies en la raíz; se encontraron cookies en ${login_url})"
            echo ""
            headers="$headers_login"
            cookie_lines="$cookie_lines_login"
            url_usada="$login_url"
        fi
    fi

    # --- Cabeceras de seguridad / exposición de información ---
    echo "-- Cabeceras --"

    if echo "$headers" | grep -qi '^strict-transport-security:'; then
        local hsts_value
        hsts_value=$(echo "$headers" | grep -i '^strict-transport-security:' | head -n1)
        echo "HSTS: presente (${hsts_value#*: })"
    else
        echo "[!] HSTS ausente — el sitio no fuerza HTTPS a nivel de navegador; permite downgrade a HTTP en la primera visita o en ataques de tipo SSL stripping"
    fi

    if echo "$headers" | grep -qi '^x-frame-options:'; then
        echo "X-Frame-Options: presente"
    elif echo "$headers" | grep -qi 'frame-ancestors'; then
        echo "X-Frame-Options: ausente, pero CSP define frame-ancestors (protección equivalente)"
    else
        echo "[!] X-Frame-Options ausente (y sin frame-ancestors en CSP) — posible clickjacking"
    fi

    if echo "$headers" | grep -qi '^content-security-policy:'; then
        echo "Content-Security-Policy: presente"
    else
        echo "[!] Content-Security-Policy ausente — sin defensa en profundidad frente a XSS"
    fi

    if echo "$headers" | grep -qi '^x-content-type-options: *nosniff'; then
        echo "X-Content-Type-Options: presente (nosniff)"
    else
        echo "[!] X-Content-Type-Options ausente — permite MIME-sniffing"
    fi

    if echo "$headers" | grep -qi '^referrer-policy:'; then
        echo "Referrer-Policy: presente"
    else
        echo "[!] Referrer-Policy ausente — puede filtrar URLs completas (con parámetros sensibles) a terceros vía Referer"
    fi

    local acao acac
    acao=$(echo "$headers" | grep -i '^access-control-allow-origin:' | head -n1)
    acac=$(echo "$headers" | grep -i '^access-control-allow-credentials:' | head -n1)
    if [[ -n "$acao" ]]; then
        if [[ "$acao" == *'*'* && "${acac,,}" == *true* ]]; then
            echo "[!!!] CORS mal configurado — Access-Control-Allow-Origin: * junto con Allow-Credentials: true permite a cualquier origen leer respuestas autenticadas"
        else
            echo "Access-Control-Allow-Origin: ${acao#*: }"
        fi
    fi

    local xpb server_hdr
    xpb=$(echo "$headers" | grep -i '^x-powered-by:' | head -n1)
    server_hdr=$(echo "$headers" | grep -i '^server:' | head -n1)
    [[ -n "$xpb" ]] && echo "[i] X-Powered-By expuesto: ${xpb#*: } (fingerprinting facilitado, considerar ocultarlo)"
    [[ -n "$server_hdr" ]] && echo "[i] Server expuesto: ${server_hdr#*: } (fingerprinting facilitado, considerar ocultar versión)"

    echo ""

    # --- Cookies ---
    echo "-- Cookies --"
    if [[ -z "$cookie_lines" ]]; then
        echo "No se detectaron cookies ni en la raíz ni en ${base_url%/}/login."
        return 0
    fi

    while IFS= read -r line; do
        local cookie_full="${line#*: }"
        local cookie_name="${cookie_full%%=*}"
        local cookie_lower="${cookie_full,,}"

        echo "Cookie: ${cookie_name} (vista en: ${url_usada})"

        if [[ "$cookie_lower" != *httponly* ]]; then
            echo "  [!] Sin HttpOnly — accesible vía document.cookie; robable en caso de XSS"
        fi

        if [[ "$cookie_lower" != *secure* ]]; then
            echo "  [!] Sin Secure — puede transmitirse en texto plano si en algún momento se accede por HTTP"
        fi

        if [[ "$cookie_lower" != *samesite* ]]; then
            echo "  [!] Sin SameSite — expuesta a CSRF si no hay otras mitigaciones"
        elif [[ "$cookie_lower" == *samesite=none* ]]; then
            echo "  [!] SameSite=None — permite envío cross-site; requiere Secure para ser válido en navegadores modernos"
        fi

        if [[ "$cookie_lower" != *httponly* && "$cookie_lower" != *secure* && "$cookie_lower" != *samesite* ]]; then
            echo "  [!!!] Cookie sin ninguna flag de seguridad — máxima exposición"
        fi

        echo ""
    done <<< "$cookie_lines"
}
#-------------------------------------------------------------------------------------------------------------------

# Función: consultar_crtsh
# Realiza peticiones a https://crt.sh/$domain y lo exporta en JSON
consultar_crtsh() {
    local domain="$1"
    local raw
    local intentos=4
    local espera=3

    for i in $(seq 1 $intentos); do
        raw=$(curl -s --max-time 30 "https://crt.sh/?q=%25.${domain}&output=json")

        if echo "$raw" | jq empty 2>/dev/null; then
            echo "$raw" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
            return 0
        fi

        echo -e "${YELLOW}[!] Intento $i/${intentos}: crt.sh no respondió JSON válido, reintentando en ${espera}s...${NC}" >&2
        sleep "$espera"
        espera=$(( espera * 2 ))  # backoff: 3s, 6s, 12s, 24s...
    done

# Fallback: intentar con CSV si el JSON sigue fallando
    echo -e "${YELLOW}[!] JSON falló tras $intentos intentos, probando CSV...${NC}" >&2
    raw=$(curl -s --max-time 30 "https://crt.sh/?q=%25.${domain}&output=csv")
    if [[ -n "$raw" ]]; then
        echo "$raw" | python3 -c "
import csv, sys
reader = csv.DictReader(sys.stdin)
seen = set()
for row in reader:
    val = (row.get('name_value') or '').strip()
    if not val:
        continue
    for line in val.split('\n'):
        line = line.strip()
        if line.startswith('*.'):
            line = line[2:]
        if line and line not in seen:
            seen.add(line)
            print(line)
" | sort -u
        return 0
    fi

    echo -e "${YELLOW}[-] crt.sh no devolvió resultados en ningún formato${NC}" >&2
    return 1
}
#-------------------------------------------------------------------------------------------------------------------

# Función: analizar_wordpress
# Lanza wpscan si whatweb detectó WordPress.
analizar_wordpress() {
    local url="$1"
    local args=(--no-banner --random-user-agent -e vp,vt,u1-5 --detection-mode passive --disable-tls-checks)

    if [[ -n "$WPSCAN_API_TOKEN" ]]; then
        args+=(--api-token "$WPSCAN_API_TOKEN")
    fi

    local salida
    salida=$(timeout 120 wpscan --url "$url" "${args[@]}" 2>/dev/null)
    echo "$salida" | grep -vE "Requests Done|Cached Requests|Data Sent|Data Received|Memory used|Elapsed time"
}
#--------------------------------------------------------------------------------------------------------------------

# Función: extraer_versiones_whatweb
# Estrae los dígitos de las tecnologías detectadas por whatweb
extraer_versiones_whatweb() {
    local output="$1"
    local plugin=""
    local re_plugin='^\[ (.+) \]$'
    local re_version='Version[[:space:]]*:[[:space:]]*([^[:space:](]+)'

    while IFS= read -r line; do
        if [[ "$line" =~ $re_plugin ]]; then
            plugin="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ $re_version ]]; then
            if [[ -n "$plugin" ]]; then
                echo "${plugin}|${BASH_REMATCH[1]}"
            fi
        fi
    done <<< "$output"
}
#--------------------------------------------------------------------------------------------------------------------

# Función: version_lt
# Devuelve 0 (true) si $1 < $2, usando comparación semántica (sort -V)
version_lt() {
    [[ "$1" == "$2" ]] && return 1
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}
#--------------------------------------------------------------------------------------------------------------------

# Base de datos de vulnerabilidades conocidas por versión.
# "vulnerable si version < versión_máxima" (y coincide la rama, si se especifica)
VULN_DB=(
    "jQuery|3.5.0||CVE-2020-11022,CVE-2020-11023|XSS al pasar HTML no confiable a métodos como .html()/.append()|https://nvd.nist.gov/vuln/detail/CVE-2020-11022"
    "jQuery|1.9.0||CVE-2015-9251|XSS en respuestas Ajax con Content-Type incorrecto|https://nvd.nist.gov/vuln/detail/CVE-2015-9251"
    "Bootstrap|3.4.1|3.|CVE-2018-14040,CVE-2018-14041,CVE-2018-14042|XSS en plugins tooltip/affix/collapse (rama 3.x)|https://nvd.nist.gov/vuln/detail/CVE-2018-14042"
    "Bootstrap|4.3.1|4.|CVE-2019-8331|XSS en tooltip/popover vía atributo data-template (rama 4.x)|https://nvd.nist.gov/vuln/detail/CVE-2019-8331"
    "nginx|1.20.1||CVE-2021-23017|Desbordamiento de búfer en el resolver DNS interno|https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
    "Apache|2.4.51||CVE-2021-41773,CVE-2021-42013|Path traversal / RCE en mod_cgi (versiones 2.4.49-2.4.50)|https://nvd.nist.gov/vuln/detail/CVE-2021-42013"
    "Lodash|4.17.21||CVE-2020-8203,CVE-2019-10744|Prototype Pollution|https://nvd.nist.gov/vuln/detail/CVE-2020-8203"
    "OpenSSL|1.0.1g||CVE-2014-0160|Heartbleed — fuga de memoria del proceso|https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    "PHP|5.6.40||CVE-2019-11043|RCE en php-fpm bajo nginx con rutas concretas|https://nvd.nist.gov/vuln/detail/CVE-2019-11043"
)
#--------------------------------------------------------------------------------------------------------------------

# Función: detectar_vulnerabilidades_version
# Cruza las versiones detectadas por whatweb contra VULN_DB.
detectar_vulnerabilidades_version() {
    local whatweb_out="$1"
    local encontradas=()

    while IFS='|' read -r plugin version; do
        [[ -z "$plugin" || -z "$version" ]] && continue
        version="${version%%[^0-9.]*}"
        [[ -z "$version" ]] && continue

        for entry in "${VULN_DB[@]}"; do
            IFS='|' read -r db_tech db_max db_rama db_cve db_desc db_ref <<< "$entry"

            [[ "${plugin,,}" != "${db_tech,,}" ]] && continue
            [[ -n "$db_rama" && "$version" != "$db_rama"* ]] && continue

            if version_lt "$version" "$db_max"; then
                encontradas+=("[!] ${plugin} ${version} — vulnerable (< ${db_max})
    CVE: ${db_cve}
    ${db_desc}
    Ref: ${db_ref}")
            fi
        done
    done < <(extraer_versiones_whatweb "$whatweb_out")

    if (( ${#encontradas[@]} > 0 )); then
        printf '%s\n\n' "${encontradas[@]}"
        return 0
    fi
    return 1
}
#-------------------------------------------------------------------------------------------------------------------

# Función: test_bypass_403
# Prueba variaciones de ruta y headers contra una URL con 403.
# Imprime solo las variaciones que devuelven código != 403.
test_bypass_403() {
    local protocol="$1"
    local target="$2"
    local path="$3"   # incluye la barra inicial, ej: /admin
    local base="${protocol}://${target}"
    local found=false
    local no_lead="${path#/}"

    local path_variants=(
        "${path}/"
        "//${no_lead}"
        "/./${no_lead}"
        "${path}/."
        "${path}%20"
        "${path}%09"
        "/${no_lead^^}"
        "${path}..;/"
    )

    for variant in "${path_variants[@]}"; do
        local code
        code=$(curl -s -k -L -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "${base}${variant}")
        if [[ "$code" != "403" && "$code" != "404" ]]; then
            echo "  [$code] ${base}${variant}  (variación de ruta)"
            found=true
        fi
    done

    local header_tests=(
        "X-Original-URL: ${path}"
        "X-Rewrite-URL: ${path}"
        "X-Forwarded-For: 127.0.0.1"
        "X-Forwarded-Host: 127.0.0.1"
        "X-Custom-IP-Authorization: 127.0.0.1"
        "Referer: ${base}${path}"
    )

    for header in "${header_tests[@]}"; do
        local code
        code=$(curl -s -k -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 -H "$header" "${base}${path}")
        if [[ "$code" != "403" && "$code" != "404" ]]; then
            echo "  [$code] ${base}${path}  (header: ${header%%:*})"
            found=true
        fi
    done

    [[ "$found" == false ]] && return 1
    return 0
}
#-------------------------------------------------------------------------------------------------------------------

#--------------------------------- DETECTAR INSTALACIÓN DE HERRAMIENTAS --------------------------------------------

# Detectar instalación de httpx (projectdiscovery)

HTTPX_BIN="${HTTPX_BIN:-$HOME/.go/bin/httpx}"

if [[ -x "$HTTPX_BIN" ]]; then
    httpx_disponible=true
    echo -e ""
else
    httpx_disponible=false
    echo -e "${YELLOW}[!] httpx de ProjectDiscovery no encontrado en $HTTPX_BIN${NC}"
    echo -e "${YELLOW}    Instálalo con: go install github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
    echo -e "${YELLOW}    Se usará un fallback con curl para resolver hallazgos repetidos${NC}"
fi

#--------------------------------------------------------------------------------------------------------------------

# Detectar instalación de wafw00f
if ! command -v wafw00f &> /dev/null; then
    echo -e "${YELLOW}[!] wafw00f no está instalado, se omitirá la detección de WAF${NC}"
    echo -e "${YELLOW}    Instálalo con: sudo apt install wafw00f${NC}"
    wafw00f_disponible=false
else
    wafw00f_disponible=true
fi
#--------------------------------------------------------------------------------------------------------------------

# Detectar instalación de WP-Scan
if ! command -v wpscan &> /dev/null; then
    echo -e "${YELLOW}[!] wpscan no está instalado, se omitirá el análisis de WordPress si se detecta${NC}"
    echo -e "${YELLOW}    Instálalo con: gem install wpscan${NC}"
    wpscan_disponible=false
else
    wpscan_disponible=true
fi

#--------------------------------------------------------------------------------------------------------------------



#------------------------------------ FASE 1: Recon pasivo ----------------------------------------------------------

echo -e "${GREEN_BOLD}[+] Iniciando reconocimiento web para: $target${NC}"
echo "Fecha: $(date)"

        echo -e "\n"


echo -e "${YELLOW}[+] Iniciando reconocimiento pasivo para: $target${NC}"

        echo -e "\n"


if [[ "$SUBDOMAIN_MODE" == false ]]; then

echo -e "${GREEN}[+] Iniciando reconocimiento WHOIS${NC}"
whois_output=$(whois "$target" | head -n 20)
echo "$whois_output"
md "\n## Fase 1 — Reconocimiento pasivo\n\n### WHOIS\n\n\`\`\`\n${whois_output}\n\`\`\`"

        echo -e "\n"

echo -e "${GREEN}[+] Consultando registros DNS adicionales${NC}"
dns_extra_output=$(consultar_dns_extra "$target")
echo "$dns_extra_output"
md "\n### Registros DNS adicionales\n\n\`\`\`\n$(echo "$dns_extra_output" | strip_ansi)\n\`\`\`"
	echo -e "\n"

fi

echo -e "${GREEN}[+] Iniciando reconocimiento IP${NC}"

ips=($(dig A +short "$target"))

echo -e "IPs encontradas: ${#ips[@]}"
printf '%s\n' "${ips[@]}"

max=4
ips_limitadas=("${ips[@]:0:$max}")

ipinfo_output=""
for ip in "${ips_limitadas[@]}"; do
    resultado_ip=$(ipinfo "$ip")
    echo "$resultado_ip"
    ipinfo_output+="${resultado_ip}"$'\n\n'
done

md "\n### IPs resueltas y geolocalización\n\nIPs encontradas: ${#ips[@]}\n\n\`\`\`\n$(printf '%s\n' "${ips[@]}")\n\`\`\`\n\n\`\`\`\n${ipinfo_output}\n\`\`\`"

sleep 2

echo -e "\n"



#------------------------------------ FASE 2: Recon activo ----------------------------------------------------------
echo -e "${YELLOW}[+] Iniciando reconocimiento activo para: $target${NC}"
        echo -e "\n"
        echo -e "\n"

# Llamada a detectar_protocolo
echo -e "${GREEN}[+] Detectando protocolo (HTTP/HTTPS)${NC}"
protocol=$(detectar_protocolo "$target")
	echo -e "\n"
echo "Protocolo detectado -> $protocol"

	echo -e "\n"

# Error de protocolo
if [[ "$protocol" == "ninguno" ]]; then
    echo -e "${YELLOW}[-] $target no responde por HTTP ni HTTPS, se omite el resto de la Fase 2${NC}"
    md "\n## Fase 2 — Reconocimiento activo\n\n**$target no respondió por HTTP ni HTTPS. Fase 2 omitida.**"
else

md "\n## Fase 2 — Reconocimiento activo\n\n**Protocolo detectado:** $protocol"

# Whatweb verbose mode
echo -e "${GREEN}[+] Iniciando reconocimiento con Whatweb${NC}"
whatweb_output=$(whatweb -v "${protocol}://${target}" 2>/dev/null)

if echo "$whatweb_output" | grep -qi "cloudflare" && echo "$whatweb_output" | grep -Eqi "403 Forbidden|Just a moment|"; then
    echo -e "${YELLOW}[-] Cloudflare detectado, omitiendo este paso${NC}"
    md "\n### WhatWeb\n\nCloudflare detectado (403/challenge) — salida omitida."
else
    echo "-----------------------------INICIO WHATWEB--------------------------------------"
    echo "$whatweb_output"
    echo "-----------------------------FINAL WHATWEB----------------------------------------"
    md "\n### WhatWeb\n\n\`\`\`\n${whatweb_output}\n\`\`\`"
fi
	echo -e "\n"

echo -e "${GREEN}[+] Analizando cabeceras de seguridad y cookies${NC}"
cookies_output=$(analizar_cookies "${protocol}://${target}")
echo "$cookies_output"
md "\n### Cabeceras de seguridad y cookies\n\n\`\`\`\n${cookies_output}\n\`\`\`"
	echo -e "\n"

# Comprobación de versiones vulnerables conocidas
echo -e "${GREEN}[+] Comprobando vulnerabilidades conocidas por versión${NC}"
whatweb_clean=$(echo "$whatweb_output" | strip_ansi)
vulns_encontradas=$(detectar_vulnerabilidades_version "$whatweb_clean")

if [[ -n "$vulns_encontradas" ]]; then
    echo -e "${YELLOW}$vulns_encontradas${NC}"
    md "\n### Vulnerabilidades conocidas por versión\n\n\`\`\`\n${vulns_encontradas}\n\`\`\`"
else
    echo "[-] No se detectaron versiones con vulnerabilidades conocidas en la base de datos local"
    md "\n### Vulnerabilidades conocidas por versión\n\nNo se detectaron coincidencias en la base de datos local."
fi
	echo -e "\n"


# Llamada a WP_Scan
if [[ "$wpscan_disponible" == true ]] && echo "$whatweb_output" | grep -qi "wordpress"; then
    echo -e "${GREEN}[+] WordPress detectado, lanzando wpscan${NC}"
    resultado_wpscan=$(analizar_wordpress "${protocol}://${target}")

    if [[ -n "$resultado_wpscan" ]]; then
        echo "$resultado_wpscan"
        md "\n### WordPress (wpscan)\n\nWordPress detectado. Ver detalle completo en \`wordpress.txt\`.\n\n\`\`\`\n${resultado_wpscan}\n\`\`\`"
        if [[ "$EXPORT" == true ]]; then
            echo "$resultado_wpscan" > "$WP_FILE"
        fi
    fi
fi

	echo -e "\n"
	sleep 4

# Llamada a wafw00f
if [[ "$wafw00f_disponible" == true ]]; then
    echo -e "${GREEN}[+] Comprobando WAF${NC}"
    wafw00f_output=$(wafw00f "${protocol}://${target}" 2>/dev/null)
    wafw00f_filtrado=$(echo "$wafw00f_output" | grep -E '^\[\*\]|^\[\+\]|^\[-\]' | grep -v "Number of requests")
    echo "$wafw00f_filtrado"
    md "\n### WAF (wafw00f)\n\n\`\`\`\n${wafw00f_filtrado}\n\`\`\`"
fi
	echo -e "\n"


# Fuzzing de directorios con ffuf (20k rutas)
echo -e "${GREEN}[+] Iniciando fuzzing de directorios${NC}"

umbral_ruido=5
umbral_rate_limit=10
threads=80
wordlist="/usr/share/dirb/wordlists/big.txt"
tmp_json=$(mktemp)

ffuf -ic -ac -s -w "$wordlist" -t "$threads" \
    -u "${protocol}://${target}/FUZZ" \
    -o "$tmp_json" -of json

# --- Comprobación de rate-limiting ---
rate_limit_hits=$(jq '[.results[] | select(.status == 429 or .status == 503 or .status == 508)] | length' "$tmp_json")

if (( rate_limit_hits > umbral_rate_limit )); then
    echo -e "${YELLOW}[!] Detectados $rate_limit_hits códigos de rate-limit (429/503/508) con $threads hilos.${NC}"
    echo -e "${YELLOW}[!] Reduciendo a 20 hilos y relanzando el escaneo...${NC}"

threads=20
    rm -f "$tmp_json"
    tmp_json=$(mktemp)

    ffuf -ic -ac -s -w "$wordlist" -t "$threads" \
        -u "${protocol}://${target}/FUZZ" \
        -o "$tmp_json" -of json

    rate_limit_hits=$(jq '[.results[] | select(.status == 429 or .status == 503 or .status == 508)] | length' "$tmp_json")
    echo -e "${YELLOW}[!] Tras reducir hilos: $rate_limit_hits códigos de rate-limit restantes${NC}"
fi

echo -e "\n"

total_resultados=$(jq '.results | length' "$tmp_json")
echo "[+] Resultados totales: $total_resultados"


# Filtrar ruido
tmp_data=$(mktemp)
jq -r '.results[] | "\(.url)|\(.status)|\(.words)|\(.lines)"' "$tmp_json" > "$tmp_data"
rm -f "$tmp_json"


declare -A conteo
while IFS='|' read -r url status words lines; do
    [[ "$status" == 3* ]] && continue   # las redirecciones nunca cuentan para detectar ruido
    clave="${status}|${words}|${lines}"
    conteo["$clave"]=$(( ${conteo["$clave"]:-0} + 1 ))
done < "$tmp_data"

limpios=()
sospechosos=()
while IFS='|' read -r url status words lines; do
    if [[ "$status" == 3* ]]; then
        limpios+=("$url")
        continue
    fi
    clave="${status}|${words}|${lines}"
    if (( ${conteo["$clave"]:-0} > umbral_ruido )); then
        sospechosos+=("$url")
    else
        limpios+=("$url")
    fi
done < "$tmp_data"

mapfile -t forbidden_urls < <(grep '|403|' "$tmp_data" | cut -d'|' -f1)
rm -f "$tmp_data"


        echo -e "\n"

echo -e "${GREEN}[+] Resultados únicos (patrón no repetido):${NC}"
for url in "${limpios[@]}"; do
    echo "$url"
done

if (( ${#sospechosos[@]} > 0 )); then
    echo -e "${YELL}[+] ${#sospechosos[@]} resultados con patrón repetido (>${umbral_ruido} veces, mismo status/words/lines). Resolviendo:${NC}"

    if [[ "$httpx_disponible" == true ]]; then
        printf '%s\n' "${sospechosos[@]}" | "$HTTPX_BIN" -silent -sc -title -fc 404
    else
        echo -e "${YELLOW}[!] httpx no disponible, usando fallback con curl (más lento, limitado a 50 URLs)${NC}"
        max_resolver=50
        count=0
        for url in "${sospechosos[@]}"; do
            if (( count >= max_resolver )); then
                echo "[...] Límite de $max_resolver alcanzado, resto omitido (instala httpx para resolver todo)"
                break
            fi
            resolver_con_curl "$url"
            (( count++ ))
        done
    fi
else
    echo "[+] No se detectaron grupos de ruido repetido"
fi

md "\n### Fuzzing de directorios\n\n**Resultados totales:** $total_resultados\n\n#### Resultados limpios (${#limpios[@]})\n\n\`\`\`\n$(printf '%s\n' "${limpios[@]}")\n\`\`\`"

if (( ${#sospechosos[@]} > 0 )); then
    md "\n#### Resultados sospechosos (${#sospechosos[@]}, patrón repetido >${umbral_ruido} veces)\n\nDescartados por comportamiento repetido, no listados individualmente en el reporte."
else
    md "\n#### Resultados sospechosos\n\nNo se detectaron grupos de ruido repetido."
fi

# -------------------------------- Bypass-403 -------------------------------------------------------
if (( ${#forbidden_urls[@]} > 0 )); then
    if [[ "$EXPORT" == false ]]; then
        read -rp "$(echo -e "${YELLOW}[!] Se detectaron ${#forbidden_urls[@]} rutas con 403 durante el fuzzing. ¿Quieres intentar técnicas de bypass sobre ellas? [y/N]: ${NC}")" respuesta_bypass

        if [[ "${respuesta_bypass,,}" == "y" ]]; then
            echo -e "${GREEN}[+] Probando técnicas de bypass de 403${NC}"
            bypass_output=""
            for url in "${forbidden_urls[@]}"; do
                path="${url#${protocol}://${target}}"
                echo "-- $url --"
                resultado_bypass=$(test_bypass_403 "$protocol" "$target" "$path")
                if [[ -n "$resultado_bypass" ]]; then
                    echo "$resultado_bypass"
                    bypass_output+="-- $url --"$'\n'"${resultado_bypass}"$'\n\n'
                else
                    echo "  [-] No se encontró ningún bypass"
                    bypass_output+="-- $url --"$'\n'"  [-] No se encontró ningún bypass"$'\n\n'
                fi
            done
            md "\n### Bypass de 403\n\n\`\`\`\n${bypass_output}\n\`\`\`"
        else
            echo "[-] Bypass de 403 omitido por el usuario"
            md "\n### Bypass de 403\n\nOmitido por el usuario."
        fi
    else
        echo -e "${YELLOW}[!] Se detectaron ${#forbidden_urls[@]} rutas con 403 durante el fuzzing.${NC}"
        echo -e "${YELLOW}    Vuelve a ejecutar con -n para poder probar bypass de forma interactiva.${NC}"
        md "\n### Bypass de 403\n\nSe detectaron ${#forbidden_urls[@]} rutas con 403. Ejecuta con \`-n\` para probar bypass interactivamente."
    fi
fi

	echo -e "\n"


# Leer Robots.txt si existe
echo -e "${GREEN}[+] Leyendo Robots.txt (si existe)${NC}"
robots_output=$(curl -s "${protocol}://${target}/robots.txt" \
  | grep -Ev '^\s*#|^\s*$' \
  | grep -Ei '^(disallow|allow):' \
  | awk -F': ' '{print $2}' \
  | sed '/^$/d' \
  | sort -u)

echo "$robots_output"
md "\n### robots.txt\n\n\`\`\`\n${robots_output:-(sin rutas relevantes o robots.txt no encontrado)}\n\`\`\`"

        echo -e "\n"


# Iniciar descubrimiento de subdominios
if [[ "$SUBDOMAIN_MODE" == false ]]; then
echo -e "${YELL}[+] Iniciando descubrimiento de subdominios${NC}"
        echo -e "\n"


# Paso 1: subfinder
echo -e "${GREEN}[+] Paso 1: subfinder${NC}"

mapfile -t subs_full < <(subfinder -silent -d "$target")

echo -e "${YELL}[+] Subdominios encontrados por subfinder: ${#subs_full[@]}${NC}"
for fqdn in "${subs_full[@]}"; do
    echo "${protocol}://${fqdn}"
done
        echo -e "\n"


# Paso 2: crt.sh (Certificate Transparency)
echo -e "${GREEN}[+] Paso 2: crt.sh${NC}"

# Consultar subs_crtsh
mapfile -t subs_crtsh < <(consultar_crtsh "$target")
echo "[+] crt.sh: ${#subs_crtsh[@]} entradas encontradas"


for fqdn in "${subs_crtsh[@]}"; do
    echo "$fqdn"
done
        echo -e "\n"


# Resumen final: unión y deduplicación de ambas fuentes
mapfile -t subs_totales < <(printf '%s\n' "${subs_full[@]}" "${subs_crtsh[@]}" | sort -u)

echo -e "${GREEN}[+] Resumen final de subdominios (subfinder + crt.sh)${NC}"
echo -e "${YELL}[+] Total únicos combinados: ${#subs_totales[@]}${NC}"
echo "  - subfinder: ${#subs_full[@]}"
echo "  - crt.sh:    ${#subs_crtsh[@]}"
echo -e "\n"

for fqdn in "${subs_totales[@]}"; do
    echo "$fqdn"
done

md "\n### Subdominios\n\n**subfinder:** ${#subs_full[@]} | **crt.sh:** ${#subs_crtsh[@]} | **Total únicos:** ${#subs_totales[@]}\n\n\`\`\`\n$(printf '%s\n' "${subs_totales[@]}")\n\`\`\`"


	echo -e "\n"

# Verificando subdominios vivos
echo -e "${GREEN}[+] Verificando cuáles subdominios responden (httpx)${NC}"

if [[ "$httpx_disponible" == true ]]; then
    live_subs_output=$(printf '%s\n' "${subs_totales[@]}" | "$HTTPX_BIN" -silent -sc -title -fc 404)
else
    echo -e "${YELLOW}[!] httpx no disponible, usando fallback con curl (más lento, limitado a 50)${NC}"
    max_resolver=50
    count=0
    live_subs_output=""
    for fqdn in "${subs_totales[@]}"; do
        if (( count >= max_resolver )); then
            echo "[...] Límite de $max_resolver alcanzado, resto omitido"
            break
        fi
        resultado=$(resolver_con_curl "${protocol}://${fqdn}")
        # Filtra líneas cuyo código de estado sea 404
        if [[ ! "$resultado" =~ ^\[404\] ]]; then
            live_subs_output+="${resultado}"$'\n'
        fi
        (( count++ ))
    done
fi

echo "$live_subs_output"

if [[ "$EXPORT" == true ]]; then
    echo "$live_subs_output" > "$SUBS_FILE"
fi

md "\n### Subdominios vivos (verificados)\n\nListado completo en \`subdominios_vivos.txt\`.\n\n\`\`\`\n${live_subs_output}\n\`\`\`"

fi

if [[ "$EXPORT" == true ]]; then
    md "\n---\n\n*Fin del reporte.*"
    echo -e "\n${GREEN}[+] Reporte guardado en: $REPORT_FILE${NC}"
    echo -e "${GREEN}[+] Carpeta de resultados: $OUTDIR${NC}"
fi
fi
