#!/bin/bash


#Colores
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
YELL='\033[0;33m'

BIG='\033[1;32m'


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
echo -e "${GREEN}         Version 1.0 - by w1s4${NC}"
echo -e "${CYAN}=========================================================${NC}"
echo ""
}

banner
#-------------------------------------------------------------------------


# Verificar si se proporcionó un objetivo
if [ $# -eq 0 ]; then
    echo "Error: Debes proporcionar un dominio como argumento."
    echo "Uso: $0 example.com"
    exit 1
fi

target=$1


# DEFINIR FUNCIONES

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
        echo "$raw" | tail -n +2 | awk -F',' '{print $6}' | sed 's/\*\.//g' | sort -u
        return 0
    fi

    echo -e "${YELLOW}[-] crt.sh no devolvió resultados en ningún formato${NC}" >&2
    return 1
}
#-------------------------------------------------------------------------------------------------------------------




#FASE 1: Recon pasivo
echo -e "${BIG}[+] Iniciando reconocimiento web para: $target${NC}"
echo "Fecha: $(date)"

        echo -e "\n"


echo -e "${YELLOW}[+] Iniciando reconocimiento pasivo para: $target${NC}"

        echo -e "\n"


echo -e "${GREEN}[+] Iniciando reconocimiento WHOIS${NC}"
echo "$(whois $target | head -n 20)"

        echo -e "\n"


echo -e "${GREEN}[+] Iniciando reconocimiento IP${NC}"
ips=($(dig A +short "$target"))
echo -e "IPs encontradas:\n $ips"


max=4
ips_limitadas=("${ips[@]:0:$max}")

for ip in "${ips_limitadas[@]}"; do
    ipinfo "$ip"
done

sleep 2

echo -e "\n"




#FASE 2: Recon activo
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
else


# Whatweb verbose mode
echo -e "${GREEN}[+] Iniciando reconocimiento con Whatweb${NC}"
        echo -e "\n"

echo "-----------------------------INICIO WHATWEB--------------------------------------"
whatweb -v "${protocol}://${target}"
echo "-----------------------------FINAL WHATWEB---------------------------------------"

	echo -e "\n"



echo -e "${GREEN}[+] Iniciando fuzzing de directorios${NC}"

umbral_ruido=5
tmp_json=$(mktemp)

ffuf -ic -w /usr/share/dirb/wordlists/big.txt -t 80 \
     -u "${protocol}://${target}/FUZZ" \
     -o "$tmp_json" -of json 2>/dev/null

total_resultados=$(jq '.results | length' "$tmp_json")
echo "[+] Resultados totales: $total_resultados"

tmp_data=$(mktemp)
jq -r '.results[] | "\(.url)|\(.words)|\(.lines)"' "$tmp_json" > "$tmp_data"
rm -f "$tmp_json"

declare -A conteo
while IFS='|' read -r url words lines; do
    clave="${words}|${lines}"
    conteo["$clave"]=$(( ${conteo["$clave"]:-0} + 1 ))
done < "$tmp_data"

limpios=()
sospechosos=()
while IFS='|' read -r url words lines; do
    clave="${words}|${lines}"
    if (( ${conteo["$clave"]} > umbral_ruido )); then
        sospechosos+=("$url")
    else
        limpios+=("$url")
    fi
done < "$tmp_data"
rm -f "$tmp_data"
        echo -e "\n"

echo -e "${GREEN}[+] Resultados únicos (patrón no repetido):${NC}"
for url in "${limpios[@]}"; do
    echo "$url"
done

if (( ${#sospechosos[@]} > 0 )); then
    echo -e "${YELL}[+] ${#sospechosos[@]} resultados con patrón repetido (>${umbral_ruido} veces, mismas words/lines). Resolviendo:${NC}"

    if [[ "$httpx_disponible" == true ]]; then
        printf '%s\n' "${sospechosos[@]}" | "$HTTPX_BIN" -silent -sc -title -nc
    else
        for url in "${sospechosos[@]}"; do
            resolver_con_curl "$url"
        done
    fi
else
    echo "[+] No se detectaron grupos de ruido repetido"
fi

	echo -e "\n"

# Leer Robots.txt si existe
echo -e "${GREEN}[+] Leyendo Robots.txt (si existe)${NC}"
curl -s "${protocol}://${target}/robots.txt" \
  | grep -Ev '^\s*#|^\s*$' \
  | grep -Ei '^(disallow|allow):' \
  | awk -F': ' '{print $2}' \
  | sed '/^$/d' \
  | sort -u

        echo -e "\n"


# Iniciar descubrimiento de subdominios
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

fi
