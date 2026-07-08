#!/bin/bash


#Colores
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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
echo -e "\n"




#FASE 2: Recon activo

echo -e "${YELLOW}[+] Iniciando reconocimiento activo para: $target${NC}"
        echo -e "\n"


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

# ---------------------------------------------------------
# Llamada a la función y comprobación (fase de pruebas)
# ---------------------------------------------------------
echo -e "${GREEN}[+] Detectando protocolo (HTTP/HTTPS)${NC}"
protocol=$(detectar_protocolo "$target")
echo "[DEBUG] Valor de \$protocol -> [$protocol]"

if [[ "$protocol" == "ninguno" ]]; then
    echo -e "${YELLOW}[-] $target no responde por HTTP ni HTTPS, se omite el resto de la Fase 2${NC}"
else

echo -e "${GREEN}[+] Iniciando reconocimiento con Whatweb${NC}"
        echo -e "\n"

echo "-----------------------------INICIO WHATWEB--------------------------------------"
whatweb -v "${protocol}://${target}"
echo "-----------------------------FINAL WHATWEB---------------------------------------"

	echo -e "\n"

echo -e "${GREEN}[+] Iniciando fuzzing de directorios${NC}"

mapfile -t encontrados < <(ffuf -c -ic -w /usr/share/dirb/wordlists/common.txt -t 80 -u "${protocol}://${target}/FUZZ" -s)

	echo -e "\n"

echo "[+] Directorios encontrados: ${#encontrados[@]}"

for dir in "${encontrados[@]}"; do
    echo "${protocol}://${target}/${dir}"
done
        echo -e "\n"

echo -e "${GREEN}[+] Leyendo Robots.txt (si existe)${NC}"
curl -s "${protocol}://${target}/robots.txt" \
  | grep -Ev '^\s*#|^\s*$' \
  | grep -Ei '^(disallow|allow):' \
  | awk -F': ' '{print $2}' \
  | sed '/^$/d' \
  | sort -u
        echo -e "\n"

echo -e "${GREEN}[+] Iniciando descubrimiento de subdominios${NC}"

       echo -e "\n"


echo "${GREEN}[+] Paso 1: ffuf${NC}"
ffuf -u "${protocol}://${target}/" \
     -H "Host: FUZZ.$target" \
     -w /usr/bin/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -mc 200,301,302,403 \
     -fs 0,151 \
     -s

        echo -e "\n"

fi


echo -e "${GREEN}[+] Paso 2: crt.sh${NC}"

curl -s "https://crt.sh/?q=%25.${target}&output=json" | jq -r '.[].name_value' | sort -u
