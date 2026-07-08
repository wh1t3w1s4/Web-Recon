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


#FASE 2: Recon activo
        echo -e "\n"
        echo -e "\n"

echo -e "${YELLOW}[+] Iniciando reconocimiento activo para: $target${NC}"
        echo -e "\n"


echo -e "${GREEN}[+] Iniciando reconocimiento con Whatweb${NC}"
        echo -e "\n"

echo "-----------------------------INICIO WHATWEB--------------------------------------"
whatweb -v $target
echo "-----------------------------FINAL WHATWEB---------------------------------------"

	echo -e "\n"
echo -e "${GREEN}[+] Iniciando fuzzing de directorios${NC}"
ffuf -c -ic -w /usr/share/dirb/wordlists/common.txt -t 80 -u https://$target/FUZZ -s
        echo -e "\n"


echo -e "${GREEN}[+] Leyendo Robots.txt${NC}"
curl -s "https://$target/robots.txt" \
  | grep -Ev '^\s*#|^\s*$' \
  | grep -Ei '^(disallow|allow):' \
  | awk -F': ' '{print $2}' \
  | sed '/^$/d' \
  | sort -u
        echo -e "\n"


echo -e "${GREEN}[+] Iniciando descubrimiento de subdominios${NC}"
        echo -e "\n"


echo -e "${GREEN}[+] Paso 1: ffuf${NC}"

ffuf -u https://$target/ \
     -H "Host: FUZZ.$target" \
     -w /usr/bin/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -mc 200,301,302,403 \
     -fs 0,151
        echo -e "\n"


echo -e "${GREEN}[+] Paso 2: crt.sh${NC}"

curl -s "https://crt.sh/?q=%25.${target}&output=json" | jq -r '.[].name_value' | sort -u
