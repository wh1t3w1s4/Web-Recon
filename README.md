# Web-Recon v0.2.0-beta

Script bash de reconocimiento web (pasivo + activo) para auditorías, bug bounty y CTFs con autorización.

**v0.2.0-beta** · en pruebas, puede tener bugs · [licencia CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.es)

## Instalación

```bash
git clone https://github.com/wh1t3w1s4/Web-Recon
cd Web-Recon
chmod +x setup.sh
./setup.sh
```

## Uso

```bash
./web_recon.sh ejemplo.com
```

| Opción | Qué hace |
|---|---|
| `-o <ruta>` | Carpeta de salida (por defecto `./resultados`) |
| `-n` | No exportar nada, solo pantalla. Activa la pregunta de bypass de 403 |
| `-s` | Modo subdominio: escanea directo, sin WHOIS ni descubrimiento de subdominios |
| `-h` | Ayuda |

```bash
./web_recon.sh -s admin.ejemplo.com
./web_recon.sh -n -o /home/user/pentest ejemplo.com
```

**Ctrl+K** corta la ejecución en cualquier momento.

### Salida

Cada escaneo (salvo `-n`) crea `resultados/<target>_<fecha>/` con:
- `reporte_final.md` — todo el escaneo, en Markdown
- `subdominios_vivos.txt`
- `wordpress.txt` (solo si hay hallazgos de WordPress)


## Qué hace, por fase

**Fase 1 (pasiva)** — WHOIS, registros DNS (A/MX/NS/TXT/SOA/CNAME/CAA con interpretación automática de SPF/DKIM/DMARC, takeovers, etc.), geolocalización de IPs.

**Fase 2 (activa)** — protocolo HTTP/HTTPS, whatweb, vulnerabilidades conocidas por versión, cabeceras de seguridad y cookies (HSTS, CSP, HttpOnly/Secure/SameSite...), WordPress + wpscan si aplica, WAF, fuzzing de directorios con filtrado de ruido y bypass de 403 sobre lo encontrado, robots.txt, y descubrimiento de subdominios (subfinder + crt.sh).

`-s` ejecuta solo la parte de Fase 2 que tiene sentido sobre un host ya conocido (sin WHOIS ni descubrimiento de subdominios).

## Dependencias

Instaladas automáticamente por `setup.sh`. Si prefieres a mano:

| Herramienta | Instalación |
|---|---|
| whois, dig, curl, jq, python3, whatweb, dirb | `apt install <nombre>` |
| wafw00f | `pip install wafw00f` |
| wpscan | `gem install wpscan` |
| ffuf, subfinder, httpx | `go install github.com/.../<tool>@latest` |

Faltando alguna, el script avisa y omite o usa fallback (curl en vez de httpx, por ejemplo) en vez de romperse.

**wpscan (opcional):** con token gratuito de [wpscan.com](https://wpscan.com/) consulta su base de CVEs.
```bash
export WPSCAN_API_TOKEN="tu_token"
```

`httpx` de ProjectDiscovery puede chocar con el paquete de Python del mismo nombre — el script usa ruta absoluta (`$HOME/.go/bin/httpx` por defecto, configurable con `HTTPX_BIN`).

## Vulnerabilidades por versión

`VULN_DB` (editable en el script) compara versiones detectadas por whatweb contra CVEs conocidos — comprobación determinista, no un escáner completo. Puede dar falsos positivos con backports, y solo cubre lo que hay añadido a mano en la base de datos.

## Roadmap

- Flag `-d/--deep`: wpscan agresivo + bypass 403 automático
- Export en JSON
- Ampliar `VULN_DB`, screenshots, comparación entre escaneos

## Feedback

Abre un Issue con el comando exacto, la salida obtenida y tu sistema operativo.

## Uso responsable

Solo contra objetivos con autorización explícita. El autor no se hace responsable del uso indebido.
