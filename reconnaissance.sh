#!/bin/bash
# ==============================================================================
# Enhanced Simple Recon Script by Walnutsec (Single File Output)
# Tools: whatweb, nmap, subfinder, httpx, nuclei, ffuf, waybackurls, nikto
# Usage: ./enhanced-recon.sh <url> [--full|--quick] [--config <file>]
# Example: ./enhanced-recon.sh https://example.com --full --config myconfig.ini
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

declare -A CONFIG=(
    ["nmap_quick_rate"]="50"
    ["nmap_normal_rate"]="30"
    ["nmap_full_rate"]="10"
    ["nuclei_rate"]="10"
    ["ffuf_threads"]="50"
    ["ffuf_rate"]="100"
    ["parallel"]="true"
    ["output_formats"]="txt,html,json"
)

load_config() {
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        print_status "Loading configuration from $CONFIG_FILE"
        while IFS='=' read -r key value; do
            # Remove comments and whitespace
            key=$(echo "$key" | sed 's/[[:space:]]*#.*//;s/^[[:space:]]*//;s/[[:space:]]*$//')
            value=$(echo "$value" | sed 's/[[:space:]]*#.*//;s/^[[:space:]]*//;s/[[:space:]]*$//')
            
            if [[ -n "$key" && -n "$value" ]]; then
                CONFIG["$key"]="$value"
            fi
        done < "$CONFIG_FILE"
    fi
}

# HTML report
generate_html_report() {
    local html_file="${OUTPUT_FILE%.txt}.html"
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; border-left: 4px solid #3498db; }
        .summary { background: #e8f4fc; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .success { color: #27ae60; }
        .warning { color: #f39c12; }
        .error { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Reconnaissance Report</h1>
EOF

    cat >> "$html_file" << EOF
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Target:</strong> $TARGET_URL</p>
            <p><strong>Scan Type:</strong> $SCAN_TYPE</p>
            <p><strong>Start Time:</strong> $(date -r "$OUTPUT_FILE" "+%Y-%m-%d %H:%M:%S")</p>
            <p><strong>Subdomains Found:</strong> $([ -f "$SUBDOMAINS_TMP" ] && wc -l < "$SUBDOMAINS_TMP" || echo "0")</p>
            <p><strong>Live Subdomains:</strong> $([ -f "$LIVE_SUBDOMAINS_TMP" ] && wc -l < "$LIVE_SUBDOMAINS_TMP" || echo "0")</p>
        </div>
EOF

    ansi2html --input="$OUTPUT_FILE" >> "$html_file" 2>/dev/null || {
        echo "<pre>$(cat "$OUTPUT_FILE")</pre>" >> "$html_file"
    }

    cat >> "$html_file" << 'EOF'
    </div>
</body>
</html>
EOF

    print_success "HTML report generated: $html_file"
}

generate_json_report() {
    local json_file="${OUTPUT_FILE%.txt}.json"
    
    cat > "$json_file" << EOF
{
    "target": "$TARGET_URL",
    "domain": "$DOMAIN",
    "scan_type": "$SCAN_TYPE",
    "start_time": "$(date -r "$OUTPUT_FILE" "+%Y-%m-%d %H:%M:%S")",
    "subdomains": {
        "total": $([ -f "$SUBDOMAINS_TMP" ] && wc -l < "$SUBDOMAINS_TMP" || echo "0"),
        "live": $([ -f "$LIVE_SUBDOMAINS_TMP" ] && wc -l < "$LIVE_SUBDOMAINS_TMP" || echo "0"),
        "list": $([ -f "$LIVE_SUBDOMAINS_TMP" ] && jq -R -s -c 'split("\n")' < "$LIVE_SUBDOMAINS_TMP" || echo "[]")
    },
    "ports": {
        "open": $(grep "open" "$OUTPUT_FILE" | wc -l),
        "services": $(grep -E "^[0-9]+" "$OUTPUT_FILE" | awk '{print $3}' | sort | uniq -c | jq -R -s -c 'split("\n") | map(select(length > 0))')
    },
    "vulnerabilities": {
        "critical": $(grep -c "CRITICAL" "$OUTPUT_FILE"),
        "high": $(grep -c "HIGH" "$OUTPUT_FILE"),
        "medium": $(grep -c "MEDIUM" "$OUTPUT_FILE")
    },
    "directories": {
        "found": $(grep -c "Found directories/files:" "$OUTPUT_FILE")
    }
}
EOF

    print_success "JSON report generated: $json_file"
}

show_usage() {
    echo -e "${WHITE}Usage:${NC} $0 <url> [--full|--quick] [--config <file>]"
    echo ""
    echo -e "${WHITE}Options:${NC}"
    echo -e "  ${GREEN}--full${NC}    Comprehensive scan (all tools + wayback + nikto)"
    echo -e "  ${GREEN}--quick${NC}   Quick scan (basic tools only)"
    echo -e "  ${GREEN}--config${NC}  Use custom configuration file"
    echo -e "  ${GREEN}(none)${NC}    Normal scan (original tools + some extras)"
    echo ""
    echo -e "${WHITE}Examples:${NC}"
    echo -e "  $0 https://example.com"
    echo -e "  $0 https://example.com --full"
    echo -e "  $0 example.com --quick"
    echo -e "  $0 example.com --config myconfig.ini"
    exit 1
}

SCAN_TYPE="normal"
CONFIG_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)
            SCAN_TYPE="full"
            shift
            ;;
        --quick)
            SCAN_TYPE="quick"
            shift
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        *)
            if [[ -z "$TARGET_URL" ]]; then
                TARGET_URL="$1"
            else
                echo -e "${RED}❌ Invalid option: $1${NC}"
                show_usage
            fi
            shift
            ;;
    esac
done

if [[ -z "$TARGET_URL" ]] || [[ "$TARGET_URL" == "--help" ]] || [[ "$TARGET_URL" == "-h" ]]; then
    show_usage
fi

load_config

DOMAIN=$(echo "$TARGET_URL" | sed 's|https\?://||' | sed 's|/.*||' | sed 's|:.*||')
OUTPUT_FILE="enhanced_recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S).txt"
SUBDOMAINS_TMP="${DOMAIN}_subdomains.tmp"
LIVE_SUBDOMAINS_TMP="${DOMAIN}_live_subdomains.tmp"

WORDLISTS=(
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "/usr/share/wordlists/dirb/common.txt"
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/home/$(whoami)/wordlists/directory-list-2.3-medium.txt"
    "/opt/wordlists/directory-list-2.3-medium.txt"
    "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
    "/usr/share/dirb/wordlists/common.txt"
)

WORDLIST=""
for wl in "${WORDLISTS[@]}"; do
    if [[ -f "$wl" ]]; then
        WORDLIST="$wl"
        break
    fi
done

if [[ -z "$WORDLIST" ]]; then
    print_warning "No wordlist found in common locations."
    echo "You can download wordlists with:" >> "$OUTPUT_FILE"
    echo "- git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists" >> "$OUTPUT_FILE"
    echo "- Or manually download directory-list-2.3-medium.txt to ~/wordlists/" >> "$OUTPUT_FILE"
    echo "Directory fuzzing will be skipped." >> "$OUTPUT_FILE"
fi

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_header() {
    echo "" >> "$OUTPUT_FILE"
    echo "============================== $1 ==============================" >> "$OUTPUT_FILE"
    echo "Timestamp: $(date)" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
}

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        print_warning "Tool '$1' not found. Skipping..."
        return 1
    fi
    return 0
}

echo -e "${PURPLE}🚀 Enhanced Recon Script ${NC}"
echo -e "${CYAN}Target: $DOMAIN${NC}"
echo -e "${CYAN}Scan Type: $SCAN_TYPE${NC}"
echo -e "${CYAN}Output: $OUTPUT_FILE${NC}"
if [[ -n "$CONFIG_FILE" ]]; then
    echo -e "${CYAN}Config: $CONFIG_FILE${NC}"
fi
echo ""

cat > "$OUTPUT_FILE" << EOF
===============================================================================
                            RECONNAISSANCE REPORT
===============================================================================
Target URL: $TARGET_URL
Domain: $DOMAIN
Scan Type: $SCAN_TYPE
Start Time: $(date)
Generated by: Walnutsec Enhanced Script
===============================================================================
EOF

cleanup() {
    rm -f "$SUBDOMAINS_TMP" "$LIVE_SUBDOMAINS_TMP" /tmp/nmap_stdout.tmp /tmp/ffuf_results.json
}
trap cleanup EXIT

# 1. PARALLEL EXECUTION
print_status "(1/8) Running initial reconnaissance in parallel..."
print_header "PARALLEL RECONNAISSANCE (WhatWeb, Subfinder, Nmap)"

WHATWEB_TMP="/tmp/whatweb_${DOMAIN}.tmp"
SUBFINDER_TMP="/tmp/subfinder_${DOMAIN}.tmp"
NMAP_TMP="/tmp/nmap_${DOMAIN}.tmp"

# WhatWeb
if check_tool whatweb; then
    whatweb -v "$TARGET_URL" > "$WHATWEB_TMP" 2>/dev/null &
    WHATWEB_PID=$!
    print_status "Started WhatWeb (PID: $WHATWEB_PID)"
else
    echo "WhatWeb not available" >> "$OUTPUT_FILE"
    touch "$WHATWEB_TMP"
fi

# Subfinder
if check_tool subfinder; then
    subfinder -d "$DOMAIN" -silent > "$SUBFINDER_TMP" 2>/dev/null &
    SUBFINDER_PID=$!
    print_status "Started Subfinder (PID: $SUBFINDER_PID)"
else
    echo "Subfinder not available" >> "$OUTPUT_FILE"
    touch "$SUBFINDER_TMP"
fi

# Nmap
if check_tool nmap; then
    NMAP_RATE=""
    case "$SCAN_TYPE" in
        "quick")
            NMAP_RATE="--max-rate ${CONFIG[nmap_quick_rate]}"
            NMAP_CMD="nmap -T4 --top-ports 100 --open $NMAP_RATE -oA ${DOMAIN}_nmap_quick ${DOMAIN}"
            ;;
        "full")
            NMAP_RATE="--max-rate ${CONFIG[nmap_full_rate]}"
            NMAP_CMD="nmap -sS -sV -sC -T4 --top-ports 5000 --open $NMAP_RATE -oA ${DOMAIN}_nmap_full ${DOMAIN}"
            ;;
        *)
            NMAP_RATE="--max-rate ${CONFIG[nmap_normal_rate]}"
            NMAP_CMD="nmap -sS -sV -T4 --top-ports 1000 --open $NMAP_RATE -oA ${DOMAIN}_nmap_normal ${DOMAIN}"
            ;;
    esac
    
    eval "$NMAP_CMD" > "$NMAP_TMP" 2>/dev/null &
    NMAP_PID=$!
    print_status "Started Nmap (PID: $NMAP_PID)"
else
    echo "Nmap not available" >> "$OUTPUT_FILE"
    touch "$NMAP_TMP"
fi

wait $WHATWEB_PID $SUBFINDER_PID $NMAP_PID

{
    echo "===== WHATWEB RESULTS ====="
    cat "$WHATWEB_TMP"
    echo ""
    echo "===== SUBFINDER RESULTS ====="
    cat "$SUBFINDER_TMP"
    echo ""
    echo "===== NMAP RESULTS ====="
    cat "$NMAP_TMP"
    echo ""
    echo "Full Nmap output saved to ${DOMAIN}_nmap_${SCAN_TYPE}.(nmap|gnmap|xml)"
} >> "$OUTPUT_FILE"

if [[ -s "$SUBFINDER_TMP" ]]; then
    cp "$SUBFINDER_TMP" "$SUBDOMAINS_TMP"
    subdomain_count=$(wc -l < "$SUBDOMAINS_TMP")
    print_success "Subfinder found $subdomain_count subdomains"
else
    touch "$SUBDOMAINS_TMP"
fi

print_success "Parallel reconnaissance completed"

# 2. ADDITIONAL SUBDOMAIN TOOLS (if full scan)
if [[ "$SCAN_TYPE" == "full" ]]; then
    print_status "(2/8) Running additional subdomain discovery tools..."
    print_header "ADDITIONAL SUBDOMAIN DISCOVERY"
    
    # Assetfinder
    if check_tool assetfinder; then
        echo "--- Assetfinder Results ---" >> "$OUTPUT_FILE"
        assetfinder --subs-only "$DOMAIN" 2>/dev/null | tee -a "$SUBDOMAINS_TMP" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
    
    # Remove duplicates
    if [[ -f "$SUBDOMAINS_TMP" ]]; then
        sort "$SUBDOMAINS_TMP" | uniq > "${SUBDOMAINS_TMP}.sorted"
        mv "${SUBDOMAINS_TMP}.sorted" "$SUBDOMAINS_TMP"
        final_count=$(wc -l < "$SUBDOMAINS_TMP")
        echo "Total unique subdomains: $final_count" >> "$OUTPUT_FILE"
        print_success "Additional subdomain discovery completed"
    fi
else
    print_status "(2/8) Skipping additional subdomain discovery (use --full for more tools)"
fi

# 3. HTTPX - Live Subdomain Detection
print_status "(3/8) Running httpx to identify live subdomains..."
print_header "HTTPX - LIVE SUBDOMAINS"
if check_tool httpx && [[ -f "$SUBDOMAINS_TMP" ]] && [[ -s "$SUBDOMAINS_TMP" ]]; then
    cat "$SUBDOMAINS_TMP" | httpx -silent -o "$LIVE_SUBDOMAINS_TMP"
    if [[ -f "$LIVE_SUBDOMAINS_TMP" ]] && [[ -s "$LIVE_SUBDOMAINS_TMP" ]]; then
        live_count=$(wc -l < "$LIVE_SUBDOMAINS_TMP")
        print_success "httpx found $live_count live subdomains"
        
        echo "Gathering detailed info on live subdomains..." >> "$OUTPUT_FILE"
        cat "$LIVE_SUBDOMAINS_TMP" | httpx -silent -title -tech-detect -status-code -content-length -probe -json >> "$OUTPUT_FILE"
    else
        echo "No live subdomains found" >> "$OUTPUT_FILE"
        print_warning "No live subdomains detected"
    fi
else
    echo "httpx not available or no subdomains to check" >> "$OUTPUT_FILE"
fi

# 4. NUCLEI - Vulnerability Scanning
print_status "(4/8) Running Nuclei for vulnerability scanning..."
print_header "NUCLEI - VULNERABILITY SCANNING"
if check_tool nuclei && [[ -f "$LIVE_SUBDOMAINS_TMP" ]] && [[ -s "$LIVE_SUBDOMAINS_TMP" ]]; then
    nuclei -l "$LIVE_SUBDOMAINS_TMP" -c 50 -bs 35 -rate-limit "${CONFIG[nuclei_rate]}" -severity critical,high,medium -silent >> "$OUTPUT_FILE" 2>/dev/null
    print_success "Nuclei vulnerability scan completed"
elif [[ ! -s "$LIVE_SUBDOMAINS_TMP" ]]; then
    echo "No live subdomains available for vulnerability scanning" >> "$OUTPUT_FILE"
    print_warning "Skipping Nuclei - no live subdomains"
else
    echo "Nuclei not available" >> "$OUTPUT_FILE"
fi

# 5. DIRECTORY FUZZING
print_status "(5/8) Running directory fuzzing..."
print_header "FFUF - DIRECTORY FUZZING"
if [[ -n "$WORDLIST" ]] && check_tool ffuf; then
    echo "Fuzzing target: $TARGET_URL" >> "$OUTPUT_FILE"
    echo "Wordlist: $WORDLIST" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    FFUF_THREADS="${CONFIG[ffuf_threads]}"
    FFUF_RATE="${CONFIG[ffuf_rate]}"
    
    case "$SCAN_TYPE" in
        "quick")
            ffuf -w "$WORDLIST" -u "${TARGET_URL}/FUZZ" -c -t "$FFUF_THREADS" -rate "$FFUF_RATE" -fc 404,403,400 -fs 0 -mc 200,204,301,302,307,401,500 -o /tmp/ffuf_results.json -of json -s 2>/dev/null
            ;;
        "full")
            ffuf -w "$WORDLIST" -u "${TARGET_URL}/FUZZ" -c -t "$FFUF_THREADS" -rate "$FFUF_RATE" -fc 404,400 -recursion -recursion-depth 2 -o /tmp/ffuf_results.json -of json -s 2>/dev/null
            ;;
        *)
            ffuf -w "$WORDLIST" -u "${TARGET_URL}/FUZZ" -c -t "$FFUF_THREADS" -rate "$FFUF_RATE" -fc 404,403,400 -fs 0 -o /tmp/ffuf_results.json -of json -s 2>/dev/null
            ;;
    esac
    
    if [[ -f "/tmp/ffuf_results.json" ]]; then
        python3 -c "
import json
try:
    with open('/tmp/ffuf_results.json', 'r') as f:
        data = json.load(f)
    
    if 'results' in data and data['results']:
        print('Found directories/files:')
        for result in data['results']:
            url = result.get('url', '')
            status = result.get('status', '')
            length = result.get('length', '')
            print(f'[{status}] {url} (Size: {length})')
        print(f'\nTotal findings: {len(data[\"results\"])}')
    else:
        print('No directories or files found')
except:
    print('No valid results found')
" >> "$OUTPUT_FILE"
        rm -f /tmp/ffuf_results.json
    else
        echo "No directories or files found" >> "$OUTPUT_FILE"
    fi
    
    print_success "Directory fuzzing completed"
elif [[ -z "$WORDLIST" ]]; then
    echo "No wordlist available for directory fuzzing" >> "$OUTPUT_FILE"
    print_warning "Skipping directory fuzzing - no wordlist found"
else
    echo "ffuf not available" >> "$OUTPUT_FILE"
fi

# 6. ADDITIONAL TOOLS (Full scan only)
if [[ "$SCAN_TYPE" == "full" ]]; then
    print_status "(6/8) Running additional reconnaissance tools..."
    
    # Wayback URLs
    print_header "WAYBACK MACHINE - HISTORICAL URLS"
    if check_tool waybackurls; then
        echo "Fetching historical URLs for $DOMAIN..." >> "$OUTPUT_FILE"
        waybackurls "$DOMAIN" 2>/dev/null | head -100 >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "Note: Showing first 100 URLs. Historical URLs can reveal old endpoints, parameters, and files." >> "$OUTPUT_FILE"
        print_success "Wayback URLs retrieved"
    else
        echo "waybackurls not available" >> "$OUTPUT_FILE"
    fi
    
    # Nikto Web Scanner
    print_header "NIKTO - WEB VULNERABILITY SCANNER"
    if check_tool nikto; then
        nikto -h "$TARGET_URL" -Format txt -output - 2>/dev/null >> "$OUTPUT_FILE"
        print_success "Nikto web scan completed"
    else
        echo "nikto not available" >> "$OUTPUT_FILE"
    fi
    
    print_success "Additional tools completed"
else
    print_status "(6/8) Skipping additional tools (use --full for wayback URLs and nikto)"
fi

if [[ "${CONFIG[output_formats]}" == *"html"* ]]; then
    generate_html_report
fi

if [[ "${CONFIG[output_formats]}" == *"json"* ]]; then
    generate_json_report
fi

cat >> "$OUTPUT_FILE" << EOF
===============================================================================
                           RECONNAISSANCE SUMMARY
===============================================================================
Scan completed: $(date)
Target: $TARGET_URL ($DOMAIN)
Scan type: $SCAN_TYPE
STATISTICS:
- Subdomains discovered: $([ -f "$SUBDOMAINS_TMP" ] && wc -l < "$SUBDOMAINS_TMP" || echo "0")
- Live subdomains: $([ -f "$LIVE_SUBDOMAINS_TMP" ] && wc -l < "$LIVE_SUBDOMAINS_TMP" || echo "0")
- Wordlist used: $([ -n "$WORDLIST" ] && echo "$WORDLIST" || echo "None")
RECOMMENDATIONS:
1. Review port scan results for unusual services
2. Check subdomain results for interesting targets  
3. Analyze vulnerability scan findings (prioritize critical/high)
4. Test discovered directories for sensitive files
5. $([ "$SCAN_TYPE" == "full" ] && echo "Review wayback URLs for old endpoints and parameters" || echo "Run with --full for more comprehensive results")
Generated by Walnutsec
Happy Hunting! 🎯
===============================================================================
EOF

echo ""
print_success "🎉 Enhanced reconnaissance completed!"
print_success "📄 All results saved in: $OUTPUT_FILE"
if [[ "${CONFIG[output_formats]}" == *"html"* ]]; then
    print_success "🌐 HTML report: ${OUTPUT_FILE%.txt}.html"
fi
if [[ "${CONFIG[output_formats]}" == *"json"* ]]; then
    print_success "📊 JSON report: ${OUTPUT_FILE%.txt}.json"
fi
echo ""
echo -e "${CYAN}Summary:${NC}"
echo -e "  📊 Subdomains: $([ -f "$SUBDOMAINS_TMP" ] && wc -l < "$SUBDOMAINS_TMP" || echo "0")"
echo -e "  🟢 Live subdomains: $([ -f "$LIVE_SUBDOMAINS_TMP" ] && wc -l < "$LIVE_SUBDOMAINS_TMP" || echo "0")"
echo -e "  🎯 Scan type: $SCAN_TYPE"
echo ""
echo -e "${GREEN}Happy Hacking! 🚀${NC}"
