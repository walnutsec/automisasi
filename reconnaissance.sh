#!/bin/bash

# ==============================================================================
# Simple Recon Script by Walnutsec
# Tools: whatweb, nmap, subfinder, httpx, nuclei, ffuf
# Usage: ./recon-plus.sh <url>
# Example: ./recon-plus.sh https://example.com
# ==============================================================================

if [ "$#" -ne 1 ]; then
    echo "❌ Penggunaan: $0 <url>"
    echo "Contoh: $0 https://example.com"
    exit 1
fi

TARGET_URL=$1
DOMAIN=$(echo $TARGET_URL | awk -F/ '{print $3}')
OUTPUT_FILE="recon_results_${DOMAIN}.txt"
SUBDOMAINS_TMP="${DOMAIN}_subdomains.txt"
LIVE_SUBDOMAINS_TMP="${DOMAIN}_live_subdomains.txt"

WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

if [ ! -f "$WORDLIST" ]; then
    echo "⚠️ Peringatan: Wordlist tidak ditemukan di '$WORDLIST'."
    echo "Harap edit script dan sesuaikan variabel WORDLIST."
fi


print_header() {
    echo "" >> $OUTPUT_FILE
    echo "============================== $1 ==============================" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
}

# --- Mulai Proses ---
> $OUTPUT_FILE
rm -f $SUBDOMAINS_TMP $LIVE_SUBDOMAINS_TMP

echo "🚀 Memulai reconnaissance LENGKAP untuk: $DOMAIN"
echo "📝 Hasil akan disimpan di: $OUTPUT_FILE"
echo ""

# 1. WHATWEB
echo "[*] (1/6) Menjalankan WhatWeb untuk identifikasi teknologi..."
print_header "WHATWEB"
whatweb -v "$TARGET_URL" >> $OUTPUT_FILE
echo "[+] WhatWeb selesai."

# 2. NMAP
echo "[*] (2/6) Menjalankan Nmap untuk port scanning..."
print_header "NMAP (Main Domain)"
nmap -sC -sV -T4 "$DOMAIN" >> $OUTPUT_FILE
echo "[+] Nmap selesai."

# 3. SUBFINDER
echo "[*] (3/6) Menjalankan Subfinder untuk mencari subdomain..."
print_header "SUBFINDER (All Subdomains)"
subfinder -d "$DOMAIN" -o $SUBDOMAINS_TMP -silent
cat $SUBDOMAINS_TMP >> $OUTPUT_FILE
echo "[+] Subfinder selesai. Menemukan $(wc -l < $SUBDOMAINS_TMP) subdomain."

# 4. HTTPX
echo "[*] (4/6) Menjalankan httpx untuk menemukan subdomain yang aktif..."
print_header "HTTPX (Live Subdomains)"
httpx -l $SUBDOMAINS_TMP -o $LIVE_SUBDOMAINS_TMP -silent
cat $LIVE_SUBDOMAINS_TMP >> $OUTPUT_FILE
echo "[+] httpx selesai. Menemukan $(wc -l < $LIVE_SUBDOMAINS_TMP) subdomain yang aktif."

# 5. NUCLEI
if [ -s $LIVE_SUBDOMAINS_TMP ]; then
    echo "[*] (5/6) Menjalankan Nuclei untuk scan kerentanan..."
    print_header "NUCLEI (Vulnerability Scan)"
    nuclei -l $LIVE_SUBDOMAINS_TMP -c 50 -bs 35 -o- >> $OUTPUT_FILE
    echo "[+] Nuclei selesai."
else
    echo "[!] (5/6) Melewati Nuclei karena tidak ada subdomain aktif yang ditemukan."
fi

# 6. FFUF
if [ -f "$WORDLIST" ]; then
    echo "[*] (6/6) Menjalankan ffuf untuk mencari direktori tersembunyi..."
    print_header "FFUF (Directory Fuzzing)"
    ffuf -w "$WORDLIST" -u "${TARGET_URL}/FUZZ" -c -v >> $OUTPUT_FILE
    echo "[+] ffuf selesai."
else
    echo "[!] (6/6) Melewati ffuf karena wordlist tidak ditemukan."
fi

echo ""
echo "🧹 Membersihkan file temporary..."
rm -f $SUBDOMAINS_TMP $LIVE_SUBDOMAINS_TMP

echo "✅ Reconnaissance selesai! Semua hasil tersimpan di $OUTPUT_FILE"
