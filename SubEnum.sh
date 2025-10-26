#!/bin/bash

# Check if domain is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

domain=$1
output_dir="subdomain_recon_${domain}"
mkdir -p $output_dir

echo "[+] Starting comprehensive subdomain discovery for: $domain"

# Phase 1: Passive Enumeration
echo "[+] Phase 1: Passive Enumeration"
{
    # Subfinder with all sources
    if command -v subfinder &> /dev/null; then
        subfinder -d $domain -all -silent
    else
        echo "[-] subfinder not found, skipping..."
    fi
    
    # Amass passive
    if command -v amass &> /dev/null; then
        amass enum -passive -d $domain
    else
        echo "[-] amass not found, skipping..."
    fi
    
    # Assetfinder
    if command -v assetfinder &> /dev/null; then
        assetfinder --subs-only $domain
    else
        echo "[-] assetfinder not found, skipping..."
    fi
    
    # CRT.sh certificates
    echo "[+] Querying crt.sh..."
    curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'
    
    # Wayback Machine
    echo "[+] Querying Wayback Machine..."
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
    
    # HackerTarget API
    echo "[+] Querying HackerTarget..."
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | cut -d',' -f1
    
    # ThreatCrowd
    echo "[+] Querying ThreatCrowd..."
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq -r '.subdomains[]' 2>/dev/null
    
    # BufferOverrun
    echo "[+] Querying BufferOverrun..."
    curl -s "https://dns.bufferover.run/dns?q=.$domain" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2
    
} | grep -E ".*\.$domain$" | sort -u > $output_dir/passive_subs.txt

echo "[+] Passive found: $(wc -l < $output_dir/passive_subs.txt) subdomains"

# Phase 2: DNS Bruteforcing
echo "[+] Phase 2: DNS Bruteforcing"
if command -v dnsx &> /dev/null; then
    # Check for common wordlist locations
    wordlist=""
    if [ -f "/usr/share/wordlists/subdomains.txt" ]; then
        wordlist="/usr/share/wordlists/subdomains.txt"
    elif [ -f "/usr/share/wordlists/dns/subdomains.txt" ]; then
        wordlist="/usr/share/wordlists/dns/subdomains.txt"
    else
        echo "[-] No subdomain wordlist found, creating basic one..."
        # Create a basic wordlist
        cat > /tmp/basic_subs.txt << EOF
www
api
dev
test
staging
mail
ftp
cpanel
admin
blog
shop
store
app
mobile
secure
portal
login
dashboard
support
help
docs
api
v1
v2
api1
api2
test
staging
dev
development
prod
production
EOF
        wordlist="/tmp/basic_subs.txt"
    fi
    
    dnsx -d $domain -w $wordlist -silent > $output_dir/brute_subs.txt
    echo "[+] Bruteforce found: $(wc -l < $output_dir/brute_subs.txt) subdomains"
else
    echo "[-] dnsx not found, skipping bruteforce..."
    touch $output_dir/brute_subs.txt
fi

# Phase 3: Permutations
echo "[+] Phase 3: Permutations"
if command -v alterx &> /dev/null && [ -s "$output_dir/passive_subs.txt" ]; then
    cat $output_dir/passive_subs.txt | alterx | dnsx -silent > $output_dir/permutation_subs.txt
    echo "[+] Permutations found: $(wc -l < $output_dir/permutation_subs.txt) subdomains"
else
    echo "[-] alterx not found or no passive subs, skipping permutations..."
    touch $output_dir/permutation_subs.txt
fi

# Combine all results
cat $output_dir/passive_subs.txt $output_dir/brute_subs.txt $output_dir/permutation_subs.txt | \
sort -u > $output_dir/all_subdomains.txt

echo "[+] Total unique subdomains: $(wc -l < $output_dir/all_subdomains.txt)"

# Phase 4: Live Verification
echo "[+] Phase 4: Live Verification"
if command -v httpx &> /dev/null && [ -s "$output_dir/all_subdomains.txt" ]; then
    cat $output_dir/all_subdomains.txt | httpx -silent -threads 100 > $output_dir/live_subdomains.txt
    echo "[+] Live subdomains: $(wc -l < $output_dir/live_subdomains.txt)"
else
    echo "[-] httpx not found or no subdomains, skipping live verification..."
    touch $output_dir/live_subdomains.txt
fi

# Phase 5: DNS Resolution
echo "[+] Phase 5: DNS Resolution"
if command -v dnsx &> /dev/null && [ -s "$output_dir/all_subdomains.txt" ]; then
    cat $output_dir/all_subdomains.txt | dnsx -silent -a -resp -o $output_dir/dns_resolution.txt
    echo "[+] DNS resolution saved"
else
    echo "[-] dnsx not found or no subdomains, skipping DNS resolution..."
    touch $output_dir/dns_resolution.txt
fi

# Create summary report
echo "=== Subdomain Discovery Report for $domain ===" > $output_dir/report.txt
echo "Scan date: $(date)" >> $output_dir/report.txt
echo "Passive subdomains: $(wc -l < $output_dir/passive_subs.txt)" >> $output_dir/report.txt
echo "Bruteforce subdomains: $(wc -l < $output_dir/brute_subs.txt)" >> $output_dir/report.txt
echo "Permutation subdomains: $(wc -l < $output_dir/permutation_subs.txt)" >> $output_dir/report.txt
echo "Total unique subdomains: $(wc -l < $output_dir/all_subdomains.txt)" >> $output_dir/report.txt
echo "Live subdomains: $(wc -l < $output_dir/live_subdomains.txt)" >> $output_dir/report.txt

echo ""
echo "[+] === SCAN COMPLETE ==="
echo "[+] Results saved in: $output_dir/"
echo "[+] Total subdomains found: $(wc -l < $output_dir/all_subdomains.txt)"
echo "[+] Live subdomains: $(wc -l < $output_dir/live_subdomains.txt)"
echo "[+] View results:"
echo "    cat $output_dir/all_subdomains.txt"
echo "    cat $output_dir/live_subdomains.txt"
