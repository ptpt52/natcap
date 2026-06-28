sed -n -e '/^[ ]*\/\//d' -e 's/.*https\?:\/\/\([^/]*\).*/\1/p' urls.js | grep -v '\*' | sort -u > temp_domains.txt
grep -vE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' temp_domains.txt > gfwlist1.tocn.host.txt
grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' temp_domains.txt > gfwlist1.tocn.ip.txt
rm -f temp_domains.txt
