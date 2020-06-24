cat urls.js | grep -v "^[ ]*//" | \
		grep -o "\(http\|https\)://.*" | \
		cut -d"/" -f3 | \
		grep -v '*' | \
		sort | uniq | \
		grep -v '\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)' \
		>gfwlist1.tocn.host.txt

cat urls.js | grep -v "^[ ]*//" | \
		grep -o "\(http\|https\)://.*" | \
		cut -d"/" -f3 | \
		grep -v '*' | \
		sort | uniq | \
		grep -v '\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)' \
		>gfwlist1.tocn.ip.txt
