modprobe ip_set
modprobe nf_nat
modprobe  nf_conntrack
insmod ./natcap.ko
wget https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf -O accelerated-domains.china.conf && \
cat accelerated-domains.china.conf | cut -d\/ -f2 >accelerated-domains.china.raw.txt && {
	echo cn_domain_clean >/dev/natcap_ctl
	echo cn_domain_path=$(pwd)/accelerated-domains.china.raw.txt >/dev/natcap_ctl
	echo cn_domain_dump=$(pwd)/accelerated-domains.china.raw.build >/dev/natcap_ctl
	rm -f accelerated-domains.china.raw.build.gz
	gzip -n accelerated-domains.china.raw.build
	chmod 666 accelerated-domains.china.raw.build.gz accelerated-domains.china.raw.txt
}
