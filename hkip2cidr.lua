local ip2region = require("ip2region")

for _, cidr in ipairs(ip2region.generate("HK", {...})) do
	print(cidr)
end
