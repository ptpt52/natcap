local ip2region = require("ip2region")

for _, cidr in ipairs(ip2region.generate("CN", {...})) do
	print(cidr)
end
