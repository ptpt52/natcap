local args = {...}
local js =  require("cjson")
local ipops = require("ipops")

local group = {}
local ipranges = {}

for _, arg in ipairs(args) do
	for line in io.lines(arg) do
		local ip = ipops.get_parts_as_number(line)
		if #ip == 5 then
			local ips = (((ip[1] * 256 + ip[2]) * 256 + ip[3]) * 256 + ip[4])
			local ipe = ips + ip[5] - 1
			table.insert(ipranges, string.format("%s-%s", ipops.int2ipstr(ips), ipops.int2ipstr(ipe)))
		end
	end
end

group = ipops.ipranges2ipgroup(ipranges)

for i, range in pairs(group) do
	print(string.format("ipcalc -r %s-%s", ipops.int2ipstr(range[1]), ipops.int2ipstr(range[2])))
end
