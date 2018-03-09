local args = {...}
local js =  require("cjson")
local ipops = require("ipops")

local group = {}

for _, arg in ipairs(args) do
	for line in io.lines(arg) do
		group = ipops.ipgroup_add(group, line)
	end
end

for i, range in pairs(group) do
	print(string.format("ipcalc -r %s-%s", ipops.int2ipstr(range[1]), ipops.int2ipstr(range[2])))
end
