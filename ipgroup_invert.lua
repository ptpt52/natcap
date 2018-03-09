local args = {...}
local js =  require("cjson")
local ipops = require("ipops")

local group = {}

for line in io.lines(args[1]) do
	group = ipops.ipgroup_add(group, line)
end

local invgroup = {}
local lastrange = {0, 0}

for i, range in pairs(group) do
	if i == 1 then
		if 0 < range[1] then
			table.insert(invgroup, {0, range[1] - 1})
		end
		lastrange = range
	else
		if group[i-1][2] + 1 <= range[1] - 1 then
			table.insert(invgroup, {group[i-1][2] + 1, range[1] - 1})
		end
		lastrange = range
	end
end

if lastrange[2] < 4294967295 then
	table.insert(invgroup, {lastrange[2] + 1, 4294967295})
end

for i, range in pairs(invgroup) do
	print(string.format("ipcalc -r %s-%s", ipops.int2ipstr(range[1]), ipops.int2ipstr(range[2])))
end
