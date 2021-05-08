local args = {...}
local ipops = require("ipops")

local netStringSet = {}

for line in io.lines(args[1]) do
	table.insert(netStringSet, line)
end

local rangeSet = ipops.netStringSet2rangeSet(netStringSet)

local invgroup = {}
local lastrange = {0, 0}

for i, range in pairs(rangeSet) do
	if i == 1 then
		if 0 < range[1] then
			table.insert(invgroup, {0, range[1] - 1})
		end
		lastrange = range
	else
		if rangeSet[i-1][2] + 1 <= range[1] - 1 then
			table.insert(invgroup, {rangeSet[i-1][2] + 1, range[1] - 1})
		end
		lastrange = range
	end
end

if lastrange[2] < 4294967295 then
	table.insert(invgroup, {lastrange[2] + 1, 4294967295})
end

local ipcidrSet = ipops.rangeSet2ipcidrSet(invgroup)
for _, ipcidr in ipairs(ipcidrSet) do
	print(ipcidr)
end
