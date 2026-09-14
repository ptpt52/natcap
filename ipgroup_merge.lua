local args = {...}
local ipops = require("ipset_ops")

local netStringSet = {}

for _, arg in ipairs(args) do
	for line in io.lines(arg) do
		table.insert(netStringSet, line)
	end
end

local rangeSet = ipops.netStringSet2rangeSet(netStringSet)
local ipcidrSet = ipops.rangeSet2ipcidrSet(rangeSet)
for _, ipcidr in ipairs(ipcidrSet) do
	print(ipcidr)
end
