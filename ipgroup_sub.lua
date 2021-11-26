local args = {...}
local ipops = require("ipops")

local netStringSetA = {}
local netStringSetB = {}

for line in io.lines(arg[1]) do
	table.insert(netStringSetA, line)
end
for line in io.lines(arg[2]) do
	table.insert(netStringSetB, line)
end

local rangeSetA = ipops.netStringSet2rangeSet(netStringSetA)
local rangeSetB = ipops.netStringSet2rangeSet(netStringSetB)
local rangeSet = ipops.rangeSet_sub_rangeSet(rangeSetA, rangeSetB)
local ipcidrSet = ipops.rangeSet2ipcidrSet(rangeSet)
for _, ipcidr in ipairs(ipcidrSet) do
	print(ipcidr)
end
