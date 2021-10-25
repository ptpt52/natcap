local ipops = require "ipops"

local rangeSet = {}

for line in io.lines("ip.merge.txt") do
	local ip1, ip2, z1, _, z2 = line:match('(%d+.%d+.%d+.%d+)|(%d+.%d+.%d+.%d+)|(%S-)|(%S-)|(%S-)|.*')
	--print(z1, z2)
	if z1 == '中国' and z2 ~= '香港' and z2 ~= '台湾省' and z2 ~= '澳门' then
		local netString = string.format("%s-%s", ip1, ip2)
		rangeSet = ipops.rangeSet_add_range(rangeSet, ipops.netString2range(netString))
	end
end

local ipcidrSet = ipops.rangeSet2ipcidrSet(rangeSet)
--print(table.concat(ipcidrSet, ','))
for _, ipcidr in ipairs(ipcidrSet) do
	print(ipcidr)
end
