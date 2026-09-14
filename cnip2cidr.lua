local ipops = require "ipset_ops"

local rangeSet = {}

for line in io.lines("ip.merge.txt") do
	local ip1, ip2, z1, _, z2 = line:match('(%d+.%d+.%d+.%d+)|(%d+.%d+.%d+.%d+)|(%S-)|(%S-)|(%S-)|.*')
	--print(z1, z2)
	if z1 == '中国' and z2 ~= '香港' and z2 ~= '台湾省' and z2 ~= '澳门' then
		local netString = string.format("%s-%s", ip1, ip2)
		local range = ipops.netString2range(netString)
		if range then rangeSet[#rangeSet + 1] = range end
	end
end

local ipcidrSet = ipops.rangeSet2ipcidrSet(ipops.rangeSet_normalize(rangeSet))
--print(table.concat(ipcidrSet, ','))
for _, ipcidr in ipairs(ipcidrSet) do
	print(ipcidr)
end
