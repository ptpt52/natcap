local args = {...}
local ipops = require("ipops")

local group = {}
local rangeSet = {}

local function get_parts_as_number(str)
	local t = {}
	for part in string.gmatch(str, "%d+") do
		table.insert(t, tonumber(part, 10))
	end
	return t
end

for _, arg in ipairs(args) do
	for line in io.lines(arg) do
		local ip = get_parts_as_number(line)
		if #ip == 5 then
			local ips = (((ip[1] * 256 + ip[2]) * 256 + ip[3]) * 256 + ip[4])
			local ipe = ips + ip[5] - 1
			rangeSet = ipops.rangeSet_add_range(rangeSet, {ips, ipe})
		end
	end
end

local ipcidrSet = ipops.rangeSet2ipcidrSet(rangeSet)
for _, ipcidr in ipairs(ipcidrSet) do
	print(ipcidr)
end
