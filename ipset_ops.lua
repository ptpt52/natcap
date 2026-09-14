-- Batch operations for the build-time IPv4 lists (Lua 5.1 compatible).
local ipops = require("ipops")
local M = {netString2range = ipops.netString2range}

-- Sort once, then merge overlapping or adjacent ranges in a single pass.
function M.rangeSet_normalize(ranges)
	table.sort(ranges, function(a, b)
		return a[1] < b[1] or (a[1] == b[1] and a[2] < b[2])
	end)
	local result = {}
	for _, range in ipairs(ranges) do
		local last = result[#result]
		if last and range[1] <= last[2] + 1 then
			last[2] = math.max(last[2], range[2])
		else
			result[#result + 1] = {range[1], range[2]}
		end
	end
	return result
end

function M.netStringSet2rangeSet(strings)
	local ranges = {}
	for _, str in ipairs(strings) do
		local range = M.netString2range(str)
		if range then
			ranges[#ranges + 1] = range
		end
	end
	return M.rangeSet_normalize(ranges)
end

-- Both inputs are sorted, disjoint range sets returned by normalization.
function M.rangeSet_sub_rangeSet(a, b)
	local result, j = {}, 1
	for _, range in ipairs(a) do
		local first, last = range[1], range[2]
		while b[j] and b[j][2] < first do
			j = j + 1
		end
		while b[j] and b[j][1] <= last do
			if b[j][1] > first then
				result[#result + 1] = {first, b[j][1] - 1}
			end
			first = math.max(first, b[j][2] + 1)
			if first > last then
				break
			end
			j = j + 1
		end
		if first <= last then
			result[#result + 1] = {first, last}
		end
	end
	return result
end

local sizes = {}
for prefix = 0, 32 do
	sizes[prefix] = 2 ^ (32 - prefix)
end

function M.rangeSet2ipcidrSet(ranges)
	local result = {}
	for _, range in ipairs(ranges) do
		local first, last = range[1], range[2]
		while first <= last do
			-- The largest aligned block contained in the remaining range.
			for prefix = 0, 32 do
				local size = sizes[prefix]
				if first % size == 0 and size <= last - first + 1 then
					result[#result + 1] = ipops.int2ipstr(first) .. '/' .. prefix
					first = first + size
					break
				end
			end
		end
	end
	return result
end

return M
