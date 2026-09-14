-- Run from the repository root: lua tests/ipset_ops.lua
local fast = require("ipset_ops")
local reference = require("ipops")

local function copy(ranges)
	local result = {}
	for i, range in ipairs(ranges) do
		result[i] = {range[1], range[2]}
	end
	return result
end

local function equal_ranges(a, b)
	assert(#a == #b, "range count differs")
	for i, range in ipairs(a) do
		assert(range[1] == b[i][1] and range[2] == b[i][2], "range differs")
	end
end

local function normalize_reference(ranges)
	local result = {}
	for _, range in ipairs(ranges) do
		result = reference.rangeSet_add_range(result, {range[1], range[2]})
	end
	return result
end

local function check_cidrs(ranges, expected)
	local before = copy(ranges)
	assert(table.concat(fast.rangeSet2ipcidrSet(ranges), "\n") == expected,
		"CIDRs differ")
	equal_ranges(ranges, before)
end

check_cidrs({}, "")
check_cidrs({{0, 4294967295}}, "0.0.0.0/0")
check_cidrs({{0, 0}, {4294967295, 4294967295}}, "0.0.0.0/32\n255.255.255.255/32")
check_cidrs({{1, 6}}, "0.0.0.1/32\n0.0.0.2/31\n0.0.0.4/31\n0.0.0.6/32")
check_cidrs({{2147483648, 4294967295}}, "128.0.0.0/1")

equal_ranges(fast.rangeSet_sub_rangeSet({{0, 9}, {20, 29}, {40, 49}}, {{5, 44}}),
	{{0, 4}, {45, 49}})
equal_ranges(fast.rangeSet_sub_rangeSet({{0, 4294967295}}, {{0, 4294967295}}), {})
equal_ranges(fast.rangeSet_sub_rangeSet({}, {{0, 1}}), {})
equal_ranges(fast.rangeSet_sub_rangeSet({{0, 1}}, {}), {{0, 1}})

local strings = {
	"192.0.2.1", "192.0.2.0/24", "198.51.100.1-198.51.100.17",
	"203.0.113.0/255.255.255.0", "", "invalid",
}
equal_ranges(fast.netStringSet2rangeSet(strings), reference.netStringSet2rangeSet(strings))

math.randomseed(12345)
for trial = 1, 100 do
	local a, b = {}, {}
	local offset = (trial % 2 == 0) and 4294963200 or 0
	local length = (trial % 3 == 0) and 1000 or 20
	for i = 1, 30 do
		local first = offset + math.random(0, 3000)
		a[i] = {first, first + math.random(0, length)}
		first = offset + math.random(0, 3000)
		b[i] = {first, first + math.random(0, length)}
	end
	local ra, rb = normalize_reference(a), normalize_reference(b)
	local na, nb = fast.rangeSet_normalize(a), fast.rangeSet_normalize(b)
	equal_ranges(na, ra)
	equal_ranges(nb, rb)
	local before_a, before_b = copy(na), copy(nb)
	local sub = fast.rangeSet_sub_rangeSet(na, nb)
	equal_ranges(sub, reference.rangeSet_sub_rangeSet(copy(na), copy(nb)))
	equal_ranges(na, before_a)
	equal_ranges(nb, before_b)
	check_cidrs(na, table.concat(reference.rangeSet2ipcidrSet(copy(na)), "\n"))
	check_cidrs(sub, table.concat(reference.rangeSet2ipcidrSet(copy(sub)), "\n"))
end

print("ipset operations: boundary cases and 100 randomized comparisons passed")
