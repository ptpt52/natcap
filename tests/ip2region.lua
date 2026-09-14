-- Run from the repository root: lua tests/ip2region.lua
local region = require("ip2region")
local ops = require("ipset_ops")
local data = region.read("tests/ip2region.txt")

assert(region.classify("中国", "香港") == "HK")
assert(region.classify("中国", "澳门") == "MO")
assert(region.classify("中国", "台湾") == "TW")
assert(region.classify("Hong Kong", "0") == "HK")
assert(region.classify("China", "0") == "CN")
assert(region.classify("", "0") == nil)

local fallback = ops.netStringSet2rangeSet({"192.0.2.0/24", "118.184.0.0/17"})
local cn = region.select(data, "CN", fallback)
local hk = region.select(data, "HK", fallback)

local function contains(ranges, ip)
	local value = ops.netString2range(ip)[1]
	for _, range in ipairs(ranges) do
		if range[1] <= value and value <= range[2] then return true end
	end
	return false
end

-- ip2region wins in both directions; MO, TW and foreign ranges enter neither list.
for last = 0, 255 do
	local ip = "192.0.2." .. last
	assert(contains(cn, ip) == (last < 64 or last >= 192), "CN conflict: " .. ip)
	assert(contains(hk, ip) == ((last >= 64 and last < 96) or last >= 192), "HK conflict: " .. ip)
end
assert(not contains(cn, "118.184.26.113"))
assert(contains(hk, "118.184.26.113"))
-- Classified ranges must also be added when absent from all fallback sources.
assert(contains(region.select(data, "CN", {}), "192.0.2.1"))
assert(contains(region.select(data, "HK", {}), "118.184.26.113"))
assert(contains(cn, "118.184.12.255"))
assert(contains(cn, "118.184.68.0"))
print("ip2region: CN/HK precedence, MO/TW/foreign exclusion and fallback passed")
