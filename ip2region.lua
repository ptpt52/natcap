local ipops = require("ipset_ops")
local M = {}

local special = {
	["香港"] = "HK", ["香港特别行政区"] = "HK", ["Hong Kong"] = "HK", ["HK"] = "HK",
	["澳门"] = "MO", ["澳门特别行政区"] = "MO", ["Macao"] = "MO", ["Macau"] = "MO", ["MO"] = "MO",
	["台湾"] = "TW", ["台湾省"] = "TW", ["Taiwan"] = "TW", ["TW"] = "TW",
}

function M.classify(country, region)
	if country == "中国" or country == "China" or country == "CN" then
		return special[region] or "CN"
	end
	if country == "" or country == "0" or country == "Unknown" then
		return nil
	end
	return special[country] or "OTHER"
end

-- Coalesce consecutive records before sorting to keep full-database memory low.
local function append(ranges, range)
	local last = ranges[#ranges]
	if last and last[2] + 1 == range[1] then
		last[2] = range[2]
	else
		ranges[#ranges + 1] = {range[1], range[2]}
	end
end

function M.read(filename)
	local data = {known = {}, CN = {}, HK = {}}
	for line in io.lines(filename) do
		-- start|end|country|province/region|city|ISP|country-code
		local first, last, country, region = line:match("^([^|]+)|([^|]+)|([^|]*)|([^|]*)|")
		if first then
			local kind = M.classify(country, region)
			local range = ipops.netString2range(first .. "-" .. last)
			if kind and range then
				append(data.known, range)
				if data[kind] then append(data[kind], range) end
			end
		end
	end
	for key, ranges in pairs(data) do
		data[key] = ipops.rangeSet_normalize(ranges)
	end
	return data
end

function M.select(data, country, fallback)
	-- Replace every classified range, including ranges assigned to other countries.
	local ranges = ipops.rangeSet_sub_rangeSet(ipops.rangeSet_normalize(fallback), data.known)
	for _, range in ipairs(assert(data[country], "unsupported country")) do
		ranges[#ranges + 1] = range
	end
	return ipops.rangeSet_normalize(ranges)
end

function M.generate(country, filenames)
	local data = M.read("ip.merge.txt")
	local fallback = {}
	for _, filename in ipairs(filenames) do
		for line in io.lines(filename) do
			local range = ipops.netString2range(line)
			if range then append(fallback, range) end
		end
	end
	return ipops.rangeSet2ipcidrSet(M.select(data, country, fallback))
end

return M
