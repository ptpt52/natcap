local bit = require("bit")

local function _lshift(a, i)
	return a * 2^i
end

local function _rshift(a, i)
	return math.floor(a / 2^i)
end

local function _band(a, b)
	local r = 0
	a = bit.band(a, b)
	for i = 0, 31 do
		local x = bit.lshift(1, i)
		if bit.band(x, a) ~= 0 then
			r = r + 2^i
		end
	end
	return r
end

local function _bor(a, b)
	local r = 0
	a = bit.bor(a, b)
	for i = 0, 31 do
		local x = bit.lshift(1, i)
		if bit.band(x, a) ~= 0 then
			r = r + 2^i
		end
	end
	return r
end

local function _bxor(a, b)
	local r = 0
	a = bit.bxor(a, b)
	for i = 0, 31 do
		local x = bit.lshift(1, i)
		if bit.band(x, a) ~= 0 then
			r = r + 2^i
		end
	end
	return r
end

local function _bnot(a)
	local r = 0
	a = bit.bnot(a)
	for i = 0, 31 do
		local x = bit.lshift(1, i)
		if bit.band(x, a) ~= 0 then
			r = r + 2^i
		end
	end
	return r
end

local function get_parts_as_number(ipstr)
	local t = {}
	for part in string.gmatch(ipstr, "%d+") do
		table.insert(t, tonumber(part, 10))
	end
	return t
end

local function ipstr2int(ipstr)
	local ip = get_parts_as_number(ipstr)
	if #ip == 4 then
		return (((ip[1] * 256 + ip[2]) * 256 + ip[3]) * 256 + ip[4])
	end
	return 0
end

local function int2ipstr(ip)
	local a = _band(_rshift(ip, 24), 0x000000FF)
	local b = _band(_rshift(ip, 16), 0x000000FF)
	local c = _band(_rshift(ip, 8), 0x000000FF)
	local d = _band(_rshift(ip, 0), 0x000000FF)

	return string.format("%u.%u.%u.%u", a, b, c, d)
end

local function cidr2int(cidr)
	local x = 0
	for i = 0, cidr - 1 do
		x = x + _lshift(1, 31 - i)
	end
	return x
end

local function int2cidr(ip)
	for i = 0, 31 do
		if _band(ip, _lshift(1, 31 - i)) == 0 then
			return i
		end
	end
	return 32
end

-- 10 to 2
local function hexadecimal10to2(num)
	local bin_str = ""
	local num = tonumber(num)
	local mode_binstr = function(bin_str, num)
		while num ~=0 do
			bin_str = num ~= 1 and tostring(num % 2)..bin_str or tostring(num)..bin_str
			num = math.floor(num / 2)
		end

		for i = #bin_str + 1, 8 do
			bin_str = "0"..bin_str
		end

		return bin_str
	end

	return mode_binstr(bin_str, num)
end

-- get 1's numbers
local function get_1_numbers(str)
	local num = 0
	for i in string.gmatch(str, "%d") do
		if tonumber(i) == 1 then
			num = num + 1
		end
		if tonumber(i) == 0 then
			break
		end
	end

	return num
end

-- get ip or netmask bin str about batch
local function get_ips_bin_str(ip)
	local ip_parts = get_parts_as_number(ip)
	local bin_str = ""
	for _, v in ipairs(ip_parts) do
		bin_str = bin_str..hexadecimal10to2(v)
	end

	return bin_str
end

-- ip checkout
local function ip_checkout(ip)
	local ip_map = get_parts_as_number(ip)
	if ip_map[1] < 1 or ip == "1.0.0.0" or ip_map[1] == 127 or ip == "126.255.255.255" or ip == "128.0.0.0" or ip == "223.255.255.255" or ip_map[1] > 223 then
		return nil, "INVALID_IP_PERMIT"
	end
	return true
end

local function validate_ip_ranges(ip)
	if not ip then
		return nil, "INVALID_PARS"
	end

	local temp = ip
	local head, data1, data2, tail = temp:match("^(%d+).(%d+).(%d+).(%d+)$")
	if not (head and data1 and data2 and tail) then
		return nil, "IP_FORMAT_ERROR"
	end

	if tonumber(head) == 127 then
		return nil, "LOOKBACK"
	end

	if tonumber(head) < 1 or tonumber(head) > 223 then
		return nil, "INVALID_IP"
	end

	local r, e = ip_checkout(ip)
	if not r then
		return nil, e
	end

	for _, part in ipairs({head, data1, data2, tail}) do
		if #part ~= #tostring(tonumber(part)) then
			return nil, "IP_FORMAT_ERROR"
		end

		if tonumber(part) < 0 or tonumber(part) > 255 then
			return nil, "IP_FORMAT_ERROR"
		end
	end

	return ip
end

-- 将 24 转换为 “255.255.255.0”
local function cidr2maskstr(cidr)
	return int2ipstr(cidr2int(cidr))
end

-- 将“255.255.255.0” 转换为 24
local function maskstr2cidr(maskstr)
	return int2cidr(ipstr2int(maskstr))
end

-- 校验IP地址是否主机位全为0或者全为1
local function chekcout_netorbroadcast_address(ip, netmask)
	local ip_bin = get_ips_bin_str(ip)
	local mask_cidr = (type(netmask) == "number" or #netmask < 3) and tonumber(netmask) or maskstr2cidr(netmask)
	local host_bin = string.sub(ip_bin, mask_cidr + 1, #ip_bin)
	local num = get_1_numbers(host_bin)
	if num == #host_bin or (not string.find(host_bin, "1")) then
		return nil, "IP_ERROR_INTERNET"
	end

	return true
end

local function get_ip_and_mask(ipaddr)
	local n = get_parts_as_number(ipaddr)
	return (((n[1] * 256 + n[2]) * 256 + n[3]) * 256 + n[4]), cidr2int(n[5])
end

local function get_ipstr_and_maskstr(ipaddr)
	local ip, mask = get_ip_and_mask(ipaddr)
	return int2ipstr(ip), int2ipstr(mask)
end

local function ipstr2range(ipstr)
	ip = get_parts_as_number(ipstr)
	if #ip == 4 then
		local i = (((ip[1] * 256 + ip[2]) * 256 + ip[3]) * 256 + ip[4])
		return {i, i}
	end

	if #ip == 5 and ip[5] >=1 and ip[5] <= 32 then
		local i = (((ip[1] * 256 + ip[2]) * 256 + ip[3]) * 256 + ip[4])
		local m = cidr2int(ip[5])
		local s = _band(i, m)
		local e = _bor(i, _bnot(m))
		return {s, e}
	end

	if #ip == 8 then
		local s = (((ip[1] * 256 + ip[2]) * 256 + ip[3]) * 256 + ip[4])
		local e = (((ip[5] * 256 + ip[6]) * 256 + ip[7]) * 256 + ip[8])
		if s <= e then
			return {s, e}
		end
	end

	return nil
end

local function ipgroup_add(ipgrp, ipstr)
	local range = ipstr2range(ipstr)
	if not range then
		return ipgrp
	end

	ipgrp = ipgrp or {}
	if #ipgrp == 0 then
		table.insert(ipgrp, range)
		return ipgrp
	end

	local ipgrp_new = {}
	for _, r in ipairs(ipgrp) do
		if range[2] + 1 < r[1] then
			table.insert(ipgrp_new, range)
			range = r
		elseif range[2] + 1 >= r[1] and range[2] <= r[2] then
			if range[1] < r[1] then
				range = {range[1], r[2]}
			else
				range = r
			end
		else
			if r[2] + 1 < range[1] then
				table.insert(ipgrp_new, r)
				range = range
			else
				if r[1] < range[1] then
					range = {r[1], range[2]}
				else
					range = range
				end
			end
		end
	end
	table.insert(ipgrp_new, range)

	return ipgrp_new
end

local function ipranges2ipgroup(ipranges)
	local ipgrp = {}
	for _, ipstr in ipairs(ipranges) do
		ipgrp = ipgroup_add(ipgrp, ipstr)
	end
	return ipgrp
end

local function ipgroup2ipranges(ipgrp)
	local ipranges = {}
	for _, range in ipairs(ipgrp) do
		table.insert(ipranges, string.format("%s-%s", int2ipstr(range[1]), int2ipstr(range[2])))
	end
	return ipranges
end

--[[
local ipranges = {
	"1.1.1.1-2.2.2.2",
	"192.168.0.0/16",
	"192.168.0.1-192.168.0.2",
	"192.168.255.254-192.169.0.100",
	"172.16.0.1-172.16.0.100",
	"0.0.0.0-255.255.255.255"
}

local ipgrp = ipranges2ipgroup(ipranges)
for _, r in ipairs(ipgrp) do
	print(r[1], r[2])
end
ipranges = ipgroup2ipranges(ipgrp)
for _, ipstr in ipairs(ipranges) do
	print(ipstr)
end
]]

-- netmask checkout
local function netmask_checkout(ip, netmask, mode)
	local r, e = ip_checkout(ip)
	if not r then
		return nil, e
	end

	netmask = type(netmask) == "number" and tostring(netmask) or netmask

	if netmask:match("%d+.%d+.%d+.%d+") then
		local bin = ""
		local masks = get_parts_as_number(netmask)
		for _, v in ipairs(masks) do
			bin = bin..hexadecimal10to2(v)
		end

		if bin:find("01") then
			return nil, "INVALID_NETMASK"
		end

		local nums = get_1_numbers(bin)
		if nums < 8 or (not mode and nums == 31) then
			return nil, "INVALID_NETMASK_PERMIT"
		end
	end

	if not netmask:match("%d+.%d+.%d+.%d+") then
		netmask = type(netmask) == "number" and netmask or tonumber(netmask)
		if netmask < 8 or netmask == 31 then
			return nil, "INVALID_NETMASK_PERMIT"
		end
	end

	return true
end

-- checkout ip and netmask whether match or not
local function checkout_ipandnetmast_match(ip_range, netmask, netmask_type) -- netmask_type: netmask_ip, netmask_num
	if type(ip_range) == "table" then
		local r = ipranges2ipgroup(ip_range)
		local ip_nums = r[1][2]-r[1][1]

		local checkout = function(a, b)
			if tonumber(a) < 8 or tonumber(a) == 31 then
				return nil, "INVALID_NETMASK_PERMIT"
			end
			local c = _lshift(1, 32 - a)
			if tonumber(b) > tonumber(c) then
				return nil, "IP_OUT_RANGE_NETMASK"
			end

			return true
		end
		if netmask_type == "netmask_ip" then
			local bin = ""
			local masks = get_parts_as_number(netmask)
			for _, v in ipairs(masks) do
				bin = bin..hexadecimal10to2(v)
			end

			if bin:find("01") then
				return nil, "INVALID_NETMASK"
			end

			local nums = get_1_numbers(bin)
			local r, e = checkout(nums, ip_nums)
			if not r then
				return nil, e
			end
		end

		if netmask_type == "netmask_num" then
			local r, e = checkout(netmask, ip_nums)
			if not r then
				return nil, e
			end
		end

		return true
	end
	return nil, "NEED_TABLE"
end

local function get_netmask_bin(netmask)
	if not netmask:match("%d+.%d+.%d+.%d+") then
		local num = type(netmask) ~= "number" and tonumber(netmask) or netmask
		local bin = ""
		for i = 1, num do
			bin = bin.."1"
		end

		while #bin == 32 do
			bin = bin.."0"
		end

		return bin
	end
	if netmask:match("%d+.%d+.%d+.%d+") then
		local netmask_map = get_parts_as_number(netmask)
		local bin = ""
		for _, part in ipairs(netmask_map) do
			bin = bin..hexadecimal10to2(part)
		end

		return bin
	end
end

-- ??????
local function _and(bin1, bin2)
	local bin_result = ""
	local op1, op2 = {}, {}
	for i in bin1:gmatch("%d") do
		table.insert(op1, tonumber(i))
	end
	for i in bin2:gmatch("%d") do
		table.insert(op2, tonumber(i))
	end

	local r = {}
	for i = 1, 32 do
		if op1[i] == 1 and op2[i] == 1 then
			r[i] = 1
		else
			r[i] = 0
		end
	end

	local bin = ""
	for i = 1, 32 do
		bin = bin..tostring(r[i])
	end

	return bin
end

-- checkout ips's network segment
local function whether_network_segment_same(ip1, netmask1, ip2, netmask2)
	local ip1_bin = get_ips_bin_str(ip1)
	local mask1_bin = get_netmask_bin(netmask1)
	local ip2_bin = get_ips_bin_str(ip2)
	local mask2_bin = get_netmask_bin(netmask2)

	local ip1_net = _and(ip1_bin, mask1_bin)
	local ip2_net = _and(ip2_bin, mask2_bin)

	if ip1_net == ip2_net then
		return true, ip1_net, ip2_net
	end

	return false, ip1_net, ip2_net
end

--[[
local function main()
	local ip = "192.168.0.255"
	local netmask = "255.255.255.0"
	print(chekcout_netorbroadcast_address(ip, netmask))
end
main()
]]

return {
	ipstr2int 				= ipstr2int,
	int2ipstr 				= int2ipstr,
	cidr2int 				= cidr2int,
	int2cidr 				= int2cidr,
	cidr2maskstr 			= cidr2maskstr,
	maskstr2cidr 			= maskstr2cidr,
	get_ip_and_mask 		= get_ip_and_mask,
	get_ipstr_and_maskstr 	= get_ipstr_and_maskstr,

	lshift 					= _lshift,
	rshift 					= _rshift,
	band 					= _band,
	bor 					= _bor,
	bxor 					= _bxor,
	bnot 					= _bnot,
	_and 					= _and,

	ipranges2ipgroup 		= ipranges2ipgroup,
	ipgroup2ipranges 		= ipgroup2ipranges,
	ipgroup_add 			= ipgroup_add,
	ipstr2range 			= ipstr2range,
	ip_checkout				= ip_checkout,

	netmask_checkout		= netmask_checkout,
	hexadecimal10to2		= hexadecimal10to2,
	get_ips_bin_str			= get_ips_bin_str,
	get_netmask_bin			= get_netmask_bin,
	validate_ip_ranges		= validate_ip_ranges,
	get_parts_as_number		= get_parts_as_number,
	whether_network_segment_same = whether_network_segment_same,
	checkout_ipandnetmast_match = checkout_ipandnetmast_match,
	chekcout_netorbroadcast_address = chekcout_netorbroadcast_address,
}
