-- The MIT License (MIT)
--
-- Copyright (c) 2018 Tim Düsterhus
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--
-- SPDX-License-Identifier: MIT

core.register_action("auth-request", { "http-req" }, function(txn, be, path)
	auth_request(txn, be, path, "HEAD", { "^.*$" }, nil, nil)
end, 2)

core.register_action("auth-intercept", { "http-req" }, function(txn, be, path, method, hdr_req, hdr_succeed, hdr_fail)
	hdr_req = globToLuaPatterns(hdr_req)
	hdr_succeed = globToLuaPatterns(hdr_succeed)
	hdr_fail = globToLuaPatterns(hdr_fail)
	auth_request(txn, be, path, method, hdr_req, hdr_succeed, hdr_fail)
end, 6)

function globToLuaPatterns(glob)
	if glob == "-" then
		return nil
	end
	local patterns = {}
	for g in glob:gmatch("[^,]+") do
		-- magic chars: '^', '$', '(', ')', '%', '.', '[', ']', '*', '+', '-', '?'
		-- https://www.lua.org/manual/5.4/manual.html#6.4.1
		local p = "^" .. g:gsub("[%^%$%(%)%%%.%[%]%+%-]", "%%%1"):gsub("*", ".*"):gsub("?", ".") .. "$"
		table.insert(patterns, p)
	end
	return patterns
end

function set_var(txn, var, value)
	return txn:set_var(var, value, true)
end

function sanitize_header_for_variable(header)
	return header:gsub("[^a-zA-Z0-9]", "_")
end

-- header_match checks whether the provided header matches the pattern.
-- patterns is a table of Lua Patterns.
function header_match(header, patterns)
	if header == "content-length" or header == "host" or not patterns then
		return false
	end
	header = header:lower()
	for _, p in ipairs(patterns) do
		if header:match(p:lower()) then
			return true
		end
	end
	return false
end

-- Terminates the transaction and sends the provided response to the client.
-- hdr_fail filters header names that should be provided using Lua Patterns.
function send_response(txn, response, hdr_fail)
	local reply = txn:reply()
	if response then
		reply:set_status(response.status)
		for header, values in pairs(response.headers) do
			if header_match(header, hdr_fail) then
				local i = 0
				while values[i] do
					reply:add_header(header, values[i])
					i = i + 1
				end
			end
		end
		if response.body then
			reply:set_body(response.body)
		end
	else
		reply:set_status(500)
	end
	txn:done(reply)
end

-- auth_request makes the request to the external authentication service
-- and waits for the response. hdr_* params receive a table of
-- Lua Patterns used to identify the headers that should be
-- copied between the requests and responses. nil in these params
-- mean that the headers shouldn't be copied at all.
-- Special values and behavior:
-- * method == "*": call the auth service using the same method used by the client.
-- * hdr_fail == nil: make the Lua script to not terminate the request.
function auth_request(txn, be, path, method, hdr_req, hdr_succeed, hdr_fail)
	set_var(txn, "txn.auth_response_successful", false)

	-- Check whether the given backend exists.
	if core.backends[be] == nil then
		txn:Alert("Unknown auth-request backend '" .. be .. "'")
		set_var(txn, "txn.auth_response_code", 500)
		return
	end

	-- Check whether the given backend has servers that
	-- are not `DOWN`.
	local addr = nil
	for name, server in pairs(core.backends[be].servers) do
		local status = server:get_stats()['status']
		if status == "no check" or status:find("UP") == 1 then
			addr = server:get_addr()
			break
		end
	end
	if addr == nil then
		txn:Warning("No servers available for auth-request backend: '" .. be .. "'")
		set_var(txn, "txn.auth_response_code", 500)
		return
	end

	-- Transform table of request headers from haproxy's to
	-- core.httpclient's format.
	local headers = {
		["connection"] = { "close" },
	}
	for header, values in pairs(txn.http:req_get_headers()) do
		if header_match(header, hdr_req) then
			headers[header] = values
		end
	end

	-- Make request to backend.
	if method == "*" then
		method = txn.sf:method()
	end
	
	-- Handle IPv6 addresses in URL
	local url_addr = addr
	if addr:find(":") and not addr:find("%[") then
		local _, count = addr:gsub(":", ":")
		if count > 1 then
			local ip, port = addr:match("^(.*):(%d+)$")
			if ip and port then
				url_addr = "[" .. ip .. "]:" .. port
			else
				url_addr = "[" .. addr .. "]"
			end
		end
	end

	local httpclient = core.httpclient
	if not httpclient then
		txn:Alert("core.httpclient not available. This script requires HAProxy 2.5+.")
		set_var(txn, "txn.auth_response_code", 500)
		return
	end
	local client = httpclient()
	local params = {
		url = "http://" .. url_addr .. path,
		headers = headers,
		timeout = 1000, -- 1 second
	}
	
	local response
	local method_upper = method:upper()
	if method_upper == "GET" then
		response = client:get(params)
	elseif method_upper == "HEAD" then
		response = client:head(params)
	elseif method_upper == "POST" then
		params.body = txn.sf:req_body()
		response = client:post(params)
	elseif method_upper == "PUT" then
		params.body = txn.sf:req_body()
		response = client:put(params)
	elseif method_upper == "DELETE" then
		response = client:delete(params)
	else
		-- Fallback for other methods if supported by the client object
		local m = method_upper:lower()
		if client[m] then
			response = client[m](client, params)
		else
			txn:Alert("Unsupported auth-request method: " .. method_upper)
			set_var(txn, "txn.auth_response_code", 500)
			return
		end
	end

	-- `terminate_on_failure == true` means that the Lua script should send the response
	-- and terminate the transaction in the case of a failure. This will happen when
	-- hdr_fail isn't nil.
	local terminate_on_failure = hdr_fail ~= nil

	-- Check whether we received a valid HTTP response.
	if response == nil then
		txn:Warning("Failure in auth-request backend '" .. be .. "'")
		set_var(txn, "txn.auth_response_code", 500)
		if terminate_on_failure then
			send_response(txn)
		end
		return
	end

	set_var(txn, "txn.auth_response_code", response.status)
	local response_ok = 200 <= response.status and response.status < 300

	for header, values in pairs(response.headers) do
		local value_list = {}
		-- core.httpclient uses 0-indexed tables for header values.
		local i = 0
		while values[i] do
			table.insert(value_list, values[i])
			i = i + 1
		end
		
		local value = table.concat(value_list, ", ")
		set_var(txn, "req.auth_response_header." .. sanitize_header_for_variable(header), value)
		if response_ok and hdr_succeed and header_match(header, hdr_succeed) then
			txn.http:req_set_header(header, value)
		end
	end

	-- response_ok means 2xx: allow request.
	if response_ok then
		set_var(txn, "txn.auth_response_successful", true)
	-- Don't allow codes < 200 or >= 300.
	-- Forward the response to the client if required.
	elseif terminate_on_failure then
		send_response(txn, response, hdr_fail)
	-- Codes with Location: Passthrough location at redirect.
	elseif response.status == 301 or response.status == 302 or response.status == 303 or response.status == 307 or response.status == 308 then
		local location = response.headers["location"]
		if location then
			set_var(txn, "txn.auth_response_location", location[#location])
		end
	-- 401 / 403: Do nothing, everything else: log.
	elseif response.status ~= 401 and response.status ~= 403 then
		txn:Warning("Invalid status code in auth-request backend '" .. be .. "': " .. response.status)
	end
end
