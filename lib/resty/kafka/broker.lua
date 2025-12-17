-- Copyright (C) Dejiang Zhu(doujiang24)


local response = require "resty.kafka.response"
local request = require "resty.kafka.request"

local to_int32 = response.to_int32
local setmetatable = setmetatable
local tcp = ngx.socket.tcp
local pid = ngx.worker.pid
local tostring = tostring

local sasl = require "resty.kafka.sasl"

local _M = {}
local mt = { __index = _M }


local function _sock_send_recieve(sock, request)
    local bytes, err = sock:send(request:package())
    if not bytes then
        return nil, err, true
    end

    local len, err = sock:receive(4)
    if not len then
        if err == "timeout" then
            sock:close()
            return nil, err
        end
        return nil, err, true
    end

    local data, err = sock:receive(to_int32(len))
    if not data then
        if err == "timeout" then
            sock:close()
            return nil, err
        end
        return nil, err, true
    end

    return response:new(data, request.api_version), nil, true
end


local function _sasl_handshake(sock, brk)
    local cli_id = "worker" .. pid()
    local req = request:new(request.SaslHandshakeRequest, 0, cli_id,
                            request.API_VERSION_V1)

    req:string(brk.auth.mechanism)

    local resp, err = _sock_send_recieve(sock, req, brk.config)
    if not resp  then
        return nil, err
    end

    local err_code = resp:int16()
    if err_code ~= 0 then
        local error_msg = resp:string()

        return nil, error_msg
    end

    return true
end


local function _sasl_auth(sock, brk)
    local cli_id = "worker" .. pid()
    local req = request:new(request.SaslAuthenticateRequest, 0, cli_id,
                            request.API_VERSION_V1)

    local ok, msg = sasl.encode(brk.auth.mechanism, nil, brk.auth.user,
                            brk.auth.password, sock)
    if not ok then
        return nil, msg
    end
    req:bytes(msg)

    local resp, err = _sock_send_recieve(sock, req, brk.config)
    if not resp  then
        return nil, err
    end

    local err_code = resp:int16()
    local error_msg = resp:string()
    local auth_bytes = resp:bytes()

    if err_code ~= 0 then
        return nil, error_msg
    end

    return true
end


local function sasl_auth(sock, broker)
    local ok, err = _sasl_handshake(sock, broker)
    if  not ok then
        return nil, err
    end

    local ok, err = _sasl_auth(sock, broker)
    if not ok then
        return nil, err
    end

    return true
end


function _M.new(self, host, port, socket_config, sasl_config)
    return setmetatable({
        host = host,
        port = port,
        config = socket_config,
        auth = sasl_config,
    }, mt)
end


function _M.send_receive(self, request)
    local sock, err = tcp()
    if not sock then
        return nil, err, true
    end

    sock:settimeout(self.config.socket_timeout)

    local ok, err = sock:connect(self.host, self.port)
    if not ok then
        return nil, err, true
    end

    local times, err = sock:getreusedtimes()
    if not times then
        return nil, "failed to get reused time: " .. tostring(err), true
    end

    if self.config.ssl and times == 0 then
        -- first connectted connnection
        -- Read PEM file contents (ngx ssl API expects PEM text, not file paths)
        local function read_pem(path)
            if not path then
                return nil
            end
            local f, ferr = io.open(path, "rb")
            if not f then
                return nil, ferr
            end
            local content = f:read("*a")
            f:close()
            return content
        end

        local client_cert, err_cert = read_pem(self.config.ssl_cert_path)
        if self.config.ssl_cert_path and not client_cert then
            return nil, "failed to read client certificate: " .. tostring(err_cert), true
        end

        local client_key, err_key = read_pem(self.config.ssl_key_path)
        if self.config.ssl_key_path and not client_key then
            return nil, "failed to read client key: " .. tostring(err_key), true
        end

        local cafile, err_ca = read_pem(self.config.ssl_ca_path)
        if self.config.ssl_ca_path and not cafile then
            return nil, "failed to read CA file: " .. tostring(err_ca), true
        end

        -- Only use options table if we have a CA file to pass for verification.
        -- For client certs alone, use boolean handshake to avoid verification side effects.
        if cafile then
            -- Use options table only with CA file for verification
            local ssl_opts = {
                client_cert = client_cert,
                client_key = client_key,
                client_key_password = self.config.ssl_key_password,
                cafile = cafile,
                verify = self.config.ssl_verify == true,
            }

            local ok, err = sock:sslhandshake(false, self.host, ssl_opts)
            if not ok then
                ngx.log(ngx.ERR, "sslhandshake with options failed for ", self.host, ":", tostring(self.port), ": ", tostring(err))
                return nil, "failed to do SSL handshake with "
                            ..  self.host .. ":" .. tostring(self.port) .. ": "
                            .. err, true
            end
        else
            -- No CA file: use boolean verify flag (cleaner for client-cert-only scenarios)
            local ok, err = sock:sslhandshake(false, self.host, self.config.ssl_verify)
            if not ok then
                return nil, "failed to do SSL handshake with "
                            ..  self.host .. ":" .. tostring(self.port) .. ": "
                            .. err, true
            end
        end
    end

    if self.auth and times == 0 then -- SASL AUTH
        local ok, err = sasl_auth(sock, self)
        if  not ok then
            return nil, "failed to do " .. self.auth.mechanism .." auth with "
                        ..  self.host .. ":" .. tostring(self.port) .. ": "
                        .. err, true

        end
    end

    local data, err, retryable = _sock_send_recieve(sock, request)

    sock:setkeepalive(self.config.keepalive_timeout, self.config.keepalive_size)

    return data, err, retryable
end


return _M
