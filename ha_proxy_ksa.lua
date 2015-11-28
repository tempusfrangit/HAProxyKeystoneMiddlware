-- -*- coding: utf-8 -*-
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
-- implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

--
-- An HAProxy Lua Script that will perform the heavy lifting of OpenStack
-- Keystone Authentication and pass through sane HTTP Headers to the backend.
-- This is designed to enable an authless-setup behind the loadbalancers,
-- meaning that the services are configured in a way to implicitly trust
-- requests from the other micro-services as the user's request was explicitly
-- validated (valid auth token) at the edge (in this case HAProxy).
--
-- All requests in the architecture that will use this script will pass through
-- HA Proxy, meaning that all API endpoints will be under a single pane of
-- glass (http://<openstack API Endpoint>/<service>
--
-- This script was developed for Lua5.3 and has been testing with HAProxy 1.6
-- on Ubuntu.
--

--
-- TODO:
--  * Cache/handle the authentication for the validation of tokens more
--    elegantly
--
--  * Ensure JSON processing is handled in a sane manner for the Service
--    catalog.
--
--  * Ensure SSL Client Certs are handled so that when/if a service hits the
--    load balancer, the headers are not stripped out when coming from a
--    trusted source. This will rely on something akin to
--    "acl validcert ssl_c_s_dn(cn) -m str VALID\ CERT\ CN" and passing throug
--    to an alternate http-request implementation that does not process the
--    'X-Auth-Token' header.
--

JSON = assert(loadfile("json.lua"))()

local http_req = require('socket.http')
local io = require("io")
local ltn12 = require("ltn12")

local keystone_auth_url = "http://localhost:35357/v3/auth/tokens"


local keystone_headers_arr = {
    "X-Auth-Token",
    "X-Identity-Status",
    "X-Service-Catalog",
    "X-Domain-ID",
    "X-Domain-Name",
    "X-Project-Id",
    "X-Project-Name",
    "X-Project-Domain-Id",
    "X-User-Id",
    "X-User-Name",
    "X-Roles",
    "X-Service-Catalog",
}

function strip_headers(txn)
    for _,header in pairs(keystone_headers_arr) do
        txn.http:req_del_header(header)
    end
end

function get_admin_token()
    -- TODO(morganfainberg): replace this with proper config-time values
    local username = "admin"
    local password = "ADMIN"
    local user_domain_name = "Default"
    local scope_project_name = "demo"
    local scope_domain_name = "Default"

    local headers = {}

    headers["content-type"] = "application/json"

    -- NOTE(morganfainberg): This is horrifying. We have to be able to do this
    -- better.
    local auth_request = {
        ["auth"] = {
            identity = {
                methods = {
                    "password"
                },
                password = {
                    user = {
                        domain = {
                            name = user_domain_name
                        },
                        name = username,
                        password = password
                    }
                }
            },
            scope = {
                project = {
                    domain = {
                        name = scope_domain_name
                    },
                    name = scope_project_name
                }
            }
        }
    }

    local encoded_body = JSON:encode(auth_request)
    local resp_body = {}
    local admin_token

    headers['content-length'] = encoded_body:len()

    r, resp_code, resp_headers, resp_status = http_req.request {
        method = "POST",
        url = keystone_auth_url,
        headers = headers,
        source = ltn12.source.string(encoded_body),
        sink = ltn12.sink.table(resp_body)
    }
    if resp_code == 201 and resp_headers['x-subject-token'] ~= nil then
        -- NOTE(morganfainberg): Response Headers are going to be case
        -- sensitive. Make sure we are handling this in a sane way.
        admin_token = resp_headers['x-subject-token']
        -- Success! We have an Admin Token
        local log_msg = "Admin Token Accquired: "
        log_msg = log_msg .. admin_token
        core.Debug(log_msg)
    end
    return admin_token
end

function extract_and_apply_authenticated_headers(txn, auth_token, decoded_body)
    local token_data = decoded_body["token"]
    txn.http:req_add_header("X-Identity-Status", "Confirmed")
    txn.http:req_add_header("X-Auth-Token", auth_token)

    if token_data["project"] ~= nil then
        txn.http:req_add_header("X-Project-Id", token_data["project"]["id"])
        txn.http:req_add_header("X-Project-Name", token_data["project"]["name"])
    end

    txn.http:req_add_header("X-User-Id", token_data["user"]["id"])
    txn.http:req_add_header("X-User-Name", token_data["user"]["name"])

    local role_list = {}
    for _,role in pairs(token_data["roles"]) do
        table.insert(role_list, role["name"])
    end

    if role_list ~= nil then
        txn.http:req_add_header("X-Roles", table.concat(role_list, ","))
    else
        txn.http:req_add_header("X-Roles", "")
    end

    if token_data["catalog"] ~= nil then
        txn.http:req_add_header("X-Service-Catalog",
            JSON:encode(token_data["catalog"]))
    end
end

function validate_token(txn)
    local req_headers = txn.http:req_get_headers()
    local admin_token = get_admin_token()
    local resp_body = {}
    local auth_token
    local log_msg

    -- Remove the Keystone Headers before we move on
    strip_headers(txn)

    if req_headers["x-auth-token"] ~= nil then
        -- We need to validate the actual auth-token now.
        local validation_headers = {}
        auth_token = req_headers["x-auth-token"][0]
        validation_headers["X-Subject-Token"] = auth_token
        validation_headers["X-Auth-Token"] = admin_token
        validation_headers["content-type"] = "application/json"

        r, resp_code, resp_headers, resp_status = http_req.request {
            method = "GET",
            url = keystone_auth_url,
            headers = validation_headers,
            sink = ltn12.sink.table(resp_body)
        }
        if resp_code == 200 then
            core.Debug("Successfully Validated Token: " .. auth_token)
            -- Reconstruct the Body to a single value, as this can be broken
            -- up into multipe bits.
            resp_body = table.concat(resp_body)
            local decoded_body = JSON:decode(resp_body)
            extract_and_apply_authenticated_headers(txn, auth_token,
                decoded_body)
            return
        end
    end

    if auth_token == nil then
        auth_token = "<NONE>"
    end
    core.Debug("Invalid Token Received: " .. auth_token)
    txn.http:req_add_header("X-Identity-Status", "Invalid")

end

core.register_action("validate_token", { "http-req" }, validate_token)