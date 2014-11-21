--
-- piepie - bot framework for Mumble
--
-- Author: Tim Cooper <tim.cooper@layeh.com>
-- License: MIT (see LICENSE)
--
local bit=require'bit'
function piepan.Permissions.new(permissionsMask)
    assert(type(permissionsMask) == "number", "permissionsMask must be a number")

    local permissions = {}

    for permission,mask in pairs(piepan.internal.permissionsMap) do
        if bit.band(permissionsMask, mask) ~= 0 then
            permissions[permission] = true
        end
    end

    setmetatable(permissions, piepan.Permissions)
    return permissions
end
