--
-- piepie - bot framework for Mumble
--
-- Author: Tim Cooper <tim.cooper@layeh.com>
-- License: MIT (see LICENSE)
--

function piepan.internal.events.onLoadScript(argument, ptr)
    local index
    local entry

    if type(argument) == "string" then
        index = #piepan.scripts + 1
        entry = {
            filename = argument,
            ptr = ptr,
            environment = {
                _G = _G,
                __index = _G,
                __newindex = _G,
                client = setmetatable({}, piepan.internal.meta)
            }
        }
    elseif type(argument) == "number" then
        index = argument
        entry = piepan.scripts[index]
    else
        return false, "invalid argument"
    end

    local script, message = loadfile(entry.filename, "bt")
    if script == nil then
        return false, message
    end

    setfenv(script, setmetatable(entry.environment, entry.environment))

    local status, message = pcall(script)
    if status == false then
        return false, message
    end

    piepan.scripts[index] = entry

    return true, index, ptr
end

--
-- Callback execution
--
function piepan.internal.triggerEvent(name, ...)
    for _,script in pairs(piepan.scripts) do
        local func = rawget(script.environment.client, name)
        if type(func) == "function" then
            piepan.internal.runCallback(func, ...)
        end
    end
end

function piepan.internal.runCallback(func, ...)
    assert(type(func) == "thread" or type(func) == "function",
        "func should be a coroutine or a function")

    local routine
    if type(func) == "thread" then
        routine = func
    else
        routine = coroutine.create(func)
    end
    local status, message = coroutine.resume(routine, ...)
    if not status then
        print ("Error: " .. message)
    end
end

--
-- Argument parsing
--
function piepan.internal.events.onArgument(key, value)
    assert(type(key) ~= nil, "key cannot be nil")

    value = value or ""
    if piepan.args[key] == nil then
        piepan.args[key] = {value}
    else
        table.insert(piepan.args[key], value)
    end
end