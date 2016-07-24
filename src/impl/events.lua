--
-- piepie - bot framework for Mumble
--
-- Author: Tim Cooper <tim.cooper@layeh.com>
-- License: MIT (see LICENSE)
--

function piepan.internal.events.onUserStats(obj)
    local event = {
        user = piepan.internal.users[obj.session],
        stats = setmetatable(obj, piepan.Stats),
    }
    setmetatable(event, piepan.UserStats)
    piepan.internal.triggerEvent("onUserStats", event)
end

function piepan.internal.events.onServerConfig(obj)
    if obj.allowHtml ~= nil then
        piepan.server.allowHtml = obj.allowHtml
    end
    if obj.maxMessageLength ~= nil then
        piepan.server.maxMessageLength = obj.maxMessageLength
    end
    if obj.maxImageMessageLength ~= nil then
        piepan.server.maxImageMessageLength = obj.maxImageMessageLength
    end

    piepan.internal.triggerEvent("onConnect")
end

function piepan.internal.events.onServerSync(obj)
    piepan.me = piepan.internal.users[obj.session]
    if obj.welcomeText ~= nil then
        piepan.server.welcomeText = obj.welcomeText
    end
    if obj.maxBandwidth ~= nil then
        piepan.server.maxBandwidth = obj.maxBandwidth
    end
    piepan.server.synced = true
end

function piepan.internal.events.onMessage(obj)
    local message = {
        text = obj.message
    }
    setmetatable(message, piepan.Message)
    if obj.actor ~= nil then
        message.user = piepan.internal.users[obj.actor]
    end
    if obj.channels ~= nil then
        -- TODO:  add __len
        message.channels = {}
        for _,v in pairs(obj.channels) do
            message.channels[v] = piepan.channels[v]
        end
    end
    if obj.users ~= nil then
        -- TODO:  add __len
        message.users = {}
        for _,v in pairs(obj.users) do
            local user = piepan.internal.users[v]
            if user ~= nil then
                message.users[user.name] = user
            end
        end
    end

    piepan.internal.triggerEvent("onMessage", message)
end

function piepan.internal.events.onUserChange(obj)
    local user, actor
    local event = {}
    setmetatable(event, piepan.UserChange)
    if piepan.internal.users[obj.session] == nil then
        if obj.name == nil then
            return
        end
        user = {
            session = obj.session,
            channel = piepan.channels[0]
        }
        piepan.internal.users[obj.session] = user
        piepan.users[obj.name] = user
        setmetatable(user, piepan.User)
        event.isConnected = true
    else
        user = piepan.internal.users[obj.session]
    end
    event.user = user

    local resolving = {}

    if obj.actor ~= nil then
        event.actor = piepan.internal.users[obj.actor]
    end
    if obj.userId ~= nil then
        user.userId = obj.userId
    end
    if obj.name ~= nil then
        user.name = obj.name
    end
    if obj.channelId ~= nil then
        event.channelFrom = user.channel
        user.channel = piepan.channels[obj.channelId]
        event.isChangedChannel = true
    end
    if obj.comment ~= nil then
        user.comment = obj.comment
        user.commentHash = nil
        event.isChangedComment = true

        local tbl = piepan.internal.resolving.users[user.session]
        if tbl then
            for k,v in pairs(tbl) do
                v.count = v.count - 1
                if v.count <= 0 then
                    table.insert(resolving, v.routine)
                    piepan.internal.resolving.users[user.session][k] = nil
                end
            end
        end
        -- TODO:  add flag which states if the blob was requested?
    end
    if obj.isServerMuted ~= nil then
        user.isServerMuted = obj.isServerMuted
    end
    if obj.isServerDeafened ~= nil then
        user.isServerDeafened = obj.isServerDeafened
    end
    if obj.isSelfMuted ~= nil then
        user.isSelfMuted = obj.isSelfMuted
    end
    if obj.isRecording ~= nil then
        user.isRecording = obj.isRecording
    end
    if obj.isSelfDeafened ~= nil then
        user.isSelfDeafened = obj.isSelfDeafened
    end
    if obj.isPrioritySpeaker ~= nil then
        user.isPrioritySpeaker = obj.isPrioritySpeaker
    end
    if obj.hash ~= nil then
        user.hash = obj.hash
    end
    if obj.texture ~= nil then
        user.texture = obj.texture
        user.textureHash = nil

        local tbl = piepan.internal.resolving.users[user.session]
        if tbl then
            for k,v in pairs(tbl) do
                v.count = v.count - 1
                if v.count <= 0 then
                    table.insert(resolving, v.routine)
                    piepan.internal.resolving.users[user.session][k] = nil
                end
            end
        end
        -- TODO:  add flag which states if the blob was requested?
    end
    if obj.textureHash ~= nil then
        user.textureHash = obj.textureHash
        user.texture = nil
    end
    if obj.commentHash ~= nil then
        user.commentHash = obj.commentHash
        user.comment = nil
    end

    for k,v in pairs(resolving) do
        resolving[k] = nil
        piepan.internal.runCallback(v)
    end

    if piepan.server.synced then
        piepan.internal.triggerEvent("onUserChange", event)
    end
end

function piepan.internal.events.onUserRemove(obj)
    local event = {}
    setmetatable(event, piepan.UserChange)
    if piepan.internal.users[obj.session] ~= nil then
        -- TODO:  remove reference from Channel -> User?
        local name = piepan.internal.users[obj.session].name
        if name ~= nil and piepan.users[name] ~= nil then
            piepan.users[name] = nil
        end
        event.user = piepan.internal.users[obj.session]
        piepan.internal.users[obj.session] = nil
    end

    if piepan.server.synced and event.user ~= nil then
        event.isDisconnected = true
        piepan.internal.triggerEvent("onUserChange", event)
    end
end

function piepan.internal.events.onChannelRemove(obj)
    local channel = piepan.channels[obj.channelId]
    local event = {}
    if channel == nil then
        return
    end
    setmetatable(event, piepan.ChannelChange)
    event.channel = channel

    if channel.parent ~= nil then
        channel.parent.children[channel.id] = nil
        if channel.name ~= nil then
            channel.parent.children[channel.name] = nil
        end
    end
    for k in pairs(channel.children) do
        if k ~= nil then
            k.parent = nil
        end
    end
    piepan.channels[channel.id] = nil

    if piepan.server.synced then
        event.isRemoved = true
        piepan.internal.triggerEvent("onChannelChange", event)
    end
end

function piepan.internal.events.onChannelState(obj)
    local channel
    local event = {}
    setmetatable(event, piepan.ChannelChange)
    if piepan.channels[obj.channelId] == nil then
        channel = {
            id = obj.channelId,
            children = {},
            temporary = false,
            users = {}
        }
        piepan.channels[obj.channelId] = channel
        setmetatable(channel, piepan.Channel)
        event.isCreated = true
    else
        channel = piepan.channels[obj.channelId]
    end
    event.channel = channel

    if obj.temporary ~= nil then
        channel.isTemporary = obj.temporary
    end
    if obj.description ~= nil then
        channel.description = obj.description
        channel.descriptionHash = nil
        event.isChangedDescription = true

        local tbl = piepan.internal.resolving.channels[channel.id]
        if tbl then
            for k,v in pairs(tbl) do
                piepan.internal.resolving.channels[channel.id][k] = nil
                piepan.internal.runCallback(v)
            end
        end
        -- TODO:  add flag which states if the blob was requested?
    end
    if obj.parentId ~= nil then
        -- Channel got a new parent
        if channel.parent ~= nil and channel.parent.id ~= obj.parentId then
            channel.parent.children[channel.id] = nil
            if channel.name ~= nil then
                channel.parent.children[channel.name] = nil
            end
        end

        channel.parent = piepan.channels[obj.parentId]

        if channel.parent ~= nil then
            channel.parent.children[channel.id] = channel
            if channel.name ~= nil then
                channel.parent.children[channel.name] = channel
            end
        end
        event.isMoved = true
    end
    if obj.name ~= nil then
        if channel.parent ~= nil then
            if channel.name ~= nil then
                channel.parent.children[channel.name] = channel
            end
            channel.parent.children[obj.name] = channel
        end
        channel.name = obj.name
        event.isChangedName = true
    end
    if obj.descriptionHash ~= nil then
        channel.descriptionHash = obj.descriptionHash
        channel.description = nil
    end

    if piepan.server.synced then
        piepan.internal.triggerEvent("onChannelChange", event)
    end
end

function piepan.internal.events.onDisconnect(obj)
    piepan.internal.triggerEvent("onDisconnect", event)
end

function piepan.internal.events.onPermissionDenied(obj)
    local event = {}
    print ("Permission denied")
    for k,v in pairs(obj) do
        print (">> " .. tostring(k) .. " => " .. tostring(v))
    end
    if obj.type == nil then
        return
    end
    setmetatable(event, piepan.PermissionDenied)
    if obj.type == 1 then
        event.isPermission = true
    elseif obj.type == 3 then
        event.isChannelName = true
    elseif obj.type == 4 then
        event.isTextTooLong = true
    elseif obj.type == 6 then
        event.isTemporaryChannel = true
    elseif obj.type == 7 then
        event.isMissingCertificate = true
    elseif obj.type == 8 then
        event.isUserName = true
    elseif obj.type == 9 then
        event.isChannelFull = true
    else
        event.isOther = true
    end

    if obj.session ~= nil then
        event.user = piepan.internal.users[obj.session]
    end
    if obj.channelId ~= nil then
        event.channel = piepan.channels[obj.channelId]
    end
    if obj.permission ~= nil then
        event.permissions = piepan.Permissions.new(obj.permission)
    end
    if obj.reason ~= nil then
        event.reason = obj.reason
    end
    if obj.name ~= nil then
        event.name = obj.name
    end

    piepan.internal.triggerEvent("onPermissionDenied", event)
end
