/*
 * piepie - bot framework for Mumble
 *
 * Author: Tim Cooper <tim.cooper@layeh.com>
 * License: MIT (see LICENSE)
 *
 * This file contains handlers for the messages that are received from the
 * server.
 */

 void handler_user_stats(lua_State *lua, Packet *packet)
{
    MumbleProto__UserStats *stats = 
        mumble_proto__user_stats__unpack(NULL, packet->length, packet->buffer);
    if (stats == NULL) {
        return;
    }

    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onUserStats");
    if (!lua_isfunction(lua, -1)) {
        mumble_proto__user_stats__free_unpacked(stats, NULL);
        lua_settop(lua, 0);
        return;
    }
    lua_newtable(lua);

    if (stats->has_session) {
        lua_pushinteger(lua, stats->session);
        lua_setfield(lua, -2, "session");
    }

    if (stats->has_stats_only) {
        lua_pushboolean(lua, stats->stats_only);
        lua_setfield(lua, -2, "stats_only");
    }

    lua_newtable(lua);
    int i;
    for ( i=0; i < stats->n_certificates; i++) {
        lua_pushinteger(lua, i);
        lua_pushlstring(lua, (char *)stats->certificates[i].data, stats->certificates[i].len);
        lua_settable(lua, -3);
    }
    lua_setfield(lua, -2, "certificates");

    lua_newtable(lua);
        if (stats->from_client->has_good) {
            lua_pushinteger(lua, stats->from_client->good);
            lua_setfield(lua, -2, "good");
        }
        if (stats->from_client->has_late) {
            lua_pushinteger(lua, stats->from_client->late);
            lua_setfield(lua, -2, "late");
        }
        if (stats->from_client->has_lost) {
            lua_pushinteger(lua, stats->from_client->lost);
            lua_setfield(lua, -2, "lost");
        }
        if (stats->from_client->has_resync) {
            lua_pushinteger(lua, stats->from_client->resync);
            lua_setfield(lua, -2, "resync");
        }
    lua_setfield(lua, -2, "from_client");

    lua_newtable(lua);
        if (stats->from_server->has_good) {
            lua_pushinteger(lua, stats->from_server->good);
            lua_setfield(lua, -2, "good");
        }
        if (stats->from_server->has_late) {
            lua_pushinteger(lua, stats->from_server->late);
            lua_setfield(lua, -2, "late");
        }
        if (stats->from_server->has_lost) {
            lua_pushinteger(lua, stats->from_server->lost);
            lua_setfield(lua, -2, "lost");
        }
        if (stats->from_server->has_resync) {
            lua_pushinteger(lua, stats->from_server->resync);
            lua_setfield(lua, -2, "resync");
        }
    lua_setfield(lua, -2, "from_server");

    if (stats->has_udp_packets) {
        lua_pushinteger(lua, stats->udp_packets);
        lua_setfield(lua, -2, "udp_packets");
    }

    if (stats->has_tcp_packets) {
        lua_pushinteger(lua, stats->tcp_packets);
        lua_setfield(lua, -2, "tcp_packets");
    }

    if (stats->has_udp_ping_avg) {
        lua_pushinteger(lua, stats->udp_ping_avg);
        lua_setfield(lua, -2, "udp_ping_avg");
    }

    if (stats->has_udp_ping_var) {
        lua_pushinteger(lua, stats->udp_ping_var);
        lua_setfield(lua, -2, "udp_ping_var");
    }

    if (stats->has_tcp_ping_avg) {
        lua_pushinteger(lua, stats->tcp_ping_avg);
        lua_setfield(lua, -2, "tcp_ping_avg");
    }

    if (stats->has_tcp_ping_var) {
        lua_pushinteger(lua, stats->tcp_ping_var);
        lua_setfield(lua, -2, "tcp_ping_var");
    }

    lua_newtable(lua);
        if (stats->version->has_version) {
            lua_pushinteger(lua, stats->version->version);
            lua_setfield(lua, -2, "version");
        }
        lua_pushstring(lua, stats->version->release);
        lua_setfield(lua, -2, "release");
        lua_pushstring(lua, stats->version->os);
        lua_setfield(lua, -2, "os");
        lua_pushstring(lua, stats->version->os_version);
        lua_setfield(lua, -2, "os_version");
    lua_setfield(lua, -2, "version");

    lua_newtable(lua);
    int j;
    for ( i=0; j < stats->n_celt_versions; j++) {
        lua_pushinteger(lua, j);
        lua_pushinteger(lua, stats->celt_versions[j]);
        lua_settable(lua, -3);
    }
    lua_setfield(lua, -2, "celt_versions");

    if (stats->has_address) {
        lua_pushlstring(lua, (char *)stats->address.data, stats->address.len);
        lua_setfield(lua, -2, "address");
    }

    if (stats->has_bandwidth) {
        lua_pushinteger(lua, stats->bandwidth);
        lua_setfield(lua, -2, "bandwidth");
    }

    if (stats->has_onlinesecs) {
        lua_pushinteger(lua, stats->onlinesecs);
        lua_setfield(lua, -2, "onlinesecs");
    }

    if (stats->has_idlesecs) {
        lua_pushinteger(lua, stats->idlesecs);
        lua_setfield(lua, -2, "idlesecs");
    }

    if (stats->has_strong_certificate) {
        lua_pushboolean(lua, stats->strong_certificate);
        lua_setfield(lua, -2, "strong_certificate");
    }

    if (stats->has_opus) {
        lua_pushboolean(lua, stats->opus);
        lua_setfield(lua, -2, "opus");
    }

    lua_call(lua, 1, 0);
    lua_settop(lua, 0);

    mumble_proto__user_stats__free_unpacked(stats, NULL);
}

void
handler_server_sync(lua_State *lua, Packet *packet)
{
    MumbleProto__ServerSync *sync =
        mumble_proto__server_sync__unpack(NULL, packet->length, packet->buffer);
    if (sync == NULL) {
        return;
    }
    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onServerSync");
    if (!lua_isfunction(lua, -1)) {
        mumble_proto__server_sync__free_unpacked(sync, NULL);
        lua_settop(lua, 0);
        return;
    }
    lua_newtable(lua);
    if (sync->has_session) {
        lua_pushinteger(lua, sync->session);
        lua_setfield(lua, -2, "session");
    }
    if (sync->welcome_text != NULL) {
        lua_pushstring(lua, sync->welcome_text);
        lua_setfield(lua, -2, "welcomeText");
    }
    if (sync->has_max_bandwidth) {
        lua_pushinteger(lua, sync->max_bandwidth);
        lua_setfield(lua, -2, "maxBandwidth");
    }
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__server_sync__free_unpacked(sync, NULL);
}

void
handler_channel_remove(lua_State *lua, Packet *packet)
{
    MumbleProto__ChannelRemove *channel =
        mumble_proto__channel_remove__unpack(NULL, packet->length, packet->buffer);
    if (channel == NULL) {
        return;
    }
    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onChannelRemove");
    if (!lua_isfunction(lua, -1)) {
        lua_settop(lua, 0);
        mumble_proto__channel_remove__free_unpacked(channel, NULL);
        return;
    }
    lua_newtable(lua);
    lua_pushinteger(lua, channel->channel_id);
    lua_setfield(lua, -2, "channelId");
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__channel_remove__free_unpacked(channel, NULL);
}

void
handler_channel_state(lua_State *lua, Packet *packet)
{
    MumbleProto__ChannelState *channel =
        mumble_proto__channel_state__unpack(NULL, packet->length, packet->buffer);
    if (channel == NULL) {
        return;
    }
    if (!channel->has_channel_id) {
        mumble_proto__channel_state__free_unpacked(channel, NULL);
        return;
    }
    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onChannelState");
    if (!lua_isfunction(lua, -1)) {
        lua_settop(lua, 0);
        mumble_proto__channel_state__free_unpacked(channel, NULL);
        return;
    }
    lua_newtable(lua);
    lua_pushinteger(lua, channel->channel_id);
    lua_setfield(lua, -2, "channelId");
    if (channel->has_parent) {
        lua_pushinteger(lua, channel->parent);
        lua_setfield(lua, -2, "parentId");
    }
    if (channel->name != NULL) {
        lua_pushstring(lua, channel->name);
        lua_setfield(lua, -2, "name");
    }
    if (channel->description != NULL) {
        lua_pushstring(lua, channel->description);
        lua_setfield(lua, -2, "description");
    }
    if (channel->has_temporary) {
        lua_pushboolean(lua, channel->temporary);
        lua_setfield(lua, -2, "temporary");
    }
    if (channel->has_description_hash) {
        lua_pushlstring(lua, (char *)channel->description_hash.data,
            channel->description_hash.len);
        lua_setfield(lua, -2, "descriptionHash");
    }
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__channel_state__free_unpacked(channel, NULL);
}

void
handler_server_config(lua_State *lua, Packet *packet)
{
    MumbleProto__ServerConfig *config =
       mumble_proto__server_config__unpack(NULL, packet->length, packet->buffer);
    if (config == NULL) {
        return;
    }
    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onServerConfig");
    if (!lua_isfunction(lua, -1)) {
        lua_settop(lua, 0);
        mumble_proto__server_config__free_unpacked(config, NULL);
        return;
    }
    lua_newtable(lua);
    if (config->has_allow_html) {
        lua_pushboolean(lua, config->allow_html);
        lua_setfield(lua, -2, "allowHtml");
    }
    if (config->has_message_length) {
        lua_pushinteger(lua, config->message_length);
        lua_setfield(lua, -2, "maxMessageLength");
    }
    if (config->has_image_message_length) {
        lua_pushinteger(lua, config->image_message_length);
        lua_setfield(lua, -2, "maxImageMessageLength");
    }
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__server_config__free_unpacked(config, NULL);
}

void
handler_text_message(lua_State *lua, Packet *packet)
{
    MumbleProto__TextMessage *msg =
        mumble_proto__text_message__unpack(NULL, packet->length, packet->buffer);
    if (msg == NULL) {
        return;
    }
    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onMessage");
    if (!lua_isfunction(lua, -1)) {
        lua_settop(lua, 0);
        mumble_proto__text_message__free_unpacked(msg, NULL);
        return;
    }
    lua_newtable(lua);
    if (msg->has_actor) {
        lua_pushinteger(lua, msg->actor);
        lua_setfield(lua, -2, "actor");
    }
    if (msg->message != NULL) {
        lua_pushstring(lua, msg->message);
        lua_setfield(lua, -2, "message");
    }
    if (msg->n_session > 0) {
        int i;
        lua_newtable(lua);
        for (i = 0; i < msg->n_session; i++) {
            lua_pushinteger(lua, i);
            lua_pushinteger(lua, msg->session[i]);
            lua_settable(lua, -3);
        }
        lua_setfield(lua, -2, "users");
    }
    if (msg->n_channel_id > 0) {
        int i;
        lua_newtable(lua);
        for (i = 0; i < msg->n_channel_id; i++) {
            lua_pushinteger(lua, i);
            lua_pushinteger(lua, msg->channel_id[i]);
            lua_settable(lua, -3);
        }
        lua_setfield(lua, -2, "channels");
    }
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__text_message__free_unpacked(msg, NULL);
}

void
handler_user_state(lua_State *lua, Packet *packet)
{
    MumbleProto__UserState *user =
        mumble_proto__user_state__unpack(NULL, packet->length, packet->buffer);
    if (user == NULL) {
        return;
    }
    if (!user->has_session) {
        mumble_proto__user_state__free_unpacked(user, NULL);
        return;
    }

    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onUserChange");
    if (!lua_isfunction(lua, -1)) {
        lua_settop(lua, 0);
        mumble_proto__user_state__free_unpacked(user, NULL);
        return;
    }
    lua_newtable(lua);
    lua_pushinteger(lua, user->session);
    lua_setfield(lua, -2, "session");
    if (user->has_actor) {
        lua_pushinteger(lua, user->actor);
        lua_setfield(lua, -2, "actor");
    }
    if (user->name != NULL) {
        lua_pushstring(lua, user->name);
        lua_setfield(lua, -2, "name");
    }
    if (user->has_channel_id) {
        lua_pushinteger(lua, user->channel_id);
        lua_setfield(lua, -2, "channelId");
    }
    if (user->has_user_id) {
        lua_pushinteger(lua, user->user_id);
        lua_setfield(lua, -2, "userId");
    }
    if (user->has_mute) {
        lua_pushboolean(lua, user->mute);
        lua_setfield(lua, -2, "isServerMuted");
    }
    if (user->has_deaf) {
        lua_pushboolean(lua, user->deaf);
        lua_setfield(lua, -2, "isServerDeafened");
    }
    if (user->has_self_mute) {
        lua_pushboolean(lua, user->self_mute);
        lua_setfield(lua, -2, "isSelfMuted");
    }
    if (user->has_self_deaf) {
        lua_pushboolean(lua, user->self_deaf);
        lua_setfield(lua, -2, "isSelfDeafened");
    }
    if (user->has_suppress) {
        lua_pushboolean(lua, user->suppress);
        lua_setfield(lua, -2, "isSuppressed");
    }
    if (user->comment != NULL) {
        lua_pushstring(lua, user->comment);
        lua_setfield(lua, -2, "comment");
    }
    if (user->has_recording) {
        lua_pushboolean(lua, user->recording);
        lua_setfield(lua, -2, "isRecording");
    }
    if (user->has_priority_speaker) {
        lua_pushboolean(lua, user->priority_speaker);
        lua_setfield(lua, -2, "isPrioritySpeaker");
    }
    if (user->has_texture) {
        lua_pushlstring(lua, (char *)user->texture.data, user->texture.len);
        lua_setfield(lua, -2, "texture");
    }
    if (user->hash != NULL) {
        lua_pushstring(lua, user->hash);
        lua_setfield(lua, -2, "hash");
    }
    if (user->has_comment_hash) {
        lua_pushlstring(lua, (char *)user->comment_hash.data, user->comment_hash.len);
        lua_setfield(lua, -2, "commentHash");
    }
    if (user->has_texture_hash) {
        lua_pushlstring(lua, (char *)user->texture_hash.data, user->texture_hash.len);
        lua_setfield(lua, -2, "textureHash");
    }
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__user_state__free_unpacked(user, NULL);
}

void
handler_user_remove(lua_State *lua, Packet *packet)
{
    MumbleProto__UserRemove *user =
       mumble_proto__user_remove__unpack(NULL, packet->length, packet->buffer);
    if (user == NULL) {
        return;
    }
    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onUserRemove");
    if (!lua_isfunction(lua, -1)) {
        lua_settop(lua, 0);
        mumble_proto__user_remove__free_unpacked(user, NULL);
        return;
    }
    lua_newtable(lua);
    lua_pushinteger(lua, user->session);
    lua_setfield(lua, -2, "session");
    if (user->has_actor) {
        lua_pushinteger(lua, user->actor);
        lua_setfield(lua, -2, "actor");
    }
    if (user->reason != NULL) {
        lua_pushstring(lua, user->reason);
        lua_setfield(lua, -2, "reason");
    }
    if (user->has_ban) {
        lua_pushboolean(lua, user->ban);
        lua_setfield(lua, -2, "ban");
    }
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__user_remove__free_unpacked(user, NULL);
}

void
handler_permissiondenied(lua_State *lua, Packet *packet)
{
    MumbleProto__PermissionDenied *proto =
        mumble_proto__permission_denied__unpack(NULL, packet->length, packet->buffer);
    if (proto == NULL) {
        return;
    }
    lua_getglobal(lua, "piepan");
    lua_getfield(lua, -1, "internal");
    lua_getfield(lua, -1, "events");
    lua_getfield(lua, -1, "onPermissionDenied");
    if (!lua_isfunction(lua, -1)) {
        lua_settop(lua, 0);
        mumble_proto__permission_denied__free_unpacked(proto, NULL);
        return;
    }
    lua_newtable(lua);
    if (proto->has_type) {
        lua_pushinteger(lua, proto->type);
        lua_setfield(lua, -2, "type");
    }
    if (proto->has_permission) {
        lua_pushinteger(lua, proto->permission);
        lua_setfield(lua, -2, "permission");
    }
    if (proto->has_channel_id) {
        lua_pushinteger(lua, proto->channel_id);
        lua_setfield(lua, -2, "channelId");
    }
    if (proto->has_session) {
        lua_pushinteger(lua, proto->session);
        lua_setfield(lua, -2, "session");
    }
    if (proto->reason != NULL) {
        lua_pushstring(lua, proto->reason);
        lua_setfield(lua, -2, "reason");
    }
    if (proto->name != NULL) {
        lua_pushstring(lua, proto->name);
        lua_setfield(lua, -2, "name");
    }
    lua_call(lua, 1, 0);
    lua_settop(lua, 0);
    mumble_proto__permission_denied__free_unpacked(proto, NULL);
}
