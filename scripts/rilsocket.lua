-- This is Wireshark/tshark packet dissector for RILd messages. Place it into
-- your local plugin directory (e.g. $HOME/.wireshark/plugins/)

local rilproxy = Proto("rild", "RILd socket");

MessageID = {
    [0xC715] = "SETUP",
    [0xC717] = "TEARDOWN"
}

rilproxy.fields.length  = ProtoField.uint32('rilproxy.length', 'Length', base.DEC)
rilproxy.fields.id      = ProtoField.uint32('rilproxy.id', 'ID', base.HEX, MessageID)
rilproxy.fields.content = ProtoField.bytes('rilproxy.content', 'Content', base.HEX)

function message_type(id)
    if MessageID[id] ~= nil
    then
        return MessageID[id]
    end

    return "UNKNOWN_MESSAGE_" .. id
end

function rilproxy.init()
    cache = ByteArray.new()
    bytesMissing = 0
end

function rilproxy.dissector(buffer, info, tree)

    -- Follow-up to a message where length header indicates
    -- more bytes than available in the message.
    if bytesMissing > 0
    then

        if buffer:len() > bytesMissing
        then
            print("Follow-up message longer (" .. buffer:len() .. ") than missing bytes (" .. bytesMissing .. "), ignoring")
            bytesMissing = 0
            cache = ByteArray.new()
            return
        end

        cache:append(buffer(0):bytes())
        bytesMissing = bytesMissing - buffer:len()

        -- Still fragments missing, wait for next packet
        if bytesMissing > 0
        then
            return
        end

        buffer = ByteArray.tvb(cache, "Packet")
        cache = nil
    end

    local buffer_len = buffer:len()

    -- Message must be at least 4 bytes
    if buffer_len < 4 then
        print("Dropping short buffer of len " .. buffer_len)
        return
    end

    local header_len = buffer:range(0,4):uint()

    if header_len < 4 then
        print("Dropping short header len of " .. header_len)
        return
    end

    if header_len > 1492
    then
        print("Skipping long buffer of length " .. header_len)
        bytesMissing = 0
        cache = ByteArray.new()
        return
    end

    if buffer_len <= (header_len - 4)
    then
        bytesMissing = header_len - buffer_len + 4
        cache:append(buffer(0):bytes())
        buffer = nil
        return
    end

    cache = ByteArray.new()
    bytesMissing = 0

    info.cols.protocol = ('RILProxy')

    mt = message_type(buffer:range(4,4):le_uint())
    info.cols.info = mt

    if buffer_len >  header_len + 4
    then
        info.cols.info = "Messages"
        tree = tree:add(rilproxy, buffer(buffer_len):tvb(), ": Messages")
    end

    local t = tree:add(rilproxy, buffer(header_len):tvb(), mt)
    t:add(rilproxy.fields.length, buffer(0,4))
    t:add_le(rilproxy.fields.id, buffer(4,4))

    if header_len - 4 > 0
    then
        t:add(rilproxy.fields.content, buffer:range(8, header_len - 4))
    end

    if buffer_len >  header_len + 4
    then
        info.cols.info = "RILd messages"
    end

end

local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(18912, rilproxy.dissector)
