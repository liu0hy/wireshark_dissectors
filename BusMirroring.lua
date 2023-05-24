require "bit32"

busmirroring_protocol = Proto("BusMirroring", "Bus Mirroring Protocol")

protocol_version = ProtoField.uint8("busmirroring.protocol_version", "Protocol Version", base.DEC)
sequence_number = ProtoField.uint8("busmirroring.sequence_number", "Sequence Number", base.DEC)
header_timestamp = ProtoField.bytes("busmirroring.header_timestamp", "Timestamp")
seconds = ProtoField.uint64("busmirroring.seconds", "Seconds", base.DEC)
nanoseconds = ProtoField.uint32("busmirroring.nanoseconds", "Nanoseconds", base.DEC)
data_length = ProtoField.uint16("busmirroring.data_length", "Data Length", base.DEC)
timestamp = ProtoField.uint16("busmirroring.timestamp", "Timestamp", base.DEC)
network_state_available = ProtoField.bool("busmirroring.network_state_available", "Network State", 8,
    {"Available", "Not Available"}, 0x80)
frame_id_available = ProtoField.bool("busmirroring.frame_id_available", "Frame ID", 8, {"Available", "Not Available"},
    0x40)
payload_available =
    ProtoField.bool("busmirroring.payload_available", "Payload", 8, {"Available", "Not Available"}, 0x20)
network_type = ProtoField.uint8("busmirroring.network_type", "Network Type", base.RANGE_STRING,
    {{1, 1, "CAN"}, {2, 2, "LIN"}, {3, 3, "FlexRay"}, {4, 4, "Ethernet"}}, 0x1F)
network_id = ProtoField.uint8("busmirroring.network_id", "Network ID", base.DEC)
network_state = ProtoField.uint8("busmirroring.network_state", "Network State", base.DEC)
frame_id = ProtoField.uint32("busmirroring.frame_id", "Frame ID", base.HEX)
can_id_format = ProtoField.bool("busmirroring.can_id_format", "CAN ID Format", 32, {"Ext.ID", "Std.ID"}, 0x80000000)
can_frame_type = ProtoField.bool("busmirroring.can_frame_type", "Type", 32, {"FD", "2.0"}, 0x40000000)
can_id = ProtoField.uint32("busmirroring.can_id", "CAN ID", base.HEX_DEC, nil, 0x1FFFFFFF)
lin_pid = ProtoField.uint8("busmirroring.lin_pid", "LIN PID", base.HEX_DEC)
payload_length = ProtoField.uint8("busmirroring.payload_length", "Payload Length", base.DEC)
payload = ProtoField.bytes("busmirroring.payload", "Payload")

busmirroring_protocol.fields =
    {protocol_version, sequence_number, header_timestamp, seconds, nanoseconds, data_length, -- header
    timestamp, network_state_available, frame_id_available, payload_available, network_type, network_id, network_state,
     frame_id, can_id_format, can_frame_type, can_id, lin_pid, payload_length, payload -- data
    }

function busmirroring_protocol.dissector(buffer, pinfo, tree)
    local buffer_length = buffer:len()
    if buffer_length == 0 then
        return
    end

    pinfo.cols.protocol = busmirroring_protocol.name

    local subtree = tree:add(busmirroring_protocol, buffer(), "Bus Mirroring Protocol")
    subtree:add(protocol_version, buffer(0, 1))
    subtree:add(sequence_number, buffer(1, 1))
    local header_timestamp_tree = subtree:add(header_timestamp, buffer(2, 10))
    header_timestamp_tree:add(seconds, buffer(2, 6))
    header_timestamp_tree:add(nanoseconds, buffer(8, 4))
    subtree:add(data_length, buffer(12, 2))

    local index = 0
    local offset = 14
    while offset < buffer_length do
        local data_length = 4
        local type = bit32.band(buffer:range(offset + 2, 1):uint(), 0x1F)
        local has_network_state = bit32.band(buffer:range(offset + 2, 1):uint(), 0x80) == 0x80
        if has_network_state then
            data_length = data_length + 1
        end
        local has_frame_id = bit32.band(buffer:range(offset + 2, 1):uint(), 0x40) == 0x40
        if has_frame_id then
            local frame_id_length = 0
            if type == 0x01 then -- CAN
                frame_id_length = 4
            elseif type == 0x02 then -- LIN
                frame_id_length = 1
            elseif type == 0x03 then -- FlexRay
                frame_id_length = 3
            end
            data_length = data_length + frame_id_length
        end
        local has_payload = bit32.band(buffer(offset + 2, 1):uint(), 0x20) == 0x20
        local length = 0
        if has_payload then
            length = buffer:range(offset + data_length, 1):uint()
            data_length = data_length + 1
            data_length = data_length + length
        end

        local data_tree = subtree:add(busmirroring_protocol, buffer(offset, data_length), "Data Item #" .. index)
        data_tree:add(timestamp, buffer(offset, 2))
        data_tree:add(network_state_available, buffer(offset + 2, 1))
        data_tree:add(frame_id_available, buffer(offset + 2, 1))
        data_tree:add(payload_available, buffer(offset + 2, 1))
        data_tree:add(network_type, buffer(offset + 2, 1))
        data_tree:add(network_id, buffer(offset + 3, 1))
        local local_offset = 4
        if has_network_state then
            data_tree:add(network_stat, buffer(offset + local_offset, 1))
            local_offset = local_offset + 1
        end
        if has_frame_id then
            if type == 0x01 then -- CAN
                local frame_id_tree = data_tree:add(frame_id, buffer(offset + local_offset, 4))
                frame_id_tree:add(can_id_format, buffer(offset + local_offset, 4))
                frame_id_tree:add(can_frame_type, buffer(offset + local_offset, 4))
                frame_id_tree:add(can_id, buffer(offset + local_offset, 4))
                local_offset = local_offset + 4
            elseif type == 0x02 then -- LIN
                local frame_id_tree = data_tree:add(frame_id, buffer(offset + local_offset, 1))
                frame_id_tree:add(lin_pid, buffer(offset + local_offset, 1))
                local_offset = local_offset + 1
            elseif type == 0x03 then -- FlexRay
                local frame_id_tree = data_tree:add(frame_id, buffer(offset + local_offset, 3))
                local_offset = local_offset + 3
            end
        end
        if has_payload then
            data_tree:add(payload_length, buffer(offset + local_offset, 1))
            data_tree:add(payload, buffer(offset + local_offset + 1, length))
        end
        index = index + 1
        offset = offset + data_length
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(30511, busmirroring_protocol)
