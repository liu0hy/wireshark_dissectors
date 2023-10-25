require "bit32"

busmirroring_protocol = Proto("BusMirroring", "Bus Mirroring Protocol")

protocol_version = ProtoField.uint8("busmirroring.protocol_version", "Protocol Version", base.DEC)
sequence_number = ProtoField.uint8("busmirroring.sequence_number", "Sequence Number", base.DEC)
header_timestamp = ProtoField.absolute_time("busmirroring.header_timestamp", "Timestamp", base.UTC)
seconds = ProtoField.uint64("busmirroring.seconds", "Seconds", base.DEC)
nanoseconds = ProtoField.uint32("busmirroring.nanoseconds", "Nanoseconds", base.DEC)
data_length = ProtoField.uint16("busmirroring.data_length", "Data Length", base.DEC)
timestamp = ProtoField.uint16("busmirroring.timestamp", "Timestamp(10 µs)", base.DEC)
network_state_available = ProtoField.bool("busmirroring.network_state_available", "Network State", 8,
    {"Available", "Not Available"}, 0x80)
frame_id_available = ProtoField.bool("busmirroring.frame_id_available", "Frame ID", 8, {"Available", "Not Available"},
    0x40)
payload_available =
    ProtoField.bool("busmirroring.payload_available", "Payload", 8, {"Available", "Not Available"}, 0x20)
network_type = ProtoField.uint8("busmirroring.network_type", "Network Type", base.DEC,
    {"CAN", "LIN", "FlexRay", "Ethernet"}, 0x1F)
network_id = ProtoField.uint8("busmirroring.network_id", "Network ID", base.DEC)
network_state = ProtoField.uint8("busmirroring.network_state", "Network State", base.HEX)
frames_lost = ProtoField.bool("busmirroring.frames_lost", "Frames Lost", 8, nil, 0x80)
bus_online = ProtoField.bool("busmirroring.bus_online", "Bus Online", 8, nil, 0x40)
can_error_passive = ProtoField.bool("busmirroring.can_error_passive", "Error-Passive", 8, nil, 0x20)
can_bus_off = ProtoField.bool("busmirroring.can_bus_off", "Bus-Off", 8, nil, 0x10)
can_tx_error_count = ProtoField.uint8("busmirroring.can_tx_error_count", "Tx Error Count(divided by 8)", base.DEC, nil,
    0x0F)
lin_header_tx_error = ProtoField.bool("busmirroring.lin_header_tx_error", "Header Tx Error", 8, nil, 0x08)
lin_tx_error = ProtoField.bool("busmirroring.lin_tx_error", "Tx Error", 8, nil, 0x04)
lin_rx_error = ProtoField.bool("busmirroring.lin_rx_error", "Rx Error", 8, nil, 0x02)
lin_rx_no_response = ProtoField.bool("busmirroring.lin_rx_no_response", "Rx No Response", 8, nil, 0x01)
frame_id = ProtoField.uint32("busmirroring.frame_id", "Frame ID", base.HEX)
can_id_format = ProtoField.bool("busmirroring.can_id_format", "CAN ID Type", 32, {"Extended", "Standard"}, 0x80000000)
can_frame_type = ProtoField.bool("busmirroring.can_frame_type", "CAN Frame Type", 32, {"CAN FD", "CAN 2.0"}, 0x40000000)
can_id = ProtoField.uint32("busmirroring.can_id", "CAN ID", base.HEX_DEC, nil, 0x1FFFFFFF)
lin_pid = ProtoField.uint8("busmirroring.lin_pid", "LIN PID", base.HEX_DEC)
payload_length = ProtoField.uint8("busmirroring.payload_length", "Payload Length", base.DEC)
payload = ProtoField.bytes("busmirroring.payload", "Payload")

busmirroring_protocol.fields =
    {protocol_version, sequence_number, header_timestamp, seconds, nanoseconds, data_length, -- header
    timestamp, network_state_available, frame_id_available, payload_available, network_type, network_id, network_state,
     frames_lost, bus_online, can_error_passive, can_bus_off, can_tx_error_count, lin_header_tx_error, lin_tx_error,
     lin_rx_error, lin_rx_no_response, frame_id, can_id_format, can_frame_type, can_id, lin_pid, payload_length, payload -- data
    }

function busmirroring_protocol.dissector(buffer, pinfo, tree)
    local buffer_length = buffer:len()
    if buffer_length == 0 then
        return
    end

    pinfo.cols.protocol = busmirroring_protocol.name
    pinfo.cols.info = "BusMirroring Seq=" .. buffer(1, 1):uint() .. " Len=" .. buffer(12, 2):uint()

    local subtree = tree:add(busmirroring_protocol, buffer(), "Bus Mirroring Protocol")
    subtree:add(protocol_version, buffer(0, 1))
    subtree:add(sequence_number, buffer(1, 1))
    local header_timestamp_tree = subtree:add(header_timestamp, buffer(2, 10),
        NSTime(buffer(2, 6):uint64():tonumber(), buffer(8, 4):uint()))
    header_timestamp_tree:add(seconds, buffer(2, 6))
    header_timestamp_tree:add(nanoseconds, buffer(8, 4))
    subtree:add(data_length, buffer(12, 2))

    local index = 0
    local offset = 14
    while offset < buffer_length do
        local data_length = 4
        local flags = buffer:range(offset + 2, 1):uint()
        local type = bit32.band(flags, 0x1F)
        local has_network_state = bit32.btest(flags, 0x80)
        if has_network_state then
            data_length = data_length + 1
        end
        local has_frame_id = bit32.btest(flags, 0x40)
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
        local has_payload = bit32.btest(flags, 0x20)
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
            local ns_tree = data_tree:add(network_state, buffer(offset + local_offset, 1))
            ns_tree:add(frames_lost, buffer(offset + local_offset, 1))
            ns_tree:add(bus_online, buffer(offset + local_offset, 1))
            if type == 0x01 then -- CAN
                ns_tree:add(can_error_passive, buffer(offset + local_offset, 1))
                ns_tree:add(can_bus_off, buffer(offset + local_offset, 1))
                ns_tree:add(can_tx_error_count, buffer(offset + local_offset, 1))
            elseif type == 0x02 then -- LIN
                ns_tree:add(lin_header_tx_error, buffer(offset + local_offset, 1))
                ns_tree:add(lin_tx_error, buffer(offset + local_offset, 1))
                ns_tree:add(lin_rx_error, buffer(offset + local_offset, 1))
                ns_tree:add(lin_rx_no_response, buffer(offset + local_offset, 1))
            end
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
udp_port:add_for_decode_as(busmirroring_protocol)
