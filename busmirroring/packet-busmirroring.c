#include "config.h"
#include <epan/packet.h>

#define BUSMIRRORING_PORT 30511

enum network_type
{
    NETWORK_TYPE_UNKNOWN = 0x00,
    NETWORK_TYPE_CAN = 0x01,
    NETWORK_TYPE_LIN = 0x02,
    NETWORK_TYPE_FLEXRAY = 0x03,
    NETWORK_TYPE_ETHERNET = 0x04
};

static int proto_busmirroring = -1;
static int hf_protocol_version = -1;
static int hf_sequence_number = -1;
static int hf_header_timestamp = -1;
static int hf_seconds = -1;
static int hf_nanoseconds = -1;
static int hf_data_length = -1;
static int hf_timestamp = -1;
static int hf_network_state_available = -1;
static int hf_frame_id_available = -1;
static int hf_payload_available = -1;
static int hf_network_type = -1;
static int hf_network_id = -1;
static int hf_network_state = -1;
static int hf_frame_id = -1;
static int hf_can_id_type = -1;
static int hf_can_frame_type = -1;
static int hf_can_id = -1;
static int hf_lin_pid = -1;
static int hf_payload_length = -1;
static int hf_payload = -1;
static int ett_busmirroring = -1;
static int ett_header_timestamp = -1;
static int ett_data_item = -1;
static int ett_frame_id = -1;

static int
dissect_busmirroring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    int buffer_length = tvb_captured_length(tvb);
    if (0 == buffer_length)
    {
        return 0;
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BUSMIRRORING");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Busmirroring Seq=%u Len=%u", tvb_get_guint8(tvb, 1), tvb_get_guint16(tvb, 12, ENC_BIG_ENDIAN));

    proto_item *ti = proto_tree_add_item(tree, proto_busmirroring, tvb, 0, -1, ENC_NA);
    proto_tree *busmirroring_tree = proto_item_add_subtree(ti, ett_busmirroring);
    proto_tree_add_item(busmirroring_tree, hf_protocol_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(busmirroring_tree, hf_sequence_number, tvb, 1, 1, ENC_BIG_ENDIAN);
    nstime_t header_timestamp;
    header_timestamp.secs = tvb_get_guint48(tvb, 2, ENC_BIG_ENDIAN);
    header_timestamp.nsecs = tvb_get_guint32(tvb, 8, ENC_BIG_ENDIAN);
    proto_item *ht_item = proto_tree_add_time(busmirroring_tree, hf_header_timestamp, tvb, 2, 10, &header_timestamp);
    proto_tree *ht_tree = proto_item_add_subtree(ht_item, ett_header_timestamp);
    proto_tree_add_item(ht_tree, hf_seconds, tvb, 2, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(ht_tree, hf_nanoseconds, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(busmirroring_tree, hf_data_length, tvb, 12, 2, ENC_BIG_ENDIAN);

    int index = 0;
    int offset = 14;
    while (offset < buffer_length)
    {
        int data_length = 4;
        uint8_t flags = tvb_get_guint8(tvb, offset + 2);
        uint8_t type = flags & 0x1F;
        uint8_t has_network_state = flags & 0x80;
        if (has_network_state)
        {
            data_length += 1;
        }
        uint8_t has_frame_id = flags & 0x40;
        if (has_frame_id)
        {
            uint8_t frame_id_length = 0;
            switch (type)
            {
            case NETWORK_TYPE_CAN:
                frame_id_length = 4;
                break;
            case NETWORK_TYPE_LIN:
                frame_id_length = 1;
                break;
            case NETWORK_TYPE_FLEXRAY:
                frame_id_length = 3;
                break;
            default:
                break;
            }
            data_length += frame_id_length;
        }
        uint8_t has_payload = flags & 0x20;
        int length = 0;
        if (has_payload)
        {
            length = tvb_get_guint8(tvb, offset + data_length);
            data_length += 1;
            data_length += length;
        }

        proto_item *data_item = proto_tree_add_item(busmirroring_tree, proto_busmirroring, tvb, offset, data_length, ENC_NA);
        proto_item_set_text(data_item, "Data Item #%d", index);
        proto_tree *data_tree = proto_item_add_subtree(data_item, ett_data_item);
        proto_tree_add_item(data_tree, hf_timestamp, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_network_state_available, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_frame_id_available, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_payload_available, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_network_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_network_id, tvb, offset + 3, 1, ENC_BIG_ENDIAN);

        int local_offset = 4;
        if (has_network_state)
        {
            proto_tree_add_item(data_item, hf_network_state, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
            local_offset += 1;
        }
        if (has_frame_id)
        {
            switch (type)
            {
            case NETWORK_TYPE_CAN:
            {
                proto_item *frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                proto_tree_add_item(frame_id_tree, hf_can_id_type, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_can_frame_type, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_can_id, tvb, offset + local_offset, 4, ENC_BIG_ENDIAN);
                local_offset += 4;
            }
            break;
            case NETWORK_TYPE_LIN:
            {
                proto_item *frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                proto_tree_add_item(frame_id_tree, hf_lin_pid, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
                local_offset += 1;
            }
            break;
            case NETWORK_TYPE_FLEXRAY:
            {
                proto_tree_add_item(data_item, hf_frame_id, tvb, offset + local_offset, 3, ENC_BIG_ENDIAN);
                local_offset += 3;
            }
            break;
            default:
                break;
            }
        }
        if (has_payload)
        {
            proto_tree_add_item(data_item, hf_payload_length, tvb, offset + local_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(data_item, hf_payload, tvb, offset + local_offset + 1, length, ENC_BIG_ENDIAN);
        }

        ++index;
        offset += data_length;
    } // while

    return buffer_length;
}

void proto_register_busmirroring(void)
{
    static const true_false_string availability_text = {"Available", "Not Available"};
    static const true_false_string can_id_type_names = {"Extended", "Standard"};
    static const true_false_string can_frame_type_names = {"CAN FD", "CAN 2.0"};
    static const value_string network_type_names[] = {
        {1, "CAN"},
        {2, "LIN"},
        {3, "FlexRay"},
        {4, "Ethernet"}};
    static hf_register_info hf[] = {
        {&hf_protocol_version,
         {"Protocol Version", "busmirroring.protocol_version",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_sequence_number,
         {"Sequence Number", "busmirroring.sequence_number",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_header_timestamp,
         {"Timestamp", "busmirroring.header_timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_seconds,
         {"Seconds", "busmirroring.seconds",
          FT_UINT48, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nanoseconds,
         {"Nanoseconds", "busmirroring.nanoseconds",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_data_length,
         {"Data Length", "busmirroring.data_length",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_timestamp,
         {"Timestamp(10 µs)", "busmirroring.timestamp",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_network_state_available,
         {"Network State", "busmirroring.network_state_available",
          FT_BOOLEAN, 8,
          TFS(&availability_text), 0x80,
          NULL, HFILL}},
        {&hf_frame_id_available,
         {"Frame ID", "busmirroring.frame_id_available",
          FT_BOOLEAN, 8,
          TFS(&availability_text), 0x40,
          NULL, HFILL}},
        {&hf_payload_available,
         {"Payload", "busmirroring.payload_available",
          FT_BOOLEAN, 8,
          TFS(&availability_text), 0x20,
          NULL, HFILL}},
        {&hf_network_type,
         {"Network Type", "busmirroring.network_type",
          FT_UINT8, BASE_DEC,
          VALS(network_type_names), 0x1F,
          NULL, HFILL}},
        {&hf_network_id,
         {"Network ID", "busmirroring.network_id",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_network_state,
         {"Network State", "busmirroring.network_state",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_frame_id,
         {"Frame ID", "busmirroring.frame_id",
          FT_UINT32, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_can_id_type,
         {"CAN ID Type", "busmirroring.can_id_type",
          FT_BOOLEAN, 32,
          TFS(&can_id_type_names), 0x80000000,
          NULL, HFILL}},
        {&hf_can_frame_type,
         {"CAN Frame Type", "busmirroring.can_frame_type",
          FT_BOOLEAN, 32,
          TFS(&can_frame_type_names), 0x40000000,
          NULL, HFILL}},
        {&hf_can_id,
         {"CAN ID", "busmirroring.can_id",
          FT_UINT32, BASE_HEX_DEC,
          NULL, 0x1FFFFFFF,
          NULL, HFILL}},
        {&hf_lin_pid,
         {"LIN PID", "busmirroring.lin_pid",
          FT_UINT8, BASE_HEX_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_payload_length,
         {"Payload Length", "busmirroring.payload_length",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_payload,
         {"Payload", "busmirroring.payload",
          FT_BYTES, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}}};

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_busmirroring,
        &ett_header_timestamp,
        &ett_data_item,
        &ett_frame_id};

    proto_busmirroring = proto_register_protocol(
        "Bus Mirroring Protocol", /* name        */
        "BusMirroring",           /* short_name  */
        "busmirroring"            /* filter_name */
    );

    proto_register_field_array(proto_busmirroring, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_busmirroring(void)
{
    static dissector_handle_t busmirroring_handle;

    busmirroring_handle = create_dissector_handle(dissect_busmirroring, proto_busmirroring);
    dissector_add_uint("udp.port", BUSMIRRORING_PORT, busmirroring_handle);
}
