local proto = Proto("xnl", "Motorola XNL")

local port = 8002

local opcodes = {
  [2] = "MASTER_STATUS_BRDCST",
  [3] = "DEV_MASTER_QUERY",
  [4] = "DEV_AUTH_KEY_REQUEST",
  [5] = "DEV_AUTH_KEY_REPLY",
  [6] = "DEV_CONN_REQUEST",
  [7] = "DEV_CONN_REPLY",
  [8] = "DEV_SYSMAP_REQUEST",
  [9] = "DEV_SYSMAP_BRDCST",
  [11] = "DATA_MSG",
  [12] = "DATA_MSG_ACK",
}

local f_len = ProtoField.uint16("xnl.len", "Total Length", base.DEC)
local f_opcode = ProtoField.uint16("xnl.opcode", "Opcode", base.DEC, opcodes)
local f_proto = ProtoField.uint8("xnl.proto", "Protocol", base.DEC)
local f_flags = ProtoField.uint8("xnl.flags", "Flags", base.HEX)
local f_dst = ProtoField.uint16("xnl.dst", "Destination", base.HEX)
local f_src = ProtoField.uint16("xnl.src", "Source", base.HEX)
local f_transaction = ProtoField.uint16("xnl.transaction", "Transaction ID", base.DEC)
local f_payload_len = ProtoField.uint16("xnl.payload_len", "Payload Length", base.DEC)
local f_payload = ProtoField.bytes("xnl.payload", "Payload")
local f_masterstatus_major = ProtoField.uint16("xnl.masterstatus.major", "Major Version", base.DEC)
local f_masterstatus_minor = ProtoField.uint16("xnl.masterstatus.minor", "Minor Version", base.DEC)
local f_masterstatus_type = ProtoField.uint8("xnl.masterstatus.type", "Device Type", base.DEC)
local f_masterstatus_number = ProtoField.uint8("xnl.masterstatus.number", "Device Number", base.DEC)
local f_masterstatus_data_traffic = ProtoField.bool("xnl.masterstatus.data_traffic", "Data Traffic Occured")
local f_authkey_addr = ProtoField.uint16("xnl.authkey.addr", "Temporary Address", base.HEX)
local f_authkey_key = ProtoField.bytes("xnl.authkey.key", "Authentication Key")
local f_conn_addr = ProtoField.uint16("xnl.conn.addr", "Address", base.HEX)
local f_conn_type = ProtoField.uint8("xnl.conn.type", "Device Type", base.DEC)
local f_conn_number = ProtoField.uint8("xnl.conn.number", "Device Number", base.DEC)
local f_conn_index = ProtoField.uint8("xnl.conn.index", "Authentication Index", base.DEC)
local f_conn_key = ProtoField.bytes("xnl.conn.key", "Authentication Key")
local f_conn_result = ProtoField.uint8("xnl.conn.index", "Result Code", base.DEC)
local f_conn_transaction = ProtoField.uint8("xnl.conn.transaction", "Transaction ID Base", base.DEC)
local f_sysmap_size = ProtoField.uint16("xnl.sysmap.size", "System Map Size", base.DEC)
local f_sysmap = ProtoField.bytes("xnl.sysmap", "System Map Entry")
local f_sysmap_type = ProtoField.uint8("xnl.sysmap.type", "Device Type", base.DEC)
local f_sysmap_number = ProtoField.uint8("xnl.sysmap.number", "Device Number", base.DEC)
local f_sysmap_addr = ProtoField.uint16("xnl.sysmap.addr", "Address", base.HEX)
local f_sysmap_index = ProtoField.uint8("xnl.sysmap.index", "Authentication Index", base.DEC)

local protos = DissectorTable.new("xnl.proto", "XNL Protocol", ftypes.UINT8)

proto.fields = {
  f_len,
  f_opcode,
  f_proto,
  f_flags,
  f_dst,
  f_src,
  f_transaction,
  f_payload_len,
  f_payload,
  f_masterstatus_major,
  f_masterstatus_minor,
  f_masterstatus_type,
  f_masterstatus_number,
  f_masterstatus_data_traffic,
  f_authkey_addr,
  f_authkey_key,
  f_conn_addr,
  f_conn_type,
  f_conn_number,
  f_conn_index,
  f_conn_key,
  f_conn_result,
  f_conn_transaction,
  f_sysmap_size,
  f_sysmap,
  f_sysmap_type,
  f_sysmap_number,
  f_sysmap_addr,
  f_sysmap_index,
}

function proto.init()
  DissectorTable.get("tcp.port"):add(port, proto)
end

function dissect_xnl_payload(buf, tree, opcode)
  if opcode == 2 then
    tree:add(f_masterstatus_minor, buf(0, 2))
    tree:add(f_masterstatus_major, buf(2, 2))
    tree:add(f_masterstatus_type, buf(4, 1))
    tree:add(f_masterstatus_number, buf(5, 1))
    tree:add(f_masterstatus_data_traffic, buf(6, 1))
  elseif opcode == 5 then
    tree:add(f_authkey_addr, buf(0, 2))
    tree:add(f_authkey_key, buf(2, 8))
  elseif opcode == 6 then
    tree:add(f_conn_addr, buf(0, 2))
    tree:add(f_conn_type, buf(2, 1))
    tree:add(f_conn_index, buf(3, 1))
    tree:add(f_conn_key, buf(4, 8))
  elseif opcode == 7 then
    tree:add(f_conn_result, buf(0, 1))
    tree:add(f_conn_transaction, buf(1, 1))
    tree:add(f_conn_addr, buf(2, 2))
    tree:add(f_conn_type, buf(4, 1))
    tree:add(f_conn_number, buf(5, 1))
    tree:add(f_conn_key, buf(6, 8))
  elseif opcode == 9 then
    local sysmap_size = buf(0, 2):uint()
    tree:add(f_sysmap_size, buf(0, 2))
    for i = 0, sysmap_size - 1 do
      local infobuf = buf(2 + i * 5, 5)
      local info = tree:add(f_sysmap, infobuf)
      info:add(f_sysmap_type, infobuf(0, 1))
      info:add(f_sysmap_number, infobuf(1, 1))
      info:add(f_sysmap_addr, infobuf(2, 2))
      info:add(f_sysmap_index, infobuf(4, 1))
    end
  end
end

function proto.dissector(buf, pkt, root)
  local len = buf(0, 2):uint() + 2
  local proto_num = buf(4, 1):uint()
  local tree = root:add(proto, buf(0, proto_num ~= 0 and 14 or len))
  tree:add(f_len, buf(0, 2), len)
  local opcode = buf(2, 2):uint()
  tree:add(f_opcode, buf(2, 2))
  tree:add(f_proto, buf(4, 1))
  tree:add(f_flags, buf(5, 1))
  local dst = buf(6, 2):uint()
  tree:add(f_dst, buf(6, 2))
  local src = buf(8, 2):uint()
  tree:add(f_src, buf(8, 2))
  local transaction = buf(10, 2):uint()
  tree:add(f_transaction, buf(10, 2))
  local payload_len = buf(12, 2):uint()
  tree:add(f_payload_len, buf(12, 2))

  pkt.cols.protocol:set("XNL")
  desc = string.format("%04x → %04x Proto=%d Op=%s Transaction=%d Len=%d", src, dst, proto_num, opcodes[opcode] or opcode, transaction, payload_len)
  tree:append_text(string.format(", Src: %04x, Dst: %04x, Proto: %d, Op: %d, Transaction: %d, Len: %d", src, dst, proto_num, opcode, transaction, payload_len))
  pkt.cols.info:set(desc)

  if proto_num == 0 and len > 14 then
    local payload_tree = tree:add(f_payload, buf(14, len - 14))
    dissect_xnl_payload(buf(14, len - 14), payload_tree, opcode)
  else
    protos:try(proto_num, buf(14, len - 14):tvb(), pkt, root)
  end
end
