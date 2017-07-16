local proto = Proto("xnl", "Motorola XNL")

local port = 8002

local f_len = ProtoField.uint16("xnl.len", "Total Length", base.DEC)
local f_opcode = ProtoField.uint16("xnl.opcode", "Opcode", base.DEC)
local f_proto = ProtoField.uint8("xnl.proto", "Protocol", base.DEC)
local f_flags = ProtoField.uint8("xnl.flags", "Flags", base.HEX)
local f_dst = ProtoField.uint16("xnl.dst", "Destination", base.HEX)
local f_src = ProtoField.uint16("xnl.src", "Source", base.HEX)
local f_transaction = ProtoField.uint16("xnl.transaction", "Transaction ID", base.DEC)
local f_payload_len = ProtoField.uint16("xnl.payload_len", "Payload Length", base.DEC)

local protos = DissectorTable.new("xnl.proto", "XNL Protocol", ftypes.UINT8)

proto.fields = { f_len, f_opcode, f_proto, f_flags, f_dst, f_src, f_transaction, f_payload_len }

opcodes = {
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

function proto.init()
  DissectorTable.get("tcp.port"):add(port, proto)
end

function proto.dissector(buf, pkt, root)
  local len = buf(0, 2):uint() + 2
  local proto_num = buf(4, 1):uint()
  local tree = root:add(proto, buf(0, proto_num ~= 0 and 14 or len))
  tree:add(f_len, buf(0, 2), len)
  local opcode = buf(2, 2):uint()
  local opcode_tree = tree:add(f_opcode, buf(2, 2), opcode)
  if opcodes[opcode] then
    opcode_tree:append_text(" (".. opcodes[opcode] .. ")")
  end
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

  protos:try(proto_num, buf(14, len - 14):tvb(), pkt, root)
end
