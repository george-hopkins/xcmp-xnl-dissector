local proto = Proto("xcmp", "Motorola XCMP")

local opcodes_base = {
  [0x0009] = "DEVSYSMAP",
  [0x000d] = "SUPERBUNDLE",
  [0x000e] = "RSTATUS",
  [0x000f] = "VERINFO",
  [0x002e] = "SUPERBUNDLE",
  [0x010a] = "CLONE",
  [0x0400] = "DEVINITSTS",
  [0x0401] = "DISPTXT",
  -- [0x0405] = "0x0405",
  -- [0x0406] = "0x0406",
  [0x0407] = "SPKRCTRL",
  [0x0408] = "TXPWRLV",
  [0x0410] = "0x0410",
  -- [0x0411] = "0x0411",
  [0x040a] = "SHUTDWN",
  [0x040d] = "CHZNSEL",
  [0x040e] = "MICCTRL",
  [0x040f] = "SCAN",
  [0x0413] = "EMG",
  [0x0415] = "KEY",
  [0x041c] = "RRCTRL",
  [0x041d] = "DATA",
  [0x041e] = "CALLCTRL",
  [0x041f] = "NAVCTRL",
  [0x042e] = "ALARMCTRL",
  [0x042f] = "RPSCTRL",
  [0x0447] = "RPTRCTRL",
  -- [0x0457] = "0x0457",
}

local opcodes = {}
for base, name in pairs(opcodes_base) do
  opcodes[base] = name .. "_REQ"
  opcodes[base + 0x8000] = name .. "_RES"
  opcodes[base + 0xb000] = name .. "_BRDCST"
end

local address_types = {
  [0] = "Local",
  [1] = "MotoTRBO",
  [2] = "IPv4",
  [5] = "MDC",
  [7] = "Phonenumber",
  [11] = "QuickCall",
  [13] = "5-Tone",
  [14] = "De-/Access Code",
}

local calltypes = {
  [0] = "No Call",
  [1] = "Selective Call",
  [2] = "Call Alert",
  [4] = "Enhanced Private Call",
  [5] = "Private Phone Call",
  [6] = "Group Call",
  [8] = "Call Alert with Voice",
  [9] = "Telegram Call",
  [10] = "Group Phone Call",
}

local results = {
  [0] = "Success",
  [2] = "Incorrect Mode",
  [3] = "Unsupported Opcode",
  [4] = "Invalid Parameter",
  [5] = "Reply Too Big",
  [6] = "Security Locked",
  [7] = "Unavailable Function",
}

local devinitsts_inits = {
  [0] = "STATUS",
  [1] = "COMPLETE",
  [2] = "UPDATE",
}

local f_opcode = ProtoField.uint16("xcmp.opcode", "Opcode", base.HEX, opcodes)
local f_address_type = ProtoField.uint8("xcmp.address.type", "Type", base.DEC, address_types)
local f_address_mototrbo = ProtoField.bytes("xcmp.address.mototrbo", "MotoTRBO ID")
local f_rstatus_result = ProtoField.uint8("xcmp.rstatus.result", "Result", base.DEC, results)
local f_rstatus_condition = ProtoField.uint8("xcmp.rstatus.condition", "Condition", base.DEC)
local f_rstatus_status = ProtoField.bytes("xcmp.rstatus.status", "Status")
local f_devinitsts_major = ProtoField.uint8("xcmp.devinists.major", "Major Version", base.DEC)
local f_devinitsts_minor = ProtoField.uint8("xcmp.devinists.minor", "Minor Version", base.DEC)
local f_devinitsts_product = ProtoField.uint8("xcmp.devinists.product", "Product ID", base.DEC)
local f_devinitsts_init = ProtoField.uint8("xcmp.devinists.init", "Initialization", base.DEC, devinitsts_inits)
local f_rrctrl_feature = ProtoField.uint8("xcmp.rrctrl.feature", "Feature", base.DEC)
local f_rrctrl_operation = ProtoField.uint8("xcmp.rrctrl.operation", "Operation", base.DEC)
local f_rrctrl_status = ProtoField.uint8("xcmp.rrctrl.status", "Status", base.DEC)
local f_rrctrl_address = ProtoField.bytes("xcmp.rrctrl.address", "Address")
local f_chznsel_function = ProtoField.uint8("xcmp.chznsel.function", "Function", base.DEC)
local f_chznsel_zone = ProtoField.uint16("xcmp.chznsel.zone", "Zone", base.DEC)
local f_chznsel_position = ProtoField.uint16("xcmp.chznsel.position", "Position", base.DEC)
local f_scan_function = ProtoField.uint8("xcmp.scan.function", "Function", base.DEC)
local f_callctrl_function = ProtoField.uint8("xcmp.callctrl.function", "Function", base.DEC)
local f_callctrl_calltype = ProtoField.uint8("xcmp.callctrl.calltype", "Call Type", base.DEC, calltypes)
local f_callctrl_address = ProtoField.bytes("xcmp.callctrl.address", "Address")
local f_callctrl_group = ProtoField.bytes("xcmp.callctrl.group", "Group ID")

proto.fields = {
  f_opcode,
  f_address_type,
  f_address_mototrbo,
  f_rstatus_result,
  f_rstatus_condition,
  f_rstatus_status,
  f_devinitsts_major,
  f_devinitsts_minor,
  f_devinitsts_product,
  f_devinitsts_init,
  f_rrctrl_feature,
  f_rrctrl_operation,
  f_rrctrl_status,
  f_rrctrl_address,
  f_chznsel_function,
  f_chznsel_zone,
  f_chznsel_position,
  f_scan_function,
  f_callctrl_function,
  f_callctrl_calltype,
  f_callctrl_address,
  f_callctrl_group,
}

-- dofile("xnl.luainc") -- uncomment to fix dependency order
local xnl_opcode = Field.new("xnl.opcode")
local xnl_transaction = Field.new("xnl.transaction")

local address_sizes = {
  [0] = 0,
  [1] = 3,
  [2] = 4,
  [5] = 2,
  [11] = 4,
}

function dissect_address(root, field, buf)
  local type = buf(0, 1):uint()
  local size = address_sizes[type]
  local tree = root:add(field, buf(0, 1 + size))
  tree:add(f_address_type, buf(0, 1))
  if type == 1 then
    tree:add(f_address_mototrbo, buf(1, size))
  end
  return buf(1 + size)
end

function proto.init()
  DissectorTable.get("xnl.proto"):add(1, proto)
end

function proto.dissector(buf, pkt, root)
  if xnl_opcode().value == 12 and buf:len() == 0 then
    return
  end

  local tree = root:add(proto, buf(0, buf:len()))
  local opcode = buf(0, 2):uint()
  tree:add(f_opcode, buf(0, 2))

  local desc = (opcodes[opcode] or opcode) .. " Transaction=" .. xnl_transaction().value

  if opcode == 0x000e then
    tree:add(f_rstatus_condition, buf(2, 1))
    desc = desc .. " Condition=" .. buf(2, 1):uint()
  elseif opcode == 0x800e then
    local rstatus_result = buf(2, 1):uint()
    tree:add(f_rstatus_result, buf(2, 1))
    if rstatus_result == 0 then
      tree:add(f_rstatus_condition, buf(3, 1))
      tree:add(f_rstatus_status, buf(4, buf:len() - 4))
      desc = desc .. " Condition=" .. buf(3, 1):uint()
    end
  elseif opcode == 0xb400 then
    tree:add(f_devinitsts_major, buf(2, 1))
    tree:add(f_devinitsts_minor, buf(3, 1))
    tree:add(f_devinitsts_product, buf(5, 1))
    local devinists_init = buf(6, 1):uint()
    tree:add(f_devinitsts_init, buf(6, 1))
    desc = desc .. " Init=" .. (devinitsts_inits[devinists_init] or devinists_init)
  elseif opcode == 0x041c or opcode == 0xb41c then
    tree:add(f_rrctrl_feature, buf(2, 1))
    tree:add(opcode == 0x041c and f_rrctrl_operation or f_rrctrl_status, buf(3, 1))
    buf = dissect_address(tree, f_rrctrl_address, buf(4))
  elseif opcode == 0x040d then
    tree:add(f_chznsel_function, buf(2, 1))
    tree:add(f_chznsel_zone, buf(3, 2))
    tree:add(f_chznsel_position, buf(5, 2))
  elseif opcode == 0x040f then
    tree:add(f_scan_function, buf(2, 1))
  elseif opcode == 0x041e then
    tree:add(f_callctrl_function, buf(2, 1))
    tree:add(f_callctrl_calltype, buf(3, 1))
    buf = dissect_address(tree, f_callctrl_address, buf(4))
    if buf:len() > 0 then
      tree:add(f_callctrl_group, buf)
    end
  end

  pkt.cols.protocol:set("XCMP")
  pkt.cols.info:set(desc)
end
