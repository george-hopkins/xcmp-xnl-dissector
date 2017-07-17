local proto = Proto("xcmp", "Motorola XCMP")

local opcodes_base = {
  [0x000d] = "SUPERBUNDLEAPPLY",
  [0x000e] = "RSTATUS",
  [0x000f] = "VERINFO",
  [0x002c] = "LANGPKINFO",
  [0x002e] = "SUPERBUNDLE",
  [0x0109] = "CLONEWR",
  [0x010a] = "CLONERD",
  [0x0400] = "DEVINITSTS",
  [0x0401] = "DISPTXT",
  [0x0402] = "INDUPDRQ",
  [0x0405] = "PUINPUT",
  [0x0406] = "VOLCTRL",
  [0x0407] = "SPKRCTRL",
  [0x0408] = "TXPWRLVL",
  [0x0409] = "TONECTRL",
  [0x040a] = "SHUTDWN",
  [0x040c] = "MON",
  [0x040d] = "CHZNSEL",
  [0x040e] = "MICCTRL",
  [0x040f] = "SCAN",
  [0x0410] = "BATLVL",
  [0x0411] = "BRIGHTNESS",
  [0x0412] = "BTNCONF",
  [0x0413] = "EMG",
  [0x0414] = "AUDRTCTRL",
  [0x0415] = "KEY",
  [0x041b] = "SIG",
  [0x041c] = "RRCTRL",
  [0x041d] = "DATA",
  [0x041e] = "CALLCTRL",
  [0x041f] = "NAVCTRL",
  [0x0420] = "MENUCTRL",
  [0x0421] = "DEVCTRL",
  [0x0428] = "DEVMGMT",
  [0x042e] = "ALARMCTRL",
  [0x042f] = "ROSCTRL",
  [0x0447] = "RPTRCTRL",
  [0x0458] = "FD",
  [0x04a1] = "SWA_AUDIO",
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

local devtypes = {
  [1] = "RF Transceiver",
  [10] = "IP Peripheral",
}

local devinitsts_attrs = {
  [0] = "Device Family",
  [2] = "Display",
  [3] = "Speaker",
  [4] = "RF Band",
  [5] = "GPIO",
  [7] = "Radio Type",
  [9] = "Keypad",
  [13] = "Channel Knob",
  [14] = "Virtual Personality",
  [17] = "Bluetooth",
  [19] = "Accelerometer",
  [20] = "GPS",
}

local f_opcode = ProtoField.uint16("xcmp.opcode", "Opcode", base.HEX, opcodes)
local f_address_type = ProtoField.uint8("xcmp.address.type", "Type", base.DEC, address_types)
local f_address_mototrbo = ProtoField.bytes("xcmp.address.mototrbo", "MotoTRBO ID")
local f_rstatus_result = ProtoField.uint8("xcmp.rstatus.result", "Result", base.DEC, results)
local f_rstatus_condition = ProtoField.uint8("xcmp.rstatus.condition", "Condition", base.DEC)
local f_rstatus_status = ProtoField.bytes("xcmp.rstatus.status", "Status")
local f_devinitsts_major = ProtoField.uint8("xcmp.devinitsts.major", "Major Version", base.DEC)
local f_devinitsts_minor = ProtoField.uint8("xcmp.devinitsts.minor", "Minor Version", base.DEC)
local f_devinitsts_patch = ProtoField.uint8("xcmp.devinitsts.patch", "Patch Version", base.DEC)
local f_devinitsts_product = ProtoField.uint8("xcmp.devinitsts.product", "Product ID", base.DEC)
local f_devinitsts_init = ProtoField.uint8("xcmp.devinitsts.init", "Initialization", base.DEC, devinitsts_inits)
local f_devinitsts_type = ProtoField.uint8("xcmp.devinitsts.type", "Type", base.DEC, devtypes)
local f_devinitsts_status = ProtoField.uint16("xcmp.devinitsts.status", "Status", base.DEC)
local f_devinitsts_attrlen = ProtoField.uint8("xcmp.devinitsts.status", "Attribute Length", base.DEC)
local f_devinitsts_attr = ProtoField.bytes("xcmp.devinitsts.attr", "Attribute")
local f_devinitsts_attr_key = ProtoField.uint8("xcmp.devinitsts.attr.key", "Key", base.HEX, devinitsts_attrs)
local f_devinitsts_attr_value = ProtoField.uint8("xcmp.devinitsts.attr.value", "Value", base.HEX)
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
  f_devinitsts_patch,
  f_devinitsts_product,
  f_devinitsts_init,
  f_devinitsts_type,
  f_devinitsts_status,
  f_devinitsts_attrlen,
  f_devinitsts_attr,
  f_devinitsts_attr_key,
  f_devinitsts_attr_value,
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

function dissect_address(root, field, buf)
  local type = buf(0, 1):uint()
  local size = buf(1, 1):uint()
  local tree = root:add(field, buf(0, 2 + size))
  tree:add(f_address_type, buf(0, 1))
  if type == 1 then
    tree:add(f_address_mototrbo, buf(2, size))
  end
  return buf(2 + size)
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
    tree:add(f_devinitsts_patch, buf(4, 1))
    tree:add(f_devinitsts_product, buf(5, 1))
    local devinitsts_init = buf(6, 1):uint()
    tree:add(f_devinitsts_init, buf(6, 1))
    desc = desc .. " Init=" .. (devinitsts_inits[devinitsts_init] or devinitsts_init)
    if devinitsts_init ~= 1 then
      tree:add(f_devinitsts_type, buf(7, 1))
      tree:add(f_devinitsts_status, buf(8, 2))
      local attrlen = buf(10, 1):uint()
      tree:add(f_devinitsts_attrlen, buf(10, 1))
      for i = 0, (attrlen - 1), 2 do
        local attr_tree = tree:add(f_devinitsts_attr, buf(11 + i, 2))
        local attr_key = buf(11 + i, 1):uint()
        attr_tree:add(f_devinitsts_attr_key, buf(11 + i, 1))
        local attr_value = buf(11 + i + 1, 1):uint()
        attr_tree:add(f_devinitsts_attr_value, buf(11 + i + 1, 1))
        if devinitsts_attrs[attr_key] then
          attr_tree:set_text(string.format("%s: 0x%02x", devinitsts_attrs[attr_key], attr_value))
        end
      end
    end
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
