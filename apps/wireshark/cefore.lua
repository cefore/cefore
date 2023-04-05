
-- CCN protocol
ccn = Proto("ccn", "Content Centric Networking (CCN)")

-----------------------------------------------------
-----------------------------------------------------

-----------------------------------------------------
-- Transport Information Option Header Sub-TLVs
-----------------------------------------------------
local switch_TiHdrTLV = {}
--
-- TI_VARIANT
--
switch_TiHdrTLV[1] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "TI_VARIANT(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- TI_SEQ_NUM
--
switch_TiHdrTLV[2] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "TI_SEQ_NUM(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   root:append_text(string.format(" SEQ: %u", value))

   return treeInfo
end
--
-- TI_PROPOS_RATE
--
switch_TiHdrTLV[3] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "TI_PROPOS_RATE(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   root:append_text(string.format(" RATE: %u", value))

   return treeInfo
end
--
-- TI_TIMESTAMP
--
switch_TiHdrTLV[4] = function(block, root)
   local valueHi = block.tvb(block.offset + block.typeLen + block.lengthLen, 4):uint()
   local valueLow = block.tvb(block.offset + block.typeLen + block.lengthLen+4, 4):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "TI_TIMESTAMP(" .. block.type .. ") Length: " .. block.length .. " Value: " .. string.format("0x%08x%08x", valueHi, valueLow))

   return treeInfo
end
--
-- TI_FRAME_NUM
--
switch_TiHdrTLV[5] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("TI_FRAME_NUM(%u) Length: %u Value: %u", block.type, block.length, value))

   root:append_text(string.format(" FRAME: %u", value))

   return treeInfo
end
--
-- TI_LAYER
--
switch_TiHdrTLV[6] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("TI_LAYER(%u) Length: %u Value: %u", block.type, block.length, value))

   root:append_text(string.format(" LAYER: %u", value))

   return treeInfo
end
--
-- TI_ESI
--
switch_TiHdrTLV[7] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("TI_ESI(%u) Length: %u Value: 0x%x", block.type, block.length, value))

   root:append_text(string.format(" ESI: %u", value))

   return treeInfo
end
--
-- TI_STATUS
--
switch_TiHdrTLV[8] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()

   if ( value == 0x01 ) then
      strstatus = "ACK"
   elseif ( value == 0x02 ) then
      strstatus = "NACK"
   elseif ( value == 0x11 ) then
      strstatus = "SOURCE"
   elseif ( value == 0x22 ) then
      strstatus = "REPAIR"
   elseif ( value == 0x8100 ) then
      strstatus = "FIN"
   end

   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("TI_STATUS(%u) Length: %u ", block.type, block.length))

   treeInfo:append_text(string.format("Value: %s(0x%02x)", strstatus, value))
   root:append_text(string.format(" %s", strstatus))

   return treeInfo
end
--
-- TI_FSSI
--
switch_TiHdrTLV[9] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "TI_FSSI(" .. block.type .. ") Length: " .. block.length .. " Value: " .. string.format("0x%x", value))

   return treeInfo
end
--
-- TI_FEC_PARAM
--
switch_TiHdrTLV[10] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local k = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local n = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
--       "TI_FEC_PARAM(" .. block.type .. ") Length: " .. block.length .. " Value: " .. string.format("0x%x", value))
         "TI_FEC_PARAM(" .. block.type .. ") Length: " .. block.length .. " Value: " .. string.format("k=%d, n=%d", (value % 0x10000), (value / 0x10000)))

   return treeInfo
end
--
-- TI_RELIABILITY
--
switch_TiHdrTLV[11] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "TI_RELIABILITY(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- TI_EV
--
switch_TiHdrTLV[12] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "TI_EV(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end

-----------------------------------------------------
-- Hop by Hop Option Header TLVs
-----------------------------------------------------
local switch_OptHdrTLV = {}
--
-- OPT_INTLIFE
--
switch_OptHdrTLV[1] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_INTLIFE(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- OPT_CACHETIME
--
switch_OptHdrTLV[2] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_CACHETIME(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- OPT_MSGHASH
--
switch_OptHdrTLV[3] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_MSGHASH(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- OPT_TRACE_REQ
--
switch_OptHdrTLV[8] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_TRACE_REQ(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- OPT_TRACE_RPT
--
switch_OptHdrTLV[9] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_TRACE_RPT(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- OPT_PING_REQ
--
switch_OptHdrTLV[10] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_PING_REQ(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end

--
-- OPT_SYMBOLIC
--
-----------------------------------------------------
-- OPT_SYMBOLIC Internel TLVs
-----------------------------------------------------
local switch_OptSymTLV = {}
--
-- OPT_REGULAR
--
switch_OptSymTLV[0] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_REGULAR(" .. block.type .. ")     Length: " .. block.length)

   return treeInfo
end
--
-- OPT_LONGLIFE
--
switch_OptSymTLV[1] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_LONGLIFE(" .. block.type .. ")    Length: " .. block.length)

   return treeInfo
end
--
-- OPT_INNOVATIVE
--
switch_OptSymTLV[2] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_INNOVATIVE(" .. block.type .. ")  Length: " .. block.length .. " Value: 0x")
   local i, j

   for i = 0, block.length-1 do
       j = block.offset + block.typeLen + block.lengthLen + i;
       treeInfo:append_text(string.format("%02x", block.tvb(j, 1):uint()))
   end

   return treeInfo
end
--
-- OPT_PIGGYBACK
--
switch_OptSymTLV[3] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_PIGGYBACK(" .. block.type .. ")   Length: " .. block.length)

   return treeInfo
end
--
-- OPT_NUMBER
--
switch_OptSymTLV[4] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_NUMBER(" .. block.type .. ")      Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- OPT_SCODE
--
switch_OptSymTLV[5] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_SCODE(" .. block.type .. ") Length: " .. block.length .. " Value: " ..
         block.tvb(block.offset + block.typeLen + block.lengthLen, block.length))

   return treeInfo
end
--
-- OPT_NWPROC
--
switch_OptSymTLV[6] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_NWPROC(" .. block.type .. ") Length: " .. block.length .. " Value: " ..
         block.tvb(block.offset + block.typeLen + block.lengthLen, block.length))

   return treeInfo
end

switch_OptHdrTLV[0x1001] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_SYMBOLIC(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      subTLVs.root = switch_OptSymTLV[subTLVs.type](subTLVs, treeInfo)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- OPT_TRANSPORT
--
switch_OptHdrTLV[0x1002] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
                            string.format("OPT_TRANSPORT(0x%x) Length: %d", block.type, block.length))
   local offset   = block.offset + block.typeLen + block.lengthLen
   local tpValiant = getBlock(block.tvb, offset)
   local strValiant = ""

   if ( 0 < tpValiant.type ) then
       local TpInfo = treeInfo:add(block.tvb(tpValiant.offset, tpValiant.size), string.format("Valiant: TP_L4C2(0x%x)", tpValiant.type))
       local valueLeft = tpValiant.length
       strValiant = "L4C2 Transport"

       offset   = offset + tpValiant.typeLen + tpValiant.lengthLen;

       while valueLeft > 0 do
          local subTLVs = getBlock(block.tvb, offset)

          subTLVs.root = switch_TiHdrTLV[subTLVs.type](subTLVs, TpInfo)
          valueLeft = valueLeft - subTLVs.size
          offset    = offset    + subTLVs.size
       end
   end

   root:append_text(" " .. strValiant)
   treeInfo:append_text(string.format(" %s(0x%x)", strValiant, tpValiant.type))

   return treeInfo
end
--
-- OPT_EFI
--
switch_OptHdrTLV[0x1003] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_EFI(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   return treeInfo
end
--
-- OPT_IUR
--
switch_OptHdrTLV[0x1004] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_IUR(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   return treeInfo
end
--
-- OPT_SEQNUM
--
switch_OptHdrTLV[0x1005] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_SEQNUM(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end

function addOptHdrInfo(block, root) -- may be add additional context later

   block.root = switch_OptHdrTLV[block.type](block, root)

   return block.root
end

-----------------------------------------------------
-----------------------------------------------------

-- block
-- .tvb
-- .offset
-- .type
-- .typeLen
-- .length
-- .lengthLen
-- .size = .typeLen + .lengthLen + .length

function addCcnFixHdrInfo(msg, root) -- may be add additional context later
   local CcnVersion = msg.tvb(msg.offset+0, 1):uint()
   local HopLimit   = msg.tvb(msg.offset+4, 1):uint()
   local Flags      = msg.tvb(msg.offset+6, 1):uint()
   local msgtype    = "Unknown"

   msg.PacketLength  = msg.tvb(msg.offset+2, 2):uint()
   msg.HeaderLength  = msg.tvb(msg.offset+7, 1):uint()
   msg.PayloadLength = msg.PacketLength - msg.HeaderLength

   treeInfo = root:add(msg.tvb(msg.offset, 1), "Version: " .. string.format("0x%x", CcnVersion))
   if ( msg.type == 0 ) then
      msgtype = "Interest"
   elseif ( msg.type == 1 ) then
      msgtype = "Content Object"
   elseif ( msg.type == 2 ) then
      msgtype = "InterestReturn"
   elseif ( msg.type == 0x10 ) then
      msgtype = "PT_CTRL"
   end
   treeInfo = root:add(msg.tvb(msg.offset+1, 1), "Type: " .. msgtype .. "(" .. msg.type .. ")")
   treeInfo = root:add(msg.tvb(msg.offset+2, 2), "PacketLength: " .. msg.PacketLength)
   if ( msg.type == 0 ) then
      treeInfo = root:add(msg.tvb(msg.offset+4, 1), "HopLimit: "       .. HopLimit)
   end

   treeInfo = root:add(msg.tvb(msg.offset+6, 1), "Flags: "          .. Flags)
   treeInfo = root:add(msg.tvb(msg.offset+7, 1), "HeaderLength: "   .. msg.HeaderLength)

   root:append_text(" " .. msgtype)

   msg.root = treeInfo
   return msg.root
end

-----------------------------------------------------
-- Name TLVs
-----------------------------------------------------
local switch_Name_TLV = {}
--
-- T_NAMESEGMENT
--
switch_Name_TLV[1] = function(block, nametree, msgroot)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):string()
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_NAMESEGMENT(" .. block.type .. ") Length: " .. block.length .. " Value: \x22" .. value .."\x22")

   msgroot:append_text(string.format("/%s", value))

   return treeInfo
end
--
-- T_NAMENONCE
--
switch_Name_TLV[2] = function(block, nametree, msgroot)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_NAMENONCE(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- T_NAMEKEY
--
switch_Name_TLV[3] = function(block, nametree, msgroot)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_NAMEKEY(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- T_OBJHASH
--
switch_Name_TLV[4] = function(block, nametree, msgroot)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_OBJHASH(" .. block.type .. ") Length: " .. block.length .. " Value: " .. string.format("0x%x", value))

   return treeInfo
end
--
-- T_CHUNK
--
switch_Name_TLV[0x10] = function(block, nametree, msgroot)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_CHUNK(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   msgroot:append_text(string.format("/%%%u", value))

   return treeInfo
end
--
-- T_META
--
switch_Name_TLV[0x11] = function(block, nametree, msgroot)
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_META(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_NONCE
--
switch_Name_TLV[0x12] = function(block, nametree, msgroot)
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_NONCE(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_SYMBOLIC_CODE
--
switch_Name_TLV[0x13] = function(block, nametree, msgroot)
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_SYMBOLIC_CODE(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   if (block.length == 8) then
      local seq_from = block.tvb(block.offset + block.typeLen + block.lengthLen,   4):uint()
      local seq_to   = block.tvb(block.offset + block.typeLen + block.lengthLen+4, 4):uint()
      treeInfo:append_text(string.format(" Num: %d, %d", seq_from, seq_to))
      msgroot:append_text(string.format("/%%%u-%%%u",  seq_from, seq_to))
   end

   return treeInfo
end
-----------------------------------------------------
-- Metadata TLVs
-----------------------------------------------------
local switch_Metadata_TLV = {}
--
-- T_KEYID
--
switch_Metadata_TLV[1] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_KEYID(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- T_OHRESTRICTION
--
switch_Metadata_TLV[2] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_OHRESTRICTION(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_PAYLDTYPE
--
switch_Metadata_TLV[3] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_PAYLDTYPE(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_MAXAGE
--
switch_Metadata_TLV[5] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_MAXAGE(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_LIFETIME
--
switch_Metadata_TLV[8] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_LIFETIME(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
-----------------------------------------------------
-- Message TLVs
-----------------------------------------------------
local switch_NictOrgTLV = {}
local switch_MessageTLV = {}
--
-- T_NAME
--
switch_MessageTLV[0] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_NAME(" .. block.type .. ") Length: " .. block.length .. "   ")

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      subTLVs.msginfo = switch_Name_TLV[subTLVs.type](subTLVs, treeInfo, msgroot)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_PAYLOAD
--
switch_MessageTLV[1] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_PAYLOAD(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_KEYIDRESTR
--
switch_MessageTLV[2] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_KEYIDRESTR(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_OBJHASHRESTR
--
switch_MessageTLV[3] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_OBJHASHRESTR(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_PAYLDTYPE
--
switch_MessageTLV[5] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_PAYLDTYPE(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_EXPIRY
--
switch_MessageTLV[6] = function(block, msginfo, msgroot)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_EXPIRY(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- T_TRACE_REPLY
--
switch_MessageTLV[8] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_TRACE_REPLY(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_END_CHUNK
--
switch_MessageTLV[12] = function(block, msginfo, msgroot)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_END_CHUNK(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end

--
-- CefC_T_SYMBOLIC
--
switch_NictOrgTLV[1] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size), "T_SYMBOLIC(" .. block.type .. ")" )

   return treeInfo
end
--
-- CefC_T_LONGLIFE
--
switch_NictOrgTLV[2] = function(block, msginfo, msgroot)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size), "T_LONGLIFE(" .. block.type .. ")" )

   return treeInfo
end

--
-- T_ORG
--
switch_MessageTLV[4095] = function(block, msginfo, msgroot)
   local val_h = block.tvb(block.offset + block.typeLen + block.lengthLen, 1):uint()
   local val_l = block.tvb(block.offset + block.typeLen + block.lengthLen+1, 2):uint()
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_ORG(" .. block.type .. ") Length: " .. block.length .. " PEN: " .. string.format("0x%02x", val_h) .. string.format("%04x", val_l))

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   offset = offset + 3

   while valueLeft > 0 do
      local subTLVs = getNictOrgBlock(block.tvb, offset)

       if (subTLVs == nil or subTLVs.size == nil) then
          -- no valid tlv found
          break
       end

      subTLVs.root = switch_NictOrgTLV[subTLVs.type](subTLVs, treeInfo)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end

-----------------------------------------------------
-- Validation TLVs
-----------------------------------------------------
local switch_ValidationTLV = {}
--
-- T_CRC32C
--
switch_ValidationTLV[2] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         "T_CRC32C(" .. block.type .. ") Length: " .. block.length)

   valdroot:append_text(" Validation by CRC32C")

   return treeInfo
end
--
-- T_HMAC_SHA256
--
switch_ValidationTLV[4] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         "T_HMAC_SHA256(" .. block.type .. ") Length: " .. block.length)

   valdroot:append_text(" Validation by HMAC_SHA256")

   return treeInfo
end
--
-- T_RSA_SHA256
--
switch_ValidationTLV[5] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         "T_RSA_SHA256(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   valdroot:append_text(" Validation by RSA_SHA256")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      subTLVs.root = switch_ValidationTLV[subTLVs.type](subTLVs, treeInfo, root)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_CERT_FORWARDER
--
switch_ValidationTLV[0x1001] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         "T_CERT_FORWARDER(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   return treeInfo
end

-----------------------------------------------------
-- Controller Message Types
-----------------------------------------------------
local switch_ControllerTLV = {}
--
-- T_INFO
--
switch_ControllerTLV[0x1001] = function(block, root)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):string()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_INFO(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length .. " Value: " .. string.format("%s", value))

   return treeInfo
end

-----------------------------------------------------
-- Message Types
-----------------------------------------------------
local switch_MessageType = {}
--
-- T_INTEREST
--
switch_MessageType[1] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_INTEREST(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   root:append_text(" INTEREST ")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      subTLVs.root = switch_MessageTLV[subTLVs.type](subTLVs, treeInfo, root)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_OBJECT
--
switch_MessageType[2] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_OBJECT(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   root:append_text(" OBJECT ")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      subTLVs.root = switch_MessageTLV[subTLVs.type](subTLVs, treeInfo, root)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_VALIDATION_ALG
--
switch_MessageType[3] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_VALIDATION_ALG(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      subTLVs.root = switch_ValidationTLV[subTLVs.type](subTLVs, treeInfo, root)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_VALIDATION_PAYLOAD
--
switch_MessageType[4] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_VALIDATION_PAYLOAD(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_TRACE
--
switch_MessageType[5] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_TRACE(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_PING
--
switch_MessageType[6] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_PING(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end

--
-- T_NOTIFY
--
switch_MessageType[0x4321] = function(block, root)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_NOTIFY(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   root:append_text(" Controller Notify ")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      subTLVs.root = switch_ControllerTLV[subTLVs.type](subTLVs, treeInfo, root)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end

function addMessageInfo(block, root) -- may be add additional context later
   if ( block.type < 7 ) then
      block.root = switch_MessageType[block.type](block, root)
   elseif ( block.type == 0x4321 ) then
      block.root = switch_MessageType[block.type](block, root)
   else
      block.root = root:add(block.tvb(block.offset, block.size),
         "T_unknown(" .. string.format("0x%x",block.type) .. ") Length: " .. block.length)
   end

   return block.root
end

-----------------------------------------------------
-----------------------------------------------------

function getCcnHeader(tvb, offset)
   local CcnVersion = tvb(offset, 1):uint()
   local block = {}
   block.tvb = tvb
   block.offset = offset

--   if (CcnVersion ~= 0xf0) then
   if (CcnVersion ~= 0x01) then
      return nil
   end

   block.type = tvb(offset+1, 1):uint()
   block.size = tvb(offset+2, 2):uint()

   return block
end

function getBlock(tvb, offset)
   if offset >= tvb:len() then
      return nil
   end

   local block = {}
   block.tvb = tvb
   block.offset = offset

   block.type,   block.typeLen   = tvb(offset+0, 2):uint(), 2
   block.length, block.lengthLen = tvb(offset+2, 2):uint(), 2

   block.size = block.typeLen + block.lengthLen + block.length

   return block
end

function getNictOrgBlock(tvb, offset)
   if offset >= tvb:len() then
      return nil
   end

   local block = {}
   block.tvb = tvb
   block.offset = offset

   block.type,   block.typeLen   = tvb(offset+0, 2):uint(), 2
   if block.type >= 0x8000 then
     block.length, block.lengthLen = tvb(offset+2, 2):uint(), 2
   else
     block.length, block.lengthLen = 0, 0
   end

   block.size = block.typeLen + block.lengthLen + block.length

   return block
end

function findCcnPacket(tvb)
   offset = 0

   while offset + 10 < tvb:len() do
      local block = getCcnHeader(tvb, offset)

      if (block ~= nil) then
         return block
      end

      offset = offset + 1
   end

   return nil
end

function getSubBlocks(block)
   local valueLeft = block.length
   local subBlocks = {}

   while valueLeft > 0 do
      local child = getBlock(block.tvb,
                             block.offset + block.typeLen + block.lengthLen + (block.length - valueLeft))

      if child == nil then
         return nil
      end

      valueLeft = valueLeft - child.size
      table.insert(subBlocks, child)
   end

   if (valueLeft == 0) then
      return subBlocks
   else
      return nil
   end
end

-----------------------------------------------------
-----------------------------------------------------

-- CCN protocol dissector function
function ccn.dissector(tvb, pInfo, root) -- Tvb, Pinfo, TreeItem
   local CcnMsg

   if (tvb:len() ~= tvb:reported_len()) then
      return 0 -- ignore partially captured packets
      -- this can/may be re-enabled only for unfragmented UDP packets
   end

   local ok, CcnMsg = pcall(findCcnPacket, tvb)
   if (not ok) then
      return 0
   end

   if (CcnMsg == nil or CcnMsg.offset == nil) then
      -- no valid CCN packets found
      return 0
   end

   -- Create Tree Items
   CcnMsg.tree = root:add(ccn, tvb(CcnMsg.offset, CcnMsg.size))

   local block = getBlock(CcnMsg.tvb, CcnMsg.offset+8)
   if (block == nil or block.size == nil) then
      -- no valid CCN header found
      return 0
   end
   CcnMsg.elements = block

   -- Create FixedHeader Tree
   CcnMsg.elements.tree = addCcnFixHdrInfo(CcnMsg, CcnMsg.tree)

   -- print (pInfo.number .. ":: Found block: " .. block.type .. " of length " .. block.size .. " bytesLeft: " .. nBytesLeft)

   local nBytesLeft = 0

   -- Create OptionHeader Section
   if ( 8 < CcnMsg.HeaderLength ) then
      block.size = CcnMsg.HeaderLength - 8
      block.tree = CcnMsg.tree:add(block.tvb(block.offset, block.size),
                                   "OptionHeader Length: " .. block.size)

      local Oph = block
      nBytesLeft = Oph.size

      while (0 < nBytesLeft) do
         block = getBlock(Oph.tvb, Oph.offset + (Oph.size - nBytesLeft))
         local queue = {block}

         while (#queue > 0) do
            local block = queue[1]
            table.remove(queue, 1)

            block.elements = getSubBlocks(block)
            local subtree = addOptHdrInfo(block, Oph.tree)

            if (block.elements ~= nil) then
               for i, subBlock in pairs(block.elements) do
                  subBlock.tree = subtree
               end
            end
         end
         nBytesLeft = nBytesLeft - block.size
      end
   end

   block = getBlock(CcnMsg.tvb, CcnMsg.offset+CcnMsg.HeaderLength)
   nBytesLeft = tvb:len() - block.offset

   block.tree = CcnMsg.tree:add(block.tvb(block.offset, nBytesLeft), "Messages")
   local MsgTree = block.tree

   -- Create Message Item Tree
   while (0 < nBytesLeft) do

      local queue = {block}
      while (#queue > 0) do
         local block = queue[1]
         table.remove(queue, 1)

         block.elements = getSubBlocks(block)
         local subtree = addMessageInfo(block, MsgTree)

         if (block.elements ~= nil) then
            for i, subBlock in pairs(block.elements) do
               subBlock.tree = subtree
            end
         end
      end

      nBytesLeft = nBytesLeft - block.size
      if (0 < nBytesLeft) then
         ok, block = pcall(getBlock, tvb, tvb:len() - nBytesLeft)
         if (not ok or block == nil) then
            break
         end
      end
   end

--   pInfo.cols.protocol = tostring(pInfo.cols.protocol) .. " (" .. ccn.name .. ")"
   pInfo.cols.protocol = ccn.name

   if (nBytesLeft > 0 and block ~= nil and block.size ~= nil and block.size > nBytesLeft) then
      pInfo.desegment_offset = tvb:len() - nBytesLeft

      -- Originally, I set desegment_len to the exact lenght, but it mysteriously didn't work for TCP
      -- pInfo.desegment_len = block.size -- this will not work to desegment TCP streams
      pInfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
   end
end

local udpDissectorTable = DissectorTable.get("udp.port")
udpDissectorTable:add("9896", ccn)

local tcpDissectorTable = DissectorTable.get("tcp.port")
tcpDissectorTable:add("9896", ccn)

local tcpDissectorTable = DissectorTable.get("tcp.port")
tcpDissectorTable:add("9458", ccn)

local ethernetDissectorTable = DissectorTable.get("ethertype")
ethernetDissectorTable:add(0x8624, ccn)

io.stderr:write("ccn.lua is successfully loaded\n")
