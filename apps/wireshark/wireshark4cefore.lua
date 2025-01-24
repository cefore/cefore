
-- CCN protocol
p_ccn = Proto("ccn", "Content Centric Networking (CCN)")

-- CCN Protocol Field define
f_ccn = p_ccn.fields
f_ccn.hw_flags = ProtoField.uint16("ccn.hw_flags", "HW_FLAGS", base.HEX)
f_ccn.hw_smi   = ProtoField.uint8("ccn.hw_flags.hw_smi", "HW_FLAGS_SYMBOLIC", base.DEC, nil, 0x10)
f_ccn.hw_cache = ProtoField.uint8("ccn.hw_flags.hw_cache", "HW_FLAGS_ENABLECACHE", base.DEC, nil, 0x01)

f_ccn.esl   = ProtoField.uint16("ccn.fec.esl", "ESL(E)", base.DEC)
f_ccn.fssi  = ProtoField.uint16("ccn.fec.fssi", "FSSI", base.HEX)
f_ccn.s     = ProtoField.uint16("ccn.fec.fssi.s", "Strict", base.DEC, nil, 0x8000)
f_ccn.m     = ProtoField.uint16("ccn.fec.fssi.m", "m", base.DEC, nil, 0x7F00)
f_ccn.codec = ProtoField.uint16("ccn.fec.fssi.codec", "Codec", base.DEC, nil, 0x00FF)
f_ccn.sbn   = ProtoField.uint32("ccn.fec.sbn", "SBN", base.DEC)
f_ccn.esi   = ProtoField.uint8( "ccn.fec.esi", "ESI", base.DEC)
f_ccn.sbl8  = ProtoField.uint8( "ccn.fec.sbl", "SBL(k)", base.DEC)
f_ccn.sbl16 = ProtoField.uint16("ccn.fec.sbl", "SBL(k)", base.DEC)
f_ccn.padd  = ProtoField.uint16("ccn.fssi.padding", "Padding-Info", base.DEC)
f_ccn.ev    = ProtoField.bytes("ccn.fec.ev", "EncodingVector")
f_ccn.sb_from = ProtoField.uint32("ccn.fec.sb_from", "SourceBlock From", base.DEC)
f_ccn.sb_to   = ProtoField.uint32("ccn.fec.sb_to", "SourceBlock To", base.DEC)
f_ccn.ev_seed = ProtoField.uint32("ccn.fec.ev_seed", "EV Seed", base.DEC)

f_ccn.msgtype = ProtoField.uint8("ccn.msgtype", "PT_TYPE", base.DEC)
f_ccn.symbolic = ProtoField.none("ccn.symbolic", "T_SYMBOLIC", base.DEC)
f_ccn.osymbolic = ProtoField.none("ccn.osymbolic", "T_OSYMBOLIC", base.DEC)
f_ccn.longlife = ProtoField.none("ccn.longlife", "T_LONGLIFE", base.DEC)
f_ccn.selective = ProtoField.bytes("ccn.selective", "T_SELECTIVE")
f_ccn.chunk = ProtoField.uint32("ccn.chunk", "T_CHUNK", base.DEC)
f_ccn.seqnum = ProtoField.uint32("ccn.seqnum", "T_SEQNUM", base.DEC)
f_ccn.intlife = ProtoField.uint16("ccn.intlife", "T_INTLIFE", base.DEC)
f_ccn.cachetime = ProtoField.uint64("ccn.cachetime", "T_CACHETIME", base.DEC)

f_ccn.epn					= ProtoField.bytes("ccn.org.epn", "T_ORG/EPN")
f_ccn.version				= ProtoField.string("ccn.version", "T_VERSION")
f_ccn.frompub				= ProtoField.none("ccn.frompub", "T_FROM_PUB", base.DEC)
f_ccn.pending				= ProtoField.uint16("ccn.pending", "T_PENDING", base.DEC)
f_ccn.csact					= ProtoField.uint64("ccn.csact", "T_CSACT")
f_ccn.csact_alg				= ProtoField.bytes("ccn.csact_alg", "T_CSACT_ALG")
f_ccn.csact_alg_type		= ProtoField.uint16("ccn.csact_alg.type", "TYPE", base.DEC)
f_ccn.csact_alg_signature	= ProtoField.bytes("ccn.csact_alg.signature", "T_SIGNATURE")
f_ccn.csact_alg_publickey	= ProtoField.bytes("ccn.csact_alg.publickey", "T_PUBLICKEY")
f_ccn.encrypt_alg_type		= ProtoField.uint16("ccn.encrypt_alg.type", "type", base.DEC)
f_ccn.encrypt_alg_padding	= ProtoField.uint16("ccn.encrypt_alg.padding", "padding", base.DEC)
f_ccn.org_keyid				= ProtoField.bytes("ccn.org_keyid", "T_KEYID")

f_ccn.telemetry				= ProtoField.none("ccn.telemetry", "T_INT")
f_ccn.availability			= ProtoField.uint16("ccn.availability", "T_INT_AVAILABILITY")
f_ccn.bandwidth				= ProtoField.uint16("ccn.bandwidth", "T_INT_BANDWITH")
f_ccn.capacity				= ProtoField.uint16("ccn.capacity", "T_INT_CAPACITY")

f_ccn.payload				= ProtoField.bytes("ccn.payload", "T_PAYLOAD")

f_ccn.valid_alg_keyid = ProtoField.bytes("ccn.valid_alg.keyid", "T_KEYID")
f_ccn.valid_alg_publickey = ProtoField.bytes("ccn.valid_alg.publickey", "T_PUBLICKEY")
f_ccn.valid_alg_cert = ProtoField.bytes("ccn.valid_alg.cert", "T_CERT")
f_ccn.valid_payload = ProtoField.bytes("ccn.valid_payload", "T_VALIDATION_PAYLOAD")

f_ccn.reflexive = ProtoField.string("ccn.reflexive", "T_REFLEXIVE_NAME")
f_ccn.keyidrestr_hash_type = ProtoField.uint16("ccn.keyidrestr.hash_type", "HASH_TYPE", base.HEX)
f_ccn.keyidrestr_hash_length = ProtoField.uint16("ccn.keyidrestr.hash_length", "LENGTH", base.DEC)
f_ccn.keyidrestr_hash_value = ProtoField.bytes("ccn.keyidrestr.hash_value", "VALUE")
f_ccn.objhash_hash_type = ProtoField.uint16("ccn.objhash.hash_type", "HASH_TYPE", base.HEX)
f_ccn.objhash_hash_length = ProtoField.uint16("ccn.objhash.hash_length", "LENGTH", base.DEC)
f_ccn.objhash_hash_value = ProtoField.bytes("ccn.objhash.hash_value", "VALUE")
f_ccn.msghash_hash_type = ProtoField.uint16("ccn.msghash_hash_type", "HASH_TYPE", base.HEX)
f_ccn.returncode = ProtoField.uint16("ccn.returncode", "ReturnCode", base.DEC)

-----------------------------------------------------
-----------------------------------------------------
local switch_NictVenderTLV = {}
local switch_TpHdrTLV = {}

--
-- T_SYMBOLIC
--
switch_NictVenderTLV[0x0001] = function(block, root, pInfo)
   local blk_sym = block.tvb(block.offset, block.size);
   local treeInfo = root:add(blk_sym, "T_SYMBOLIC(" .. block.type .. ")" )

   treeInfo:add(f_ccn.symbolic, blk_sym)
   pInfo.cols.info = string.format("%s,SYM", pInfo.cols.info)

   return treeInfo
end
--
-- T_LONGLIFE
--
switch_NictVenderTLV[0x0002] = function(block, root, pInfo)
   local blk_long = block.tvb(block.offset, block.size);
   local treeInfo = root:add(blk_long, "T_LONGLIFE(" .. block.type .. ")" )

--   treeInfo:add(f_ccn.longlife, blk_long)
   pInfo.cols.info = string.format("%s,LONG", pInfo.cols.info)

   return treeInfo
end
--
-- T_SELECTIVE
--
switch_NictVenderTLV[0x8003] = function(block, root, pInfo)
   local blk_sel  = block.tvb(block.offset, block.size);
   local len_1st  = block.tvb(block.offset + block.typeLen + block.lengthLen, 2):uint()
   local len_last = block.tvb(block.offset + block.typeLen + block.lengthLen+2, 2):uint()
   local val_num  = block.tvb(block.offset + block.typeLen + block.lengthLen+4, 4):uint()
   local val_1st  = block.tvb(block.offset + block.typeLen + block.lengthLen+8, len_1st):uint()
   local val_last = block.tvb(block.offset + block.typeLen + block.lengthLen+8+len_1st, len_last):uint()

-- print ("#" .. pInfo.number .. " T_SELECTIVE: type " .. block.type .. " of length " .. block.length .. " Range(" .. val_1st .. "-" .. val_last ..")")
-- print ("#" .. pInfo.number .. " T_SELECTIVE: type " .. block.type .. " of length " .. block.length)

   local treeInfo = root:add(blk_sel,
         string.format("T_SELECTIVE(0x%x) Length: %d  Chunk: %d - %d (%d)", block.type, block.length, val_1st, val_last, val_num))

   treeInfo:add(f_ccn.selective, blk_sel)
   pInfo.cols.info = string.format("%s,SEL", pInfo.cols.info)

   return treeInfo
end
--
-- T_SEQNUM
--
switch_NictVenderTLV[0x8005] = function(block, root, pInfo)
   local blk_seq = block.tvb(block.offset, block.size);
   local blk_val  = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   local treeInfo = root:add(blk_seq,
         string.format("T_SEQNUM(0x%x) Length: %d Value: \"%s\"", block.type, block.length, blk_val:uint()))

   treeInfo:add(f_ccn.seqnum, blk_val)
   pInfo.cols.info = string.format("%s,SEQNUM", pInfo.cols.info)

   return treeInfo
end
--
-- T_OSYMBOLIC
--
switch_NictVenderTLV[0x000A] = function(block, root, pInfo)
   local blk_sym = block.tvb(block.offset, block.size);
   local treeInfo = root:add(blk_sym, "T_OSYMBOLIC(" .. block.type .. ")" )

--   treeInfo:add(f_ccn.osymbolic, blk_sym)
   pInfo.cols.info = string.format("%s,OSYM", pInfo.cols.info)

   return treeInfo
end
--
-- T_VERSION
--
switch_NictVenderTLV[0x800B] = function(block, root, pInfo)
   local blk_version = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
             string.format("T_VERSION(0x%x) Length: %d  Value: %s",
             block.type, block.length, blk_version:string()))

   treeInfo:add(f_ccn.version, blk_version)
   pInfo.cols.info = string.format("%s,T_VERSION=%s", pInfo.cols.info, blk_version:string())

   return treeInfo
end
--
-- T_PUTVERIFY
--
switch_NictVenderTLV[0x800C] = function(block, root, pInfo)
   local blk_sel  = block.tvb(block.offset, block.size);
   local msgtype  = block.tvb(block.offset + block.typeLen + block.lengthLen, 1):uint()
   local sseq = block.tvb(block.offset + block.typeLen + block.lengthLen+1, 4):uint()
   local eseq  = block.tvb(block.offset + block.typeLen + block.lengthLen+5, 4):uint()
   local treeInfo = root:add(blk_sel,
         string.format("T_PUTVERIFY(0x%x) Length: %d  msgtype: %d", block.type, block.length, msgtype))

   if ( 5 < block.length ) then
      treeInfo:append_text(string.format(" sseq: %d  eseq: %d", sseq, eseq))
   end

   pInfo.cols.info = string.format("%s,T_PUTVERIFY", pInfo.cols.info)

   return treeInfo
end
--
-- T_FROM_PUB
--
switch_NictVenderTLV[0x000D] = function(block, root, pInfo)
   local blk_pub  = block.tvb(block.offset, block.size);
   local value    = block.tvb(block.offset + block.typeLen + block.lengthLen, 2):uint()
   local treeInfo = root:add(blk_pub, "T_FROM_PUB(" .. block.type .. ")" )

   treeInfo:add(f_ccn.frompub, value)
   pInfo.cols.info = string.format("%s,T_FROM_PUB", pInfo.cols.info)

   return treeInfo
end
--
-- T_PENDING
--
switch_NictVenderTLV[0x800E] = function(block, root, pInfo)
   local blk_pen  = block.tvb(block.offset, block.size);
   local blk_val  = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   local treeInfo = root:add(blk_pen,
         string.format("T_PENDING(0x%x) Length: %d Value: \"%s\"", block.type, block.length, blk_val:uint()))

   treeInfo:add(f_ccn.pending, blk_val)
   pInfo.cols.info = string.format("%s,PENDING", pInfo.cols.info)

   return treeInfo
end
--
-- T_CSACT
--
switch_NictVenderTLV[0x800F] = function(block, root, pInfo)
   local blk_act  = block.tvb(block.offset, block.size);
   local blk_val  = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   local treeInfo = root:add(blk_act,
         string.format("T_CSACT(0x%x) Length: %d", block.type, block.length))

   treeInfo:add(f_ccn.csact, blk_val)
   pInfo.cols.info = string.format("%s,CSACT", pInfo.cols.info)

   return treeInfo
end

------------------------------------------------------------
-- T_CSACT_ALG
------------------------------------------------------------
local switch_CsActAlg_SubTLV = {}

--
-- T_SIGNATURE
--
switch_CsActAlg_SubTLV[0x8011] = function(block, root, pInfo)
   local blk_sig  = block.tvb(block.offset, block.size);
   local blk_val  = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   local treeInfo = root:add(blk_sig,
         string.format("T_SIGNATURE(0x%x) Length: %d", block.type, block.length))

   treeInfo:add(f_ccn.csact_alg_signature, blk_val)
   pInfo.cols.info = string.format("%s,T_SIGNATURE", pInfo.cols.info)

   return treeInfo
end
--
-- T_PUBLICKEY
--
switch_CsActAlg_SubTLV[0x000b] = function(block, root, pInfo)
   local blk_pubkey  = block.tvb(block.offset, block.size);
   local blk_val  = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   local treeInfo = root:add(blk_pubkey,
         string.format("T_PUBLICKEY(0x%x) Length: %d", block.type, block.length))

   treeInfo:add(f_ccn.csact_alg_publickey, blk_val)
   pInfo.cols.info = string.format("%s,PUBLICKEY", pInfo.cols.info)

   return treeInfo
end
--
-- T_CSACT_ALG
--
local strAlgTypeName = {
  nil,
  "T_CRC32C",
  nil,
  "T_HMAC-SHA256",
  "T_RSA-SHA256",
  "T_EC-SECP-256K1",
  "T_EC-SECP-384R1",
  nil,
  nil,
  nil,
}
switch_NictVenderTLV[0x8010] = function(block, root, pInfo)
   local blk_alg  = block.tvb(block.offset, block.size);
   local alg_type  = block.tvb(block.offset + block.typeLen + block.lengthLen, 2):uint()
   local treeInfo = root:add(blk_alg,
         string.format("T_CSACT_ALG(0x%x) Length: %d ", block.type, block.length))
   local str_type;

   if ( nil == strAlgTypeName[alg_type] ) then
       str_type = string.format("Type: 0x%02x", alg_type)
   else
       str_type = string.format("%s", strAlgTypeName[alg_type])
   end

   treeInfo:append_text(str_type)

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length - 4

   local subtree = treeInfo:add(block.tvb(offset, block.length),
                                string.format("%s Length: %d ", str_type, valueLeft))

   offset = offset + 4

   pInfo.cols.info = string.format("%s,%s", pInfo.cols.info, str_type)

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

-- print ("#" .. pInfo.number .. " T_CSACT_ALG: type " .. subTLVs.type .. " of length " .. subTLVs.size .. " valueLeft: " .. valueLeft)
      if ( nil == switch_CsActAlg_SubTLV[subTLVs.type] ) then
          -- no valid tlv found
          break
      end

      subTLVs.root = switch_CsActAlg_SubTLV[subTLVs.type](subTLVs, subtree, pInfo)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_ENCRYPT_ALG
--
switch_NictVenderTLV[0x8012] = function(block, root, pInfo)
   local blk_val  = block.tvb(block.offset, block.size);
   local blk_typ  = block.tvb(block.offset + block.typeLen + block.lengthLen, 2)
   local blk_pad  = block.tvb(block.offset + block.typeLen + block.lengthLen+2, 2)
   local treeInfo = root:add(blk_val,
         string.format("T_ENCRYPT_ALG(0x%x) Length: %d, Type: %d, Padding: %d", block.type, block.length, blk_typ:uint(), blk_pad:uint()))

   treeInfo:add(f_ccn.encrypt_alg_type, blk_typ)
   treeInfo:add(f_ccn.encrypt_alg_padding, blk_pad)
   pInfo.cols.info = string.format("%s,ENCRYPT_ALG", pInfo.cols.info)

   return treeInfo
end
--
-- T_ORG_KEYID
--
switch_NictVenderTLV[0x8009] = function(block, root, pInfo)
   local blk_keyid  = block.tvb(block.offset, block.size);
   local blk_val    = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   local treeInfo = root:add(blk_keyid,
         string.format("T_ORG_KEYID(0x%x) Length: %d", block.type, block.length))

   treeInfo:add(f_ccn.org_keyid, blk_val)
   pInfo.cols.info = string.format("%s,KEYID", pInfo.cols.info)

   return treeInfo
end

------------------------------------------------------------
-- T_INT
------------------------------------------------------------
local switch_Int_SubTLV = {}

--
-- T_INT_NODE_ID
--
switch_Int_SubTLV[0x0001] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_INT_NODE_ID(0x%x) Length: %d", block.type, block.length));

   pInfo.cols.info = string.format("%s,T_INT_NODE_ID", pInfo.cols.info)

   return treeInfo
end
--
-- T_INT_APP_ID
--
switch_Int_SubTLV[0x0002] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_INT_APP_ID(0x%x) Length: %d Value: %d", block.type, block.length, value));

   pInfo.cols.info = string.format("%s,T_INT_APP_ID", pInfo.cols.info)

   root:append_text(" App=" .. value)

   return treeInfo
end
--
-- T_INT_IFINDEX
--
switch_Int_SubTLV[0x0003] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_INT_IFINDEX(0x%x) Length: %d Value: %d", block.type, block.length, value));

   pInfo.cols.info = string.format("%s,T_INT_IFINDEX", pInfo.cols.info)

   root:append_text(" IF=" .. value)

   return treeInfo
end
--
-- T_INT_BANDWIDTH
--
switch_Int_SubTLV[0x0004] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_INT_BANDWIDTH(0x%x) Length: %d Value: ", block.type, block.length) .. value);

   pInfo.cols.info = string.format("%s,T_INT_BANDWIDTH", pInfo.cols.info)

   root:append_text(" Band=" .. value)

   return treeInfo
end
--
-- T_OPT_INT_RESOURCE
--
switch_Int_SubTLV[0x0005] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_OPT_INT_RESOURCE(0x%x) Length: %d Value: %d", block.type, block.length, value));

   pInfo.cols.info = string.format("%s,T_OPT_INT_RESOURCE", pInfo.cols.info)

   return treeInfo
end
--
-- T_OPT_INT_RESOURCEGENMIN
--
switch_Int_SubTLV[0x0006] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_OPT_INT_RESOURCEGENMIN(0x%x) Length: %d Value: %d", block.type, block.length, value));

   pInfo.cols.info = string.format("%s,T_OPT_INT_RESOURCEGENMIN", pInfo.cols.info)

   return treeInfo
end
--
-- T_OPT_INT_RESOURCEGENMAX
--
switch_Int_SubTLV[0x0007] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_OPT_INT_RESOURCEGENMAX(0x%x) Length: %d Value: %d", block.type, block.length, value));

   pInfo.cols.info = string.format("%s,T_OPT_INT_RESOURCEGENMAX", pInfo.cols.info)

   return treeInfo
end
--
-- T_INT_CAPACITY
--
switch_Int_SubTLV[0x0008] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_INT_CAPACITY(0x%x) Length: %d Value: %d", block.type, block.length, value));

   pInfo.cols.info = string.format("%s,T_INT_CAPACITY", pInfo.cols.info)

   root:append_text(" Cap=" .. value)
--   treeInfo:add(f_ccn.capacity, block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4))

   return treeInfo
end
--
-- T_INT_AVAILABILITY
--
switch_Int_SubTLV[0x0009] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("T_INT_AVAILABILITY(0x%x) Length: %d Value: %d", block.type, block.length, value));

   pInfo.cols.info = string.format("%s,T_INT_AVAILABILITY", pInfo.cols.info)

   root:append_text(" Avl=" .. value)

--   treeInfo:add(f_ccn.availability, block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4))

   return treeInfo
end

--
-- T_INT
--
switch_NictVenderTLV[0x8701] = function(block, root, pInfo)
   local blk_int  = block.tvb(block.offset, block.size);

   local treeInfo = root:add(blk_int,
         string.format("T_INT(0x%x) Length: %d", block.type, block.length))

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length - 4

-- print ("#" .. pInfo.number .. " T_INT: type " .. string.format("0x%x", block.type) .. " of length " .. block.length)

   offset = 4

   while valueLeft > 0 do
      local subTLVs = getBlock(blk_int, offset)

-- print ("#" .. pInfo.number .. " T_INT: offset=" .. subTLVs.offset .. " size=" .. subTLVs.size .. " type=" .. string.format("0x%x", subTLVs.type) .. " length=" .. subTLVs.length .. " valueLeft=" .. valueLeft)
      if ( switch_Int_SubTLV[subTLVs.type] ) then
          subTLVs.root = switch_Int_SubTLV[subTLVs.type](subTLVs, treeInfo, pInfo)
      else
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          treeInfo:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
      end

      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end

switch_NictVenderTLV[0x2001] = function(block, root, pInfo)
   return switch_NictVenderTLV[0x8701](block, root, pInfo)
end

-----------------------------------------------------
-- Transport Information Option Header Sub-TLVs
-----------------------------------------------------
--
-- T_OPT_L2MCTP_ALTNAME_TLV
--
switch_TpHdrTLV[0x8001] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen, block.size):string()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         string.format("ALTNAME(0x%x) Length: %d Value: \"%s\"", block.type, block.length, value))

   return treeInfo
end
--
-- T_OPT_L2MCTP_DUPLICATE_TV
--
switch_TpHdrTLV[0x0002] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen, 2):uint()
   local treeInfo = root:add(block.tvb(block.offset, 4),
         string.format("DUPLICATE(0x%x) Value: %d", block.type, value))

   return treeInfo
end

--
-- T_OPT_TRANSPORT
--
local strTpName = {
  "SampTp",
  "L4C2",
  "FWDTP",
  "L2MCTP",
  "TP.Val5",
  "TP.Val6",
  "TP.Val7",
  "TP.Val8",
  "TP.Val9",
  "TP.Val10",
}
switch_NictVenderTLV[0x8004] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
                            string.format("OPT_TRANSPORT(0x%x) Length: %d", block.type, block.length))
   local offset   = block.offset + block.typeLen + block.lengthLen
   local tpValiant = getBlock(block.tvb, offset)

   if ( 0 < tpValiant.type ) then
       local TpInfo = treeInfo:add(block.tvb(tpValiant.offset, tpValiant.size), string.format("Valiant: 0x%x Length: %d", tpValiant.type, tpValiant.length))
       local valueLeft = tpValiant.length

       if ( nil == strTpName[tpValiant.type] ) then
          treeInfo:append_text(string.format("  Transport:0x%x Length: %d", tpValiant.type, tpValiant.length))
          TpInfo:append_text("  Value:")
          for i = 0, tpValiant.length-1 do
             j = tpValiant.offset + tpValiant.typeLen + tpValiant.lengthLen + i;
             TpInfo:append_text(string.format("%02x.", tpValiant.tvb(j, 1):uint()))
          end
       else
          treeInfo:append_text(string.format("  Transport:%s(0x%x) Length: %d", strTpName[tpValiant.type], tpValiant.type, tpValiant.length))

          offset   = offset + tpValiant.typeLen + tpValiant.lengthLen;

          while valueLeft > 0 do
             local subTLVs = getBlock(block.tvb, offset)

             if ( nil == switch_TpHdrTLV[subTLVs.type] ) then
                 -- no valid tlv found
             else
                 subTLVs.root = switch_TpHdrTLV[subTLVs.type](subTLVs, TpInfo)
             end
             valueLeft = valueLeft - subTLVs.size
             offset    = offset    + subTLVs.size
          end
       end
   end

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " [OPT_TRANSPORT]"

   return treeInfo
end

--
-- OPT_SEQNUM
--
switch_NictVenderTLV[0x8008] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
                    string.format("OPT_SEQNUM(0x%x) Length: %d Value: %s", block.type, block.length, value))

   return treeInfo
end

--
-- T_HW_FLAGS
--
switch_NictVenderTLV[0x05FF] = function(block, root, pInfo)
   local hw_flags = block.tvb(block.offset, block.size)
   local treeInfo = root:add(f_ccn.hw_flags, hw_flags)

   treeInfo:add(f_ccn.hw_smi, hw_flags)
   treeInfo:add(f_ccn.hw_cache, hw_flags)

   return treeInfo
end
--
-- T_HW_TIMESTAMP
--
switch_NictVenderTLV[0x8601] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
                    string.format("T_HW_TIMESTAMP(0x%x) Length: %d Value: %s", block.type, block.length, value))

   return treeInfo
end
--
-- T_METRIC
--
switch_NictVenderTLV[0x8998] = function(block, root, pInfo)
   local nodeid = block.tvb(block.offset + block.typeLen + block.lengthLen, 2):uint()
   local avail = block.tvb(block.offset + block.typeLen + block.lengthLen+2, 2):uint()
   local treeInfo;

   if ( block.length == 8 ) then
         local dist = block.tvb(block.offset + block.typeLen + block.lengthLen+4, 2):uint()
         local capa = block.tvb(block.offset + block.typeLen + block.lengthLen+6, 2):uint()
         treeInfo = root:add(block.tvb(block.offset, block.size),
                    string.format("T_METRIC(0x%x) Length: %d  Nodeid: %u  avail: %u  dist: %u  capa: %u",
                                    block.type, block.length, nodeid, avail, dist, capa))

         root:append_text(" " .. string.format("T_METRIC: %u, %u, %u", avail, dist, capa))
   else
         treeInfo = root:add(block.tvb(block.offset, block.size),
                    string.format("T_AVAILABLITY(0x%x) Length: %d  Nodeid: %u  Value: %u", block.type, block.length, nodeid, avail))
   end

   return treeInfo
end
--
-- T_CODERATE
--
switch_NictVenderTLV[0x8999] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
                    string.format("T_CODERATE(0x%x) Length: %d Value: %u", block.type, block.length, value))

   return treeInfo
end

-----------------------------------------------------
-- Hop by Hop Option Header TLVs
-----------------------------------------------------
local switch_OptHdrTLV = {}
local switch_OptUserTLV = {}
--
-- T_INTLIFE
--
switch_OptHdrTLV[1] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_INTLIFE(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   treeInfo:add(f_ccn.intlife, value)

   return treeInfo
end
--
-- T_CACHETIME
--
switch_OptHdrTLV[2] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_CACHETIME(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   treeInfo:add(f_ccn.cachetime, value)

   return treeInfo
end
--
-- T_MSGHASH
--
switch_OptHdrTLV[3] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_MSGHASH(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   local blk_hash_type = block.tvb(block.offset + block.typeLen + block.typeLen, block.typeLen)
   treeInfo:add(f_ccn.msghash_hash_type, blk_hash_type)

   return treeInfo
end
--
-- T_DISC_REQHDR
--
switch_OptHdrTLV[8] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_DISC_REQHDR(" .. block.type .. ") Length: " .. block.length)
   local RequestID    = block.tvb(block.offset + block.typeLen + block.lengthLen, 2)
   local SkipHopCount = block.tvb(block.offset + block.typeLen + block.lengthLen+2, 1)
   local Flags        = block.tvb(block.offset + block.typeLen + block.lengthLen+2, 2)

   treeInfo:add(RequestID,      string.format("     RequestID: %u", RequestID:uint()))
   treeInfo:add(SkipHopCount,   string.format("  SkipHopCount: %u", SkipHopCount:uint() / 0x10))
   treeInfo:add(Flags,          string.format("         Flags: 0x%x", Flags:uint() % 0x1000))

   if ( block.length <= 4 ) then
      return treeInfo
   end

   local ArrivalTime  = block.tvb(block.offset + block.typeLen + block.lengthLen+4, 4)
   treeInfo:add(ArrivalTime,    string.format("   ArrivalTime: %u", ArrivalTime:uint()))

   if ( block.length <= 8 ) then
      return treeInfo
   end

   NodeId_length = block.length - 8;
   local treeNodeId = treeInfo:add(block.tvb(block.offset + block.typeLen + block.lengthLen+8, NodeId_length), "NodeIdentifier: ")

   for i = 8, block.length-1 do
      j = block.offset + block.typeLen + block.lengthLen + i;
      treeNodeId:append_text(string.format("%02x.", block.tvb(j, 1):uint()))
   end

   return treeInfo
end
--
-- T_DISC_REPORT
--
local switch_Nodeid_SubTLV = {}
--
-- T_NODEID_SEGMENT
--
switch_Nodeid_SubTLV[1] = function(block, root, info)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):string()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_NAMESEGMENT(" .. block.type .. ") Length: " .. block.length .. " Value: \x22" .. value .."\x22")

   root:append_text(string.format("/%s", value))

   return treeInfo
end
switch_OptHdrTLV[9] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_DISC_REPORT(" .. block.type .. ") Length: " .. block.length)
   local ArrivalTime  = block.tvb(block.offset + block.typeLen + block.lengthLen, 4)

   treeInfo:add(ArrivalTime,    string.format("   ArrivalTime: %u", ArrivalTime:uint()))

   if ( block.length <= 4 ) then
      return treeInfo
   end

   local offset   = block.offset + block.typeLen + block.lengthLen+4
   local treeNodeId = treeInfo:add(block.tvb(offset, block.length-4), "NodeIdentifier: ")
   local NodeTLVs = getBlock(block.tvb, block.offset + block.typeLen + block.lengthLen+4)

-- print (string.format("T_DISC_REPLY:block.offset=%d,length=%d", block.offset, block.length))
-- print (string.format("T_DISC_REPLY:NodeTLVs.offset=%d,length=%d,size=%d", NodeTLVs.offset, NodeTLVs.length, NodeTLVs.size))

   offset   = offset + 4
   local valueLeft = NodeTLVs.length

   while valueLeft > 0 do
      local subTLVs = getBlock(NodeTLVs.tvb, offset)
-- print (string.format("T_DISC_REPLY:subTLVs.offset=%d,type=%d,length=%d,size=%d", subTLVs.offset, subTLVs.type, subTLVs.length, subTLVs.size))

      if ( nil ~= switch_Nodeid_SubTLV[subTLVs.type] ) then
          subTLVs.msginfo = switch_Nodeid_SubTLV[subTLVs.type](subTLVs, treeNodeId, treeInfo)
      end
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
      ::continue::
   end

   return treeInfo
end
--
-- OPT_PING_REQ
--
switch_OptHdrTLV[10] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_PING_REQ(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- OPT_HOPAUTH
--
switch_OptHdrTLV[11] = function(block, root, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_HOPAUTH(" .. block.type .. ")      Length: " .. block.length .. " Value: " .. value)

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " [HopAUTH]"

   return treeInfo
end
--
-- OPT_APP_REG
--
switch_OptUserTLV[0x1001] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_APP_REG(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " APP_REG"

   return treeInfo
end
--
-- OPT_APP_DEREG
--
switch_OptUserTLV[0x1002] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_APP_DEREG(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " APP_DEREG"

   return treeInfo
end
--
-- OPT_APP_REG_P
--
switch_OptUserTLV[0x1003] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_APP_REG_P(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " APP_REG_P"

   return treeInfo
end
--
-- OPT_APP_PIT_REG
--
switch_OptUserTLV[0x1004] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_APP_PIT_REG(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " PIT_REG_P"

   return treeInfo
end
--
-- OPT_APP_PIT_DEREG
--
switch_OptUserTLV[0x1005] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_APP_PIT_DEREG(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " APP_PIT_DEREG"

   return treeInfo
end
--
-- OPT_DEV_REG_PIT
--
switch_OptUserTLV[0x1006] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_DEV_REG_PIT(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   local text = string.format("%s", pInfo.cols.info)
   pInfo.cols.info = text .. " DEV_REG_PIT"

   return treeInfo
end
function addOptUserInfo(block, root, pInfo) -- may be add additional context later

-- print (string.format("#%d OptUser::type=0x%04x", pInfo.number, block.type))

   if ( switch_OptUserTLV[block.type] ~= nil ) then
      block.root = switch_OptUserTLV[block.type](block, root, pInfo)
   else
      -- no valid tlv found
      local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length)
      treeInfo:add(block.tvb(block.offset, block.size),
             string.format("T_X(0x%04x) Length:%d Value:", block.type, block.length) .. value)
   end

   return block.root
end

--
-- OPT_USER_TLV
--
switch_OptHdrTLV[0x1000] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_USER_TLV(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)
   local blk_user = getBlock(block.tvb, block.offset + block.typeLen + block.lengthLen)

   pInfo.cols.info = "[OPT_USER_TLV:"

   blk_user.elements = getSubBlocks(blk_user)

   local subtree = addOptUserInfo(blk_user, treeInfo, pInfo)
   if (block.elements ~= nil) then
      for i, subBlock in pairs(blk_user.elements) do
         subBlock.tree = subtree
      end
   end

   pInfo.cols.info = string.format("%s]", pInfo.cols.info)

   return treeInfo
end

--
-- OPT_USER_TLV (deprecated)
--
switch_OptHdrTLV[0x1000] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_USER_TLV(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)
   local blk_user = getBlock(block.tvb, block.offset + block.typeLen + block.lengthLen)

   pInfo.cols.info = "[OPT_USER_TLV:"

   blk_user.elements = getSubBlocks(blk_user)

   local subtree = addOptUserInfo(blk_user, treeInfo, pInfo)
   if (block.elements ~= nil) then
      for i, subBlock in pairs(blk_user.elements) do
         subBlock.tree = subtree
      end
   end

   pInfo.cols.info = string.format("%s]", pInfo.cols.info)

   return treeInfo
end
--
-- OPT_SYMBOLIC (Highly discouraged)
--
switch_OptHdrTLV[0x1001] = function(block, root, pInfo)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "OPT_SYMBOLIC(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)
   local blk_user = getBlock(block.tvb, block.offset + block.typeLen + block.lengthLen)

   pInfo.cols.info = "[OPT_SYMBOLIC:"

   blk_user.elements = getSubBlocks(blk_user)

   local subtree = addOptUserInfo(blk_user, treeInfo, pInfo)
   if (block.elements ~= nil) then
      for i, subBlock in pairs(blk_user.elements) do
         subBlock.tree = subtree
      end
   end

   pInfo.cols.info = string.format("%s]", pInfo.cols.info)

   return treeInfo
end

--
-- OPT_T_ORG
--
switch_OptHdrTLV[0x0FFF] = function(block, root, pInfo)
--   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, 3):uint()
   local blk_epn = block.tvb(block.offset + block.typeLen + block.lengthLen, 3)
   local epn = blk_epn:uint()
   local treeInfo = root:add(block.tvb(block.offset, block.size),
---      string.format("T_ORG(0x%04x) Length: %u PEN: 0x%06x", block.type, block.length, epn))
         string.format("T_ORG(0x%04x) Length: %u", block.type, block.length))

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length
   local base_info = tostring(pInfo.cols.info)

--   treeInfo:add(f_ccn.epn, blk_epn)
   treeInfo:add(blk_epn, string.format("IANA Private Enterprise Numbers(0x%06x)", epn))

   offset = offset + 3
   valueLeft = valueLeft - 3
   pInfo.cols.info = ""

   while valueLeft > 0 do
      local subTLVs = getNictOrgBlock(block.tvb, offset)
      local type = subTLVs.type
-- print ("#" .. pInfo.number .. " T_ORG@Header: type " .. string.format("0x%x", subTLVs.type) .. " of length " .. subTLVs.size .. " valueLeft: " .. valueLeft)

      if (subTLVs == nil or subTLVs.size == nil) then
         -- no valid tlv found
         break
      end

      if ( switch_NictVenderTLV[subTLVs.type] ) then
         subTLVs.root = switch_NictVenderTLV[subTLVs.type](subTLVs, treeInfo, pInfo)
      elseif ( 0x0500 <= subTLVs.type and subTLVs.type <= 0x05FF ) then
         -- T_HW_FLAGS(0x05xx)
         subTLVs.root = switch_NictVenderTLV[0x05FF](subTLVs, treeInfo, pInfo)
      else
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          treeInfo:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
      end
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   local t_org_info = tostring(pInfo.cols.info)

   if (1 < t_org_info:len() ) then
      pInfo.cols.info = string.format("%s [HDRORG:%s]", base_info, t_org_info:sub(1-t_org_info:len()))
   end

   return treeInfo
end


function addOptHdrInfo(block, root, pInfo) -- may be add additional context later

-- print (string.format("#%d OptHdr::type=0x%04x", pInfo.number, block.type))

   block.root = switch_OptHdrTLV[block.type](block, root, pInfo)

   return block.root
end

-----------------------------------------------------
-----------------------------------------------------
local interest_returncode = {
  "NO_ERROR",
  "NO_ROUTE",
  "LIMIT_EXCEEDED",
  "NO_RESOURCES",
  "PATH_ERROR",
  "PROHIBITED",
  "CONGESTED",
  "MTU_TOO_LARGE",
  "UNSUPPORTED_HASH_RESTRICTION",
  "MALFORMED_INTEREST",
}

local reply_returncode = {
  "NO_ERROR",
  "WRONG_IF",
  "INVALID_REQUEST",
  "NO_ROUTE",
  "NO_INFO",
  "NO_SPACE",
  "INFO_HIDDEN",
}

-- block
-- .tvb
-- .offset
-- .type
-- .typeLen
-- .length
-- .lengthLen
-- .size = .typeLen + .lengthLen + .length

function addCcnFixHdrInfo(msg, root, pInfo) -- may be add additional context later
   local CcnVersion = msg.tvb(msg.offset+0, 1):uint()
   local HopLimit   = msg.tvb(msg.offset+4, 1):uint()
   local ReturnCode = msg.tvb(msg.offset+5, 1):uint()
   local Flags      = msg.tvb(msg.offset+6, 1):uint()
   local packet_type    = "Unknown"

   msg.PacketLength  = msg.tvb(msg.offset+2, 2):uint()
   msg.HeaderLength  = msg.tvb(msg.offset+7, 1):uint()
   msg.PayloadLength = msg.PacketLength - msg.HeaderLength

   treeInfo = root:add(msg.tvb(msg.offset, 1), "Version: " .. string.format("0x%x", CcnVersion))

   if ( msg.type == 0x00 ) then
      packet_type = "INTEREST"
   elseif ( msg.type == 0x01 ) then
      packet_type = "OBJECT"
   elseif ( msg.type == 0x02 ) then
      packet_type = "RETURN"
      if ( nil ~= interest_returncode[ReturnCode+1] ) then
         packet_type = string.format("%s(%s) ", packet_type, interest_returncode[ReturnCode+1])
      else
         packet_type = string.format("%s(0x%04x) ", packet_type, ReturnCode)
      end
   elseif ( msg.type == 0x03 ) then
      packet_type = "CCNINFO_REQUEST"
   elseif ( msg.type == 0x04 ) then
      packet_type = "CCNINFO_REPLY"
      if ( nil ~= reply_returncode[ReturnCode+1] ) then
         packet_type = string.format("%s(%s) ", packet_type, reply_returncode[ReturnCode+1])
      else
         packet_type = string.format("%s(0x%04x) ", packet_type, ReturnCode)
      end
   elseif ( msg.type == 0x05 ) then
      msgtype = "PING_REQUEST"
   elseif ( msg.type == 0x06 ) then
      msgtype = "PING_REPLY"
   elseif ( msg.type == 0x07 ) then
      msgtype = "TR_REQUEST"
   elseif ( msg.type == 0x08 ) then
      msgtype = "TR_REPLY"
   elseif ( msg.type == 0x10 ) then
      msgtype = "PT_CTRL"
   end

   pInfo.cols.info = string.format("%s ", packet_type)

   treeInfo = root:add(msg.tvb(msg.offset+1, 1), "Type: " .. packet_type .. "(" .. msg.type .. ")")
   treeInfo:add(f_ccn.msgtype, msg.tvb(msg.offset+1, 1))

   treeInfo = root:add(msg.tvb(msg.offset+2, 2), "PacketLength: " .. msg.PacketLength)
   if ( msg.type == 0x00 or msg.type == 0x03 ) then
      treeInfo = root:add(msg.tvb(msg.offset+4, 1), "HopLimit: "       .. HopLimit)
   end
   if ( msg.type == 0x02 ) then
      if ( nil ~= interest_returncode[ReturnCode+1] ) then
         retmsg = string.format("ReturnCode: 0x%x (%s)", ReturnCode, interest_returncode[ReturnCode+1]);
      else
         retmsg = string.format("ReturnCode: 0x%x", ReturnCode);
      end
      treeInfo = root:add(msg.tvb(msg.offset+5, 1), retmsg);
      treeInfo:add(f_ccn.returncode, msg.tvb(msg.offset+5, 1))
   end
   if ( msg.type == 0x04 ) then
      if ( nil ~= reply_returncode[ReturnCode+1] ) then
         retmsg = string.format("ReturnCode: 0x%x (%s)", ReturnCode, reply_returncode[ReturnCode+1]);
      else
         retmsg = string.format("ReturnCode: 0x%x", ReturnCode);
      end
      treeInfo = root:add(msg.tvb(msg.offset+5, 1), retmsg);
      treeInfo:add(f_ccn.returncode, msg.tvb(msg.offset+5, 1))
   end

   treeInfo = root:add(msg.tvb(msg.offset+6, 1), "Flags: "          .. Flags)
   treeInfo = root:add(msg.tvb(msg.offset+7, 1), "HeaderLength: "   .. msg.HeaderLength)

   root:append_text(" " .. packet_type)

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
switch_Name_TLV[1] = function(block, nametree, msgroot, pInfo, CcnMsg)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):string()
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_NAMESEGMENT(" .. block.type .. ") Length: " .. block.length .. " Value: \x22" .. value .."\x22")

   msgroot:append_text(string.format("/%s", value))

   if ( pInfo ) then
      local text = string.format("%s", pInfo.cols.info)
      pInfo.cols.info = string.format("%s/%s", text, value)
   end

   if ( CcnMsg ) then
      CcnMsg:append_text(string.format("/%s", value))
   end

   return treeInfo
end
--
-- T_IPID
--
switch_Name_TLV[2] = function(block, nametree, msgroot, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_IPID(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- T_NONCE
--
switch_Name_TLV[0x03] = function(block, nametree, msgroot, pInfo)
   local blk_nonce = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length)
   local value

   if (block.length == 8) then
      value = blk_nonce:uint64()
   else
      value = blk_nonce:uint()
   end

   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_NONCE(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--[[
-- T_CHUNK
--]]
switch_Name_TLV[0x04] = function(block, nametree, msgroot, pInfo, CcnMsg)

   if ( block.length < 12 ) then
       local blk_chunk = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length)
       local value = blk_chunk:uint()
       local treeInfo = nametree:add(block.tvb(block.offset, block.size),
             "T_CHUNK(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

       msgroot:append_text(string.format("/%%%u", value))

       treeInfo:add(f_ccn.chunk, blk_chunk)

       if ( pInfo ) then
          local text = string.format("%s", pInfo.cols.info)
          pInfo.cols.info = string.format("%s/%%%u", text, value)
       end

       if ( CcnMsg ) then
          CcnMsg:append_text(string.format("/%%%u", value))
       end
   elseif ( 12 <= block.length ) then
       local treeInfo = nametree:add(block.tvb(block.offset, block.size),
             "T_FECPARAM(" .. block.type .. ") Length: " .. block.length)
       local  offset = block.offset + block.typeLen + block.lengthLen

       treeInfo:add(f_ccn.esl, block.tvb(offset, 2))
       offset = offset + 2

       local fssi = block.tvb(offset, 2)
       offset = offset + 2
       local treeFssi = treeInfo:add(f_ccn.fssi, fssi)
       treeFssi:add(f_ccn.s, fssi)
       treeFssi:add(f_ccn.m, fssi)
       treeFssi:add(f_ccn.codec, fssi)
       local val_codec = fssi(1, 1):uint()

       if ( val_codec < 3 ) then
           local blk_sbn = block.tvb(offset, 4)
           offset = offset + 4
           local val_sbn = blk_sbn:uint()
           treeInfo:append_text(string.format(" SBN=%u", val_sbn))
           treeInfo:add(f_ccn.sbn, blk_sbn)

           msgroot:append_text(string.format("/%%%u", val_sbn))
           if ( pInfo ) then
              pInfo.cols.info = string.format("%s/SBN=%%%u", string.format("%s", pInfo.cols.info), val_sbn)
           end

           if ( 12 == block.length ) then
              treeInfo:add(f_ccn.esi, block.tvb(offset, 1))
              treeInfo:add(f_ccn.sbl8, block.tvb(offset+1, 1))
           else
              treeInfo:add(f_ccn.sbl16, block.tvb(offset, 2))
           end
           offset = offset + 2

           treeInfo:add(f_ccn.padd, block.tvb(offset, 2))
           offset = offset + 2

           if ( 12 < block.length ) then
              treeInfo:add(f_ccn.ev, block.tvb(offset, block.length-12))
           end

       elseif ( val_codec == 3 ) then
           treeInfo:add(f_ccn.sb_from, block.tvb(offset, 4))
           local sbr_from = block.tvb(offset, 4):uint()
           offset = offset + 4

           treeInfo:add(f_ccn.sb_to, block.tvb(offset, 4))
           local sbr_to = block.tvb(offset, 4):uint()
           offset = offset + 4

           treeInfo:append_text(string.format(" SBR=%u-%u", sbr_from, sbr_to))

           msgroot:append_text(string.format("/%%%u-%u", sbr_from, sbr_to))
           if ( pInfo ) then
              pInfo.cols.info = string.format("%s/SBR=%%%u-%u", string.format("%s", pInfo.cols.info), sbr_from, sbr_to)
           end

           treeInfo:add(f_ccn.sbl16, block.tvb(offset, 2))
           offset = offset + 2

           treeInfo:add(f_ccn.padd, block.tvb(offset, 2))
           offset = offset + 2

           treeInfo:add(f_ccn.ev_seed, block.tvb(offset, 4))
           offset = offset + 4
       end

   end

   return treeInfo
end
--
-- T_REFLEXIVE_NAME
--
switch_Name_TLV[0x05] = function(block, nametree, msgroot, pInfo, CcnMsg)
   local val_hex = "0x"
   local blk_offset = block.offset + block.typeLen + block.lengthLen
   for i = 0, block.length - 1 do
      local value_int = block.tvb(blk_offset + i, 1):uint()
      val_hex = string.format("%s%x", val_hex, value_int)
   end

   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_REFLEXIVE_NAME(" .. block.type .. ") Length: " .. block.length .. " Value: \x22" .. val_hex .."\x22")

   msgroot:append_text(string.format("/RNP=%s", val_hex))

   if ( pInfo ) then
      local text = string.format("%s", pInfo.cols.info)
      pInfo.cols.info = string.format("%s/RNP=%s", text, val_hex)
   end

   if ( CcnMsg ) then
      CcnMsg:append_text(string.format("/RNP=%s", val_hex))
   end

   treeInfo:add(f_ccn.reflexive, val_hex)

   return treeInfo
end
--[[
-- T_CHUNK
--]]
switch_Name_TLV[0x10] = function(block, nametree, msgroot, pInfo, CcnMsg)
   local treeInfo = switch_Name_TLV[0x04](block, nametree, msgroot, pInfo, CcnMsg)

   return treeInfo
end

--
-- T_META
--
switch_Name_TLV[0x11] = function(block, nametree, msgroot, pInfo)
   local treeInfo = nametree:add(block.tvb(block.offset, block.size),
         "T_META(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)

   return treeInfo
end
-----------------------------------------------------
-- Discovery TLVs
-----------------------------------------------------
local switch_DiscoveryTLV = {}
--
-- T_DISC_CONTENT
--
switch_DiscoveryTLV[0x0000] = function(block, msginfo, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         string.format("T_DISC_CONTENT(%u) Length: %u ", block.type, block.length))

   local ObjectSize = block.tvb(block.offset + block.typeLen + block.lengthLen, 4)
   local ObjectCount = block.tvb(block.offset + block.typeLen + block.lengthLen+4, 4)
   local NumInterest = block.tvb(block.offset + block.typeLen + block.lengthLen+8, 4)
   local FirstSeqnum = block.tvb(block.offset + block.typeLen + block.lengthLen+12, 4)
   local LastSeqnum  = block.tvb(block.offset + block.typeLen + block.lengthLen+16, 4)
   local ElapsedCacheTime  = block.tvb(block.offset + block.typeLen + block.lengthLen+20, 4)
   local RemainCacheTime   = block.tvb(block.offset + block.typeLen + block.lengthLen+24, 4)
   local Tname       = getBlock(block.tvb, (block.offset + block.typeLen + block.lengthLen+28))

   treeInfo:add(ObjectSize,       string.format("       ObjectSize: %u", ObjectSize:uint()))
   treeInfo:add(ObjectCount,      string.format("      ObjectCount: %u", ObjectCount:uint()))
   treeInfo:add(NumInterest,      string.format("       # Interest: %u", NumInterest:uint()))
   treeInfo:add(FirstSeqnum,      string.format("      FirstSeqnum: %u", FirstSeqnum:uint()))
   treeInfo:add(LastSeqnum,       string.format("       LastSeqnum: %u", LastSeqnum:uint()))
   treeInfo:add(ElapsedCacheTime, string.format(" ElapsedCacheTime: %u", ElapsedCacheTime:uint()))
   treeInfo:add(RemainCacheTime,  string.format("  RemainCacheTime: %u", RemainCacheTime:uint()))

   local treeName = treeInfo:add(Tname.tvb(Tname.offset, Tname.size), "T_NAME(" .. Tname.type .. ") Length: " .. Tname.length)

   local offset   = Tname.offset + Tname.typeLen + Tname.lengthLen
   local valueLeft = Tname.length

   while valueLeft > 0 do
      local subTLVs = getBlock(Tname.tvb, offset)

      if ( nil == switch_Name_TLV[subTLVs.type] ) then
          -- no valid tlv found
          break
      end

      subTLVs.msginfo = switch_Name_TLV[subTLVs.type](subTLVs, treeName, treeInfo, nil)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_DISC_CONTENT_PUBLISHER
--
switch_DiscoveryTLV[0x0001] = function(block, msginfo, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         string.format("T_DISC_CONTENT_PUBLISHER(%u) Length: %u ", block.type, block.length))

   local ObjectSize = block.tvb(block.offset + block.typeLen + block.lengthLen, 4)
   local ObjectCount = block.tvb(block.offset + block.typeLen + block.lengthLen+4, 4)
   local NumInterest = block.tvb(block.offset + block.typeLen + block.lengthLen+8, 4)
   local FirstSeqnum = block.tvb(block.offset + block.typeLen + block.lengthLen+12, 4)
   local LastSeqnum  = block.tvb(block.offset + block.typeLen + block.lengthLen+16, 4)
   local ElapsedCacheTime  = block.tvb(block.offset + block.typeLen + block.lengthLen+20, 4)
   local RemainCacheTime   = block.tvb(block.offset + block.typeLen + block.lengthLen+24, 4)
   local Tname       = getBlock(block.tvb, (block.offset + block.typeLen + block.lengthLen+28))

   treeInfo:add(ObjectSize,       string.format("       ObjectSize: %u", ObjectSize:uint()))
   treeInfo:add(ObjectCount,      string.format("      ObjectCount: %u", ObjectCount:uint()))
   treeInfo:add(NumInterest,      string.format("       # Interest: %u", NumInterest:uint()))
   treeInfo:add(FirstSeqnum,      string.format("      FirstSeqnum: %u", FirstSeqnum:uint()))
   treeInfo:add(LastSeqnum,       string.format("       LastSeqnum: %u", LastSeqnum:uint()))
   treeInfo:add(ElapsedCacheTime, string.format(" ElapsedCacheTime: %u", ElapsedCacheTime:uint()))
   treeInfo:add(RemainCacheTime,  string.format("  RemainCacheTime: %u", RemainCacheTime:uint()))

   local treeName = treeInfo:add(Tname.tvb(Tname.offset, Tname.size), "T_NAME(" .. Tname.type .. ") Length: " .. Tname.length)

   local offset   = Tname.offset + Tname.typeLen + Tname.lengthLen
   local valueLeft = Tname.length

   while valueLeft > 0 do
      local subTLVs = getBlock(Tname.tvb, offset)

      if ( nil == switch_Name_TLV[subTLVs.type] ) then
          -- no valid tlv found
          break
      end

      subTLVs.msginfo = switch_Name_TLV[subTLVs.type](subTLVs, treeName, treeInfo, pInfo)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
-----------------------------------------------------
-- Message TLVs
-----------------------------------------------------
local switch_MessageTLV = {}
--
-- T_NAME
--
switch_MessageTLV[0] = function(block, msginfo, msgroot, pInfo, CcnMsg)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_NAME(" .. block.type .. ") Length: " .. block.length .. "   ")

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   if ( CcnMsg ) then
      CcnMsg:append_text(" ")
   end

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if ( subTLVs.type == 0 ) then
          valueLeft = (valueLeft - 1)
          offset    = (offset + 1)
          goto continue
      end
      if ( nil ~= switch_Name_TLV[subTLVs.type] ) then
          subTLVs.msginfo = switch_Name_TLV[subTLVs.type](subTLVs, treeInfo, msgroot, pInfo, CcnMsg)
      end
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
      ::continue::
   end

   return treeInfo
end
--
-- T_PAYLOAD
--
switch_MessageTLV[1] = function(block, msginfo, msgroot, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_PAYLOAD(" .. block.type .. ") Length: " .. block.length)

--   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):string()
--   treeInfo:append_text(string.format("\n%s", value))
   local blk_payload = block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4)
   treeInfo:add(f_ccn.payload, blk_payload)

   return treeInfo
end
--
-- T_KEYIDRESTR
--
switch_MessageTLV[2] = function(block, msginfo, msgroot, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_KEYIDRESTR(" .. block.type .. ") Length: " .. block.length)

   treeInfo:add(f_ccn.keyidrestr_hash_type,
                block.tvb(block.offset + block.typeLen + block.lengthLen, 2))
   local hash_length = block.tvb(block.offset + block.typeLen + block.lengthLen + 2, 2):uint()
   treeInfo:add(f_ccn.keyidrestr_hash_length,
                block.tvb(block.offset + block.typeLen + block.lengthLen + 2, 2))
   treeInfo:add(f_ccn.keyidrestr_hash_value,
                block.tvb(block.offset + block.typeLen + block.lengthLen + 2 + block.lengthLen, hash_length))

   return treeInfo
end
--
-- T_OBJHASHRESTR
--
switch_MessageTLV[3] = function(block, msginfo, msgroot, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_OBJHASHRESTR(" .. block.type .. ") Length: " .. block.length)

   treeInfo:add(f_ccn.objhash_hash_type,
                block.tvb(block.offset + block.typeLen + block.lengthLen, 2))
   local hash_length = block.tvb(block.offset + block.typeLen + block.lengthLen + 2, 2):uint()
   treeInfo:add(f_ccn.objhash_hash_length,
                block.tvb(block.offset + block.typeLen + block.lengthLen + 2, 2))
   treeInfo:add(f_ccn.objhash_hash_value,
                block.tvb(block.offset + block.typeLen + block.lengthLen + 2 + block.lengthLen, hash_length))

   return treeInfo
end
--
-- T_PAYLDTYPE
--
switch_MessageTLV[5] = function(block, msginfo, msgroot, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_PAYLDTYPE(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end
--
-- T_EXPIRY
--
switch_MessageTLV[6] = function(block, msginfo, msgroot, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint64()
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_EXPIRY(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   return treeInfo
end
--
-- T_ENDCHUNK
--
switch_MessageTLV[7] = function(block, msginfo, msgroot, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_ENDCHUNK(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   --- pInfo.cols.info = string.format("%s", pInfo.cols.info) .. " EndChunkNo=" .. value

   return treeInfo
end

--
-- T_END_CHUNK
--
switch_MessageTLV[12] = function(block, msginfo, msgroot, pInfo)
   local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length):uint()
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_END_CHUNK(" .. block.type .. ") Length: " .. block.length .. " Value: " .. value)

   --- pInfo.cols.info = string.format("%s", pInfo.cols.info) .. " EndChunkNo=" .. value

   return treeInfo
end

--
-- T_ORG
--
switch_MessageTLV[0x0FFF] = function(block, msginfo, msgroot, pInfo)
   local blk_epn = block.tvb(block.offset + block.typeLen + block.lengthLen, 3)
   local epn = blk_epn:uint()
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
---      string.format("T_ORG(0x%04x) Length: %u PEN: 0x%06x", block.type, block.length, epn))
         string.format("T_ORG(0x%04x) Length: %u", block.type, block.length))

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length
   local base_info = tostring(pInfo.cols.info)

   offset = offset + 3
   valueLeft = valueLeft - 3
   pInfo.cols.info = ""

   treeInfo:add(blk_epn, string.format("IANA Private Enterprise Numbers(0x%06x)", epn))

   while valueLeft > 0 do
      local subTLVs = getNictOrgBlock(block.tvb, offset)
-- print (string.format("#%d T_ORG@Message: type(0x%04x) Length=%d valueLeft=%d", pInfo.number, subTLVs.type, subTLVs.size, valueLeft))

      if (subTLVs == nil or subTLVs.size == nil) then
         -- no valid tlv found
         break
      end

      if ( switch_NictVenderTLV[subTLVs.type] ) then
          subTLVs.root = switch_NictVenderTLV[subTLVs.type](subTLVs, treeInfo, pInfo)
      else
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          treeInfo:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
      end

      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   local t_org_info = tostring(pInfo.cols.info)

-- print(string.format("%s [MSGORG:%s]", base_info, t_org_info))
   if (1 < t_org_info:len() ) then
      pInfo.cols.info = string.format("%s [MSGORG:%s]", base_info, t_org_info:sub(1-t_org_info:len()))
   else
      pInfo.cols.info = string.format("%s [MSGORG]", base_info)
   end

   return treeInfo
end

-----------------------------------------------------
-- Validation Algorithm TLVs
-----------------------------------------------------
local switch_ValidationAlgSubTLV = {}
local switch_ValidationAlgTLV = {}
--
-- T_CRC32C
--
switch_ValidationAlgTLV[2] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         "T_CRC32C(" .. block.type .. ") Length: " .. block.length)

   valdroot:append_text(" Validation with CRC32C")

   return treeInfo
end
--
-- T_HMAC_SHA256
--
switch_ValidationAlgTLV[4] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         string.format("T_HMAC_SHA256(%u) Length: %d", block.type, block.length))

   valdroot:append_text(" Validation with HMAC SHA256")

   return treeInfo
end
--
-- T_KEYID
--
switch_ValidationAlgSubTLV[0x0009] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         string.format("T_KEYID(%u) Length: %d", block.type, block.length))

   treeInfo:add(f_ccn.valid_alg_keyid,
                block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4))

   return treeInfo
end
--
-- T_PUBLICKEY
--
switch_ValidationAlgSubTLV[0x000B] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         string.format("T_PUBLICKEY(%u) Length: %d", block.type, block.length))

   treeInfo:add(f_ccn.valid_alg_publickey,
                block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4))

   return treeInfo
end
--
-- T_CERT
--
switch_ValidationAlgSubTLV[0x000C] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         string.format("T_CERT(%u) Length: %d", block.type, block.length))

   treeInfo:add(f_ccn.valid_alg_cert,
                block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4))

   return treeInfo
end
--
-- T_RSA_SHA256
--
switch_ValidationAlgTLV[5] = function(block, valdinfo, valdroot)
   local treeInfo = valdinfo:add(block.tvb(block.offset, block.size),
         string.format("T_RSA_SHA256(%u) Length: %d", block.type, block.length))
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   valdroot:append_text(" Validation with RSA SHA256")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if (subTLVs == nil or subTLVs.size == nil) then
          -- no valid tlv found
          break
      end
      if ( switch_ValidationAlgSubTLV[subTLVs.type] ) then
          subTLVs.root = switch_ValidationAlgSubTLV[subTLVs.type](subTLVs, treeInfo, valdroot)
      elseif ( nil == switch_NictVenderTLV[subTLVs.type] ) then
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          valdroot:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
      end

      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end


--
-- T_CERT_FORWARDER
--
switch_ValidationAlgTLV[0x1001] = function(block, valdinfo, valdroot)
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
switch_MessageType[1] = function(block, root, pInfo, CcnMsg)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_INTEREST(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   root:append_text(" INTEREST ")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if (subTLVs == nil or subTLVs.size == nil) then
         -- no valid tlv found
         break
      end
      if ( switch_MessageTLV[subTLVs.type] ) then
          subTLVs.root = switch_MessageTLV[subTLVs.type](subTLVs, treeInfo, root, pInfo, CcnMsg)
      else
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          treeInfo:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
          break
      end
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_OBJECT
--
switch_MessageType[2] = function(block, root, pInfo, CcnMsg)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_OBJECT(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   root:append_text(" OBJECT ")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if (subTLVs == nil or subTLVs.size == nil) then
         -- no valid tlv found
         break
      end
      if ( switch_MessageTLV[subTLVs.type] ) then
          subTLVs.root = switch_MessageTLV[subTLVs.type](subTLVs, treeInfo, root, pInfo, CcnMsg)
      else
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          treeInfo:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
      end

      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_VALIDATION_ALG
--
switch_MessageType[3] = function(block, root, pInfo, CcnMsg)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_VALIDATION_ALG(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if (subTLVs == nil or subTLVs.size == nil) then
         -- no valid tlv found
         break
      end
      if ( switch_ValidationAlgTLV[subTLVs.type] ) then
          subTLVs.root = switch_ValidationAlgTLV[subTLVs.type](subTLVs, treeInfo, root, pInfo, CcnMsg)
      else
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          treeInfo:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
      end

      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_VALIDATION_PAYLOAD
--
switch_MessageType[4] = function(block, root, pInfo, CcnMsg)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_VALIDATION_PAYLOAD(" .. block.type .. ") Length: " .. block.length)

   treeInfo:add(f_ccn.valid_payload,
                block.tvb(block.offset + block.typeLen + block.lengthLen, block.size-4))

   return treeInfo
end
-----------------------------------------------------
-- CCNInfo TLVs
-----------------------------------------------------
local switch_CCNInfoTLV = {}
--
-- T_NAME
--
switch_CCNInfoTLV[0x00] = function(block, msginfo, msgroot, pInfo, CcnMsg)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_NAME(" .. block.type .. ") Length: " .. block.length .. "   ")

   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   if ( CcnMsg ) then
      CcnMsg:append_text(" ")
   end

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if ( subTLVs.type == 0 ) then
          valueLeft = (valueLeft - 1)
          offset    = (offset + 1)
          goto continue
      end
      if ( nil ~= switch_Name_TLV[subTLVs.type] ) then
          subTLVs.msginfo = switch_Name_TLV[subTLVs.type](subTLVs, treeInfo, msgroot, pInfo, CcnMsg)
      end
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
      ::continue::
   end

   return treeInfo
end
--
-- T_DISC_REQ
--
switch_CCNInfoTLV[0x07] = function(block, msginfo, msgroot, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_DISC_REQ(" .. block.type .. ") Length: " .. block.length)
   local ArrivalTime  = block.tvb(block.offset + block.typeLen + block.lengthLen, 4)

   treeInfo:add(ArrivalTime,    string.format("   ArrivalTime: %u", ArrivalTime:uint()))

   if ( block.length <= 4 ) then
      return treeInfo
   end

   local offset   = block.offset + block.typeLen + block.lengthLen+4
   local treeNodeId = treeInfo:add(block.tvb(offset, block.length-4), "NodeIdentifier: ")
   local NodeTLVs = getBlock(block.tvb, block.offset + block.typeLen + block.lengthLen+4)

-- print (string.format("T_DISC_REPLY:block.offset=%d,length=%d", block.offset, block.length))
-- print (string.format("T_DISC_REPLY:NodeTLVs.offset=%d,length=%d,size=%d", NodeTLVs.offset, NodeTLVs.length, NodeTLVs.size))

   offset   = offset + 4
   local valueLeft = NodeTLVs.length

   while valueLeft > 0 do
      local subTLVs = getBlock(NodeTLVs.tvb, offset)
-- print (string.format("T_DISC_REPLY:subTLVs.offset=%d,type=%d,length=%d,size=%d", subTLVs.offset, subTLVs.type, subTLVs.length, subTLVs.size))

      if ( nil ~= switch_Nodeid_SubTLV[subTLVs.type] ) then
          subTLVs.msginfo = switch_Nodeid_SubTLV[subTLVs.type](subTLVs, treeNodeId, treeInfo)
      end
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
      ::continue::
   end

   return treeInfo
end
--
-- T_DISC_REPLY
--
switch_CCNInfoTLV[0x08] = function(block, msginfo, msgroot, pInfo)
   local treeInfo = msginfo:add(block.tvb(block.offset, block.size),
         "T_DISC_REPLY(" .. block.type .. ") Length: " .. block.length)

   local ArrivalTime  = block.tvb(block.offset + block.typeLen + block.lengthLen, 4)
   treeInfo:add(ArrivalTime,    string.format("   ArrivalTime: %u", ArrivalTime:uint()))

   if ( block.length <= 4 ) then
      return treeInfo
   end

   local offset   = block.offset + block.typeLen + block.lengthLen+4
   local treeNodeId = treeInfo:add(block.tvb(offset, block.length-4), "NodeIdentifier: ")
   local NodeTLVs = getBlock(block.tvb, block.offset + block.typeLen + block.lengthLen+4)

-- print (string.format("T_DISC_REPLY:block.offset=%d,length=%d", block.offset, block.length))
-- print (string.format("T_DISC_REPLY:NodeTLVs.offset=%d,length=%d,size=%d", NodeTLVs.offset, NodeTLVs.length, NodeTLVs.size))

   offset   = offset + 4
   local valueLeft = NodeTLVs.length

   while valueLeft > 0 do
      local subTLVs = getBlock(NodeTLVs.tvb, offset)
-- print (string.format("T_DISC_REPLY:subTLVs.offset=%d,type=%d,length=%d,size=%d", subTLVs.offset, subTLVs.type, subTLVs.length, subTLVs.size))

      if ( nil ~= switch_Nodeid_SubTLV[subTLVs.type] ) then
          subTLVs.msginfo = switch_Nodeid_SubTLV[subTLVs.type](subTLVs, treeNodeId, treeInfo)
      end
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
      ::continue::
   end

   return treeInfo
end
switch_CCNInfoTLV[0x0d] = function(block, msginfo, msgroot, pInfo)
   return switch_CCNInfoTLV[0x07](block, msginfo, msgroot, pInfo)
end
switch_CCNInfoTLV[0x0e] = function(block, msginfo, msgroot, pInfo)
   return switch_CCNInfoTLV[0x08](block, msginfo, msgroot, pInfo)
end
--
-- T_DISCOVERY
--
switch_MessageType[5] = function(block, root, pInfo, CcnMsg)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_DISCOVERY(" .. block.type .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   root:append_text(" DISCOVERY ")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if (subTLVs == nil or subTLVs.size == nil) then
         -- no valid tlv found
         break
      end
      if ( switch_CCNInfoTLV[subTLVs.type] ) then
          subTLVs.root = switch_CCNInfoTLV[subTLVs.type](subTLVs, treeInfo, root, pInfo, CcnMsg)
      else
          -- no valid tlv found
          local value = subTLVs.tvb(subTLVs.offset + subTLVs.typeLen + subTLVs.lengthLen, subTLVs.length)
          treeInfo:add(subTLVs.tvb(subTLVs.offset, subTLVs.size),
                 string.format("T_X(0x%04x) Length:%d Value:", subTLVs.type, subTLVs.length) .. value)
          break
      end

      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end
--
-- T_HOPAUTH_CERT
--
switch_MessageType[7] = function(block, root, pInfo, CcnMsg)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_HOPAUTH_CERT(" .. block.type .. ") Length: " .. block.length)

   return treeInfo
end

--
-- T_NOTIFY
--
switch_MessageType[0x4321] = function(block, root, pInfo, CcnMsg)
   local treeInfo = root:add(block.tvb(block.offset, block.size),
         "T_NOTIFY(" .. string.format("0x%x", block.type) .. ") Length: " .. block.length)
   local offset   = block.offset + block.typeLen + block.lengthLen
   local valueLeft = block.length

   root:append_text(" Controller Notify ")

   while valueLeft > 0 do
      local subTLVs = getBlock(block.tvb, offset)

      if ( nil == switch_ControllerTLV[subTLVs.type] ) then
          -- no valid tlv found
          break
      end

      subTLVs.root = switch_ControllerTLV[subTLVs.type](subTLVs, treeInfo, root)
      valueLeft = valueLeft - subTLVs.size
      offset    = offset    + subTLVs.size
   end

   return treeInfo
end

function addMessageInfo(block, root, pInfo, CcnMsg) -- may be add additional context later
   if ( switch_MessageType[block.type] ) then
      block.root = switch_MessageType[block.type](block, root, pInfo, CcnMsg)
   else
      local value = block.tvb(block.offset + block.typeLen + block.lengthLen, block.length)
      block.root = root:add(block.tvb(block.offset, block.size),
         string.format("T_X(0x%04x) Length:%d Value:", block.type, block.length) .. value)
   end

   return block.root
end

-----------------------------------------------------
-----------------------------------------------------

function getCcnHeader(tvb, offset)
   local CcnVersion = tvb(offset,   1):uint()
   local PktType    = tvb(offset+1, 1):uint()
   local PktLength  = tvb(offset+2, 2):uint()
   local Flags      = tvb(offset+6, 1):uint()
   local HdrLength  = tvb(offset+7, 1):uint()
   local block = {}

   if ((CcnVersion ~= 0x01) and (CcnVersion ~= 0xf0)) then
      return nil
   end

--     Code         Type name
--   ========      =====================
--     %x00        PT_INTEREST [1]
--     %x01        PT_CONTENT [1]
--     %x02        PT_RETURN [1]
--     %x03        PT_CCNINFO_REQUEST
--     %x04        PT_CCNINFO_REPLY
   if (0x10 < PktType) then
      return nil
   end
   if (HdrLength < 8) then
      return nil
   end
   if (PktLength <= HdrLength) then
      return nil
   end
   if ((Flags ~= 0x00)) then
      return nil
   end
   if (16384 < PktLength) then
      print ("Error:PktLength=" .. PktLength)
      return nil
   end

   block.tvb = tvb
   block.offset = offset
--   block.type = tvb(offset+1, 1):uint()
--   block.size = tvb(offset+2, 2):uint()
   block.type = PktType
   block.size = PktLength

   if ( (offset + block.size) >= tvb:len() ) then
      block.length = tvb:len() - offset
   else
      block.length = block.offset + block.size + 4
   end

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

-- print (" offset=".. block.offset .. " length=".. block.length .. " size=".. block.size)

   return block
end

function getOptHdrBlock(tvb, offset)
   if offset >= tvb:len() then
      return nil
   end

   local block = {}
   block.tvb = tvb
   block.offset = offset

   block.type,   block.typeLen   = tvb(offset+0, 2):uint(), 2
   block.length, block.lengthLen = tvb(offset+2, 2):uint(), 2

   block.size = block.typeLen + block.lengthLen + block.length

-- print ("getOptHdrBlock:: offset=".. block.offset .. " type=".. block.type .. " length=".. block.length .. " size=".. block.size)

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
   if block.type >= 0x2000 then
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
local CCNFIXHDR_LENGTH = 8

-- CCN protocol dissector function
function ccn_dissector(CcnMsg, pInfo, root) -- Tvb, Pinfo, TreeItem
   local OpInfo = pInfo
   OpInfo.cols.info = ""

   -- Create Tree Items
   CcnMsg.tree = root:add(p_ccn, CcnMsg.tvb(CcnMsg.offset, CcnMsg.size))

   local block = getBlock(CcnMsg.tvb, CcnMsg.offset+CCNFIXHDR_LENGTH)
   if (block == nil or block.size == nil) then
      -- no valid CCN header found
      return 0
   end

   CcnMsg.elements = block

   -- Create FixedHeader Tree
   CcnMsg.elements.tree = addCcnFixHdrInfo(CcnMsg, CcnMsg.tree, OpInfo)
   local pktInfo = string.format("%s", OpInfo.cols.info)
-- print (string.format("OpInfo.cols.info=%s", OpInfo.cols.info))

   local nBytesLeft = 0

   -- Create OptionHeader Section
   if ( CCNFIXHDR_LENGTH < CcnMsg.HeaderLength ) then
      block.size = CcnMsg.HeaderLength - CCNFIXHDR_LENGTH
      block.tree = CcnMsg.tree:add(block.tvb(block.offset, block.size),
                                   "OptionHeader Length: " .. block.size)

      local Oph = block
      nBytesLeft = Oph.size

      while (0 < nBytesLeft) do
         block = getOptHdrBlock(Oph.tvb, Oph.offset + (Oph.size - nBytesLeft))
         local queue = {block}

         while (#queue > 0) do
            local block = queue[1]

            table.remove(queue, 1)
            if (0 < block.size) then

                block.elements = getSubBlocks(block)

                local subtree = addOptHdrInfo(block, Oph.tree, OpInfo)
                if (block.elements ~= nil) then
                   for i, subBlock in pairs(block.elements) do
                      subBlock.tree = subtree
                   end
                end
            end
            nBytesLeft = nBytesLeft - block.size
         end
      end
   end

-- print (string.format("OpInfo.cols.info=%s", OpInfo.cols.info))
-- print (string.format("pInfo.cols.info=%s", pInfo.cols.info))

   MsgBlock = getBlock(CcnMsg.tvb, CcnMsg.offset+CcnMsg.HeaderLength)
   MsgBlock.size = CcnMsg.PayloadLength
   MsgBlock.tree = CcnMsg.tree:add(MsgBlock.tvb(MsgBlock.offset, CcnMsg.PayloadLength),
                                   "Messages Length: " .. MsgBlock.size)

   offset = MsgBlock.offset
   nBytesLeft = CcnMsg.PacketLength - MsgBlock.offset

   -- Create Message Item Tree
   while (0 < nBytesLeft) do
      block = getBlock(MsgBlock.tvb, MsgBlock.offset)

-- print (pInfo.number .. ":: blocktype: " .. block.type .. " of length " .. block.size .. " bytesLeft: " .. nBytesLeft)

      block.elements = getSubBlocks(block)
      local subtree = addMessageInfo(block, MsgBlock.tree, pInfo, CcnMsg.tree)

      if (block.elements ~= nil) then
         for i, subBlock in pairs(block.elements) do
            subBlock.tree = subtree
         end
      end

      nBytesLeft = nBytesLeft - block.size
      MsgBlock.offset = MsgBlock.offset + block.size
   end

   pInfo.cols.protocol = p_ccn.name
--   pInfo.cols.info = string.format("%s%s", pktInfo, pInfo.cols.info)

   if (nBytesLeft > 0 and block ~= nil and block.size ~= nil and block.size > nBytesLeft) then
      pInfo.desegment_offset = tvb:len() - nBytesLeft

      -- Originally, I set desegment_len to the exact lenght, but it mysteriously didn't work for TCP
      -- pInfo.desegment_len = block.size -- this will not work to desegment TCP streams
      pInfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
   end
end

function p_ccn.dissector(tvb, pInfo, root) -- Tvb, Pinfo, TreeItem
   if (tvb:len() ~= tvb:reported_len()) then
-- print (pInfo.number .. " #####")
      return 0 -- ignore partially captured packets
      -- this can/may be re-enabled only for unfragmented UDP packets
   end

   -- Create Message Item Tree
   while (tvb:len() > 0) do
       local len = tvb:len()
       if tvb:len() < CCNFIXHDR_LENGTH then
           -- Since there is no required data length in the header part, append to the subsequent packet.
-- print (pInfo.number .. " DESEGMENT_ONE_MORE_SEGMENT #1")
           pInfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
           return tvb:len() - CCNFIXHDR_LENGTH
       end

       local ok, CcnMsg = pcall(findCcnPacket, tvb)
       if (not ok) then
--   print (pInfo.number .. " DESEGMENT_ONE_MORE_SEGMENT #2")
           pInfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
           return tvb:len() - CCNFIXHDR_LENGTH
       end

       if (CcnMsg == nil or CcnMsg.offset == nil) then
          -- no valid CCN packets found
--   print (pInfo.number .. " DESEGMENT_ONE_MORE_SEGMENT #3")
           pInfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
           return tvb:len() - CcnMsg.size
       end

-- print (pInfo.number .. " (2062):: len: " .. len .. ":: CcnMsg.offset: " .. CcnMsg.offset .. " CcnMsg.size " .. CcnMsg.size.. " CcnMsg.length " .. CcnMsg.length)

       if (tvb:len() < CcnMsg.size) then
          -- no valid CCN packets found
-- print (pInfo.number .. " DESEGMENT_ONE_MORE_SEGMENT #4")
           pInfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
           return tvb:len() - CcnMsg.size
       end

      ccn_dissector(CcnMsg, pInfo, root)

      if ( tvb:len() == CcnMsg.size ) then
        break
      end

      tvb = tvb:range(CcnMsg.size)

   end

end

local udpDissectorTable = DissectorTable.get("udp.port")
udpDissectorTable:add("9896", p_ccn)

local tcpDissectorTable = DissectorTable.get("tcp.port")
tcpDissectorTable:add("9896", p_ccn)

local ethernetDissectorTable = DissectorTable.get("ethertype")
ethernetDissectorTable:add(0x0801, p_ccn)

local pppDissectorTable = DissectorTable.get("ppp.protocol")
pppDissectorTable:add(0x0025, p_ccn)

io.stderr:write("cefore.lua is successfully loaded\n")
