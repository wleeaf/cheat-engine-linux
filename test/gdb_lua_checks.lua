-- Run through the production cescan Lua runner against an independent stub or
-- a real stopped ARM64 QEMU CPU. The harness provides the endpoint and mode.
local base = CE_GDB_QEMU and 0x40000000 or 0x1000
local order = CE_GDB_QEMU and 'little' or 'big'
local options = {byteOrder=order, pointerWidth=CE_GDB_QEMU and 8 or 4,
                 timeoutMs=1000, regions={{base=base, size=4096}}}
local function expectFailure(host, port, opts)
  local ok, err = connectToGdb(host, port, opts)
  assert(ok == nil and type(err) == 'string' and #err > 0, 'invalid options accepted')
end
expectFailure('invalid.invalid', 1, {pointerWidth=3})
expectFailure('invalid.invalid', 65536, {})
expectFailure('invalid.invalid', 1, {regions={{base=0, size=-1}}})
expectFailure('invalid.invalid', 1, setmetatable({}, {__index=function() error('getter failed') end}))
expectFailure('invalid.invalid', 1, {regions={setmetatable({}, {__index=function() error('range getter failed') end})}})
assert(getTargetInfo() == nil)
assert(connectToGdb(CE_GDB_HOST, CE_GDB_PORT, options))
local info = assert(getTargetInfo())
assert(info.live and info.transport == 'gdb' and info.program.architecture == 'ARM64')
assert(info.program.pointerWidth == options.pointerWidth and info.host.architecture == 'unknown')
assert(getOpenedProcessID() == 0 and getPointerSize() == options.pointerWidth)
assert(pause()==false and unpause()==false and getProcessDir()=='')
local hostSample, hostSampleError = branchMap(0)
assert(hostSample==nil and hostSampleError:find('local'), 'guest identifiers reached the host perf backend')
expectFailure('invalid.invalid', 1, {byteOrder='nonsense'})
expectFailure('invalid.invalid', 1, {regions={{base=-1, size=2}}})
expectFailure('bad\0host', 1, {})
assert(getTargetInfo().live and getTargetInfo().transport == 'gdb', 'failed connection replaced the target')
local regs = assert(getGdbRegisterInfo())
local widths = {}
for _, reg in ipairs(regs) do widths[reg.name] = reg.bits end
assert(widths.x0 == 64 and widths.pc == 64)
local x0, pc = assert(readGdbRegister('x0')), assert(readGdbRegister('pc'))
assert(#x0 == 8 and #pc == 8)
assert(writeGdbRegister('x0', 'short') == nil and readGdbRegister('x0') == x0)
assert(readGdbRegister('absent-register') == nil)
local original = assert(readBytes(base,4096,true))
local function sameRAM()
  local current = assert(readBytes(base,4096,true))
  for i=1,4096 do assert(current[i] == original[i], 'RAM restoration mismatch at '..i) end
end
assert(writeInteger(base+128, 0x12345678) and readInteger(base+128) == 0x12345678)
local bytes = assert(readBytes(base+128,4,true))
assert(bytes[1] == (CE_GDB_QEMU and 0x78 or 0x12) and bytes[4] == (CE_GDB_QEMU and 0x12 or 0x78))
assert(writePointer(base+144, base+256) and readPointer(base+144) == base+256)
if not CE_GDB_QEMU then assert(readInteger(base+4094) == nil, 'short word invented bytes') end
-- Production MemScan reads the program data format and exposes captured values.
local scan = createMemScan()
assert(scan:firstScan(0,2,'305419896',base+128,base+131,1))
assert(scan:getFoundCount()==1 and scan:getAddress(0)==base+128 and scan:getValue(0)=='305419896')
assert(writeInteger(base+128,0x12345679))
assert(scan:nextScan(7,2,'0',base+128,base+131,1))
assert(scan:getFoundCount()==1 and scan:getValue(0)=='305419897' and scan:getValue(0,true)=='305419896')
assert(scan:getValue(-1)==nil and scan:getValue(1)==nil)
assert(scan:firstScan(0,13,tostring(base+256),base+144,base+144+options.pointerWidth-1,1))
assert(scan:getFoundCount()==1 and scan:getValue(0)==string.format('0x%x',base+256))
assert(writeFloat(base+176,2.5))
assert(scan:firstScan(0,4,'2.5',base+176,base+179,1) and scan:getValue(0)=='2.5')
assert(writeFloat(base+176,3.5))
assert(scan:nextScan(5,4,'0',base+176,base+179,1) and scan:getValue(0)=='3.5' and scan:getValue(0,true)=='2.5')
local unicode = order=='big' and {0,0x41,3,0xa9,0xd8,0x3d,0xde,0} or {0x41,0,0xa9,3,0x3d,0xd8,0,0xde}
writeBytes(base+200,unicode)
assert(scan:firstScan(0,7,'AΩ😀',base+200,base+207,1))
assert(scan:getFoundCount()==1 and scan:getValue(0)=='AΩ😀')
-- Encoded data can choose a format independently of the CPU's default ABI.
writeBytes(base+228,{0x11,0x22,0x33,0x44})
local format={byteOrder='big',pointerWidth=4}
assert(scan:firstScan(0,13,'0x11223344',base+228,base+231,1,nil,format))
assert(scan:getFoundCount()==1 and scan:getValue(0)=='0x11223344')
assert(scan:nextScan(8,13,'0',base+228,base+231,1,nil,format) and scan:getFoundCount()==1)
local function invalidFormat(opts)
  local ok,err=scan:firstScan(0,2,'0',base,base+3,1,nil,opts)
  assert(ok==false and type(err)=='string' and #err>0)
  assert(scan:getFoundCount()==1 and scan:getValue(0)=='0x11223344','failed scan replaced captured values')
end
invalidFormat({byteOrder='wrong'})
invalidFormat({pointerWidth=3})
invalidFormat(setmetatable({}, {__index=function() error('scan option getter failed') end}))
for _,case in ipairs({{2,'12oops'},{13,'bad-pointer'},{4,'2.5oops'},{8,'ZZ'}}) do
  local ok,err=scan:firstScan(0,case[1],case[2],base,base+7,1)
  assert(ok==false and type(err)=='string')
  assert(scan:getFoundCount()==1 and scan:getValue(0)=='0x11223344')
end
assert(scan:firstScan(0,2,'0x11223344',base+228,base+231,1,nil,format))
assert(scan:getValue(0)=='287454020','Lua hexadecimal integer needle was truncated')
local pointerFormula='return #current == '..options.pointerWidth
assert(scan:firstScan(10,13,pointerFormula,base+144,base+143+options.pointerWidth,1))
assert(scan:getFoundCount()==1 and #scan:getValue(0)==3*options.pointerWidth-1,'custom pointer formula used frontend width')
assert(scan:firstScan(10,13,'return #current==4',base+228,base+231,1,nil,format))
assert(scan:getFoundCount()==1 and scan:getValue(0)=='11 22 33 44','custom pointer formula ignored explicit width')
-- All scans retain actual numeric candidates, including short region tails.
writeBytes(base+4095,{42})
assert(scan:firstScan(0,10,'42',base+4095,base+4095,1))
assert(scan:getFoundCount()==1 and #scan:getValueTypes(0)==1 and scan:getValueTypes(0)[1]==0)
assert(scan:getValue(0)=='2A' and scan:getValue(0,false,0)=='42')
for _,bad in ipairs({'42oops','2.5oops','1e9999','42\0suffix'}) do
  local ok,err=scan:firstScan(0,10,bad,base+4095,base+4095,1)
  assert(ok==false and err:find('All scan') and scan:getValue(0,false,0)=='42')
end
assert(scan:nextScan(1,10,'41.5',base+4095,base+4095,1,nil,{value2='42.5'}))
assert(scan:getValue(0,false,0)=='42')
writeBytes(base+4095,{43})
assert(scan:nextScan(5,10,'0',base+4095,base+4095,1))
assert(scan:getValue(0,false,0)=='43' and scan:getValue(0,true,0)=='42')
assert(writeFloat(base+176,2.5))
assert(scan:firstScan(0,10,'2.5',base+176,base+179,1))
assert(scan:getFoundCount()==1 and #scan:getValueTypes(0)==1 and scan:getValueTypes(0)[1]==4)
assert(scan:getValue(0,false,4)=='2.5')
assert(writeFloat(base+176,3.5))
assert(scan:nextScan(5,10,'0',base+176,base+179,1))
assert(scan:getValue(0,false,4)=='3.5' and scan:getValue(0,true,4)=='2.5')
local missing,missingError=scan:getValue(0,false,2)
assert(missing==nil and missingError:find('candidate'))
assert(scan:nextScan(0,4,'3.5',base+176,base+179,1) and scan:getValue(0)=='3.5')
assert(scan:firstScan(0,10,'4.2e1',base+4095,base+4095,1) and scan:getFoundCount()==0)
assert(scan:firstScan(0,10,'0x2B',base+4095,base+4095,1) and scan:getValue(0,false,0)=='43')
print('GDB_LUA_ALL_NUMBERS=PASSED strict input, decimal bounds, scientific and hexadecimal values')
assert(writeFloat(base+176,0.05))
local rounded={rounding='rounded'}
assert(scan:firstScan(0,4,'1e-1',base+176,base+179,4,nil,rounded) and scan:getValue(0)=='0.05')
assert(scan:nextScan(0,4,'0.1',base+176,base+179,4,nil,rounded) and scan:getFoundCount()==1)
for _,opts in ipairs({{rounding='wrong'},{tolerance=-1},{tolerance=math.huge}}) do
  local ok,err=scan:firstScan(0,4,'0.1',base+176,base+179,4,nil,opts)
  assert(ok==false and type(err)=='string' and scan:getValue(0)=='0.05')
end
assert(scan:firstScan(1,4,'0.01',base+176,base+179,4,nil,{value2='0.09'}) and scan:getFoundCount()==1)
assert(scan:firstScan(0,10,'0.1',base+176,base+179,4,nil,rounded) and scan:getValue(0,false,4)=='0.05')
assert(writeFloat(base+176,16777216))
assert(scan:firstScan(0,4,'16777217',base+176,base+179,4,nil,{rounding='truncated'}) and scan:getFoundCount()==0)
assert(scan:firstScan(0,4,'16777217',base+176,base+179,4,nil,{rounding='extreme',tolerance=0.000001}) and scan:getFoundCount()==0)
assert(writeDouble(base+184,0.05))
assert(scan:firstScan(0,5,'0.1',base+184,base+191,8,nil,rounded) and scan:getValue(0)=='0.05')
assert(scan:firstScan(1,2,'305419896',base+128,base+131,4,nil,{value2='305419898'}) and scan:getValue(0)=='305419897')
print('GDB_LUA_FLOAT_ROUNDING=PASSED decimal/scientific boundaries, modes, upper values and invalid-option recovery')
print('GDB_LUA_ALL_SCANS=PASSED numeric candidates, short tails, first samples and concrete type selection')
print('GDB_LUA_SCANS=PASSED numeric, pointer, float, Unicode, snapshots and explicit data formats')

local edited = string.char(1,2,3,4,5,6,7,8)
assert(writeGdbRegister('x0',edited) and readGdbRegister('x0') == edited)
if CE_GDB_QEMU then
  assert(widths.v0 == 128)
  if CE_GDB_BANK_ONLY then
    local value, err = readGdbRegister('v0')
    assert(value==nil and err:find('unavailable'), 'omitted vectors were fabricated')
  else
    local originalVector = assert(readGdbRegister('v0'))
    local vector = string.char(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)
    assert(#originalVector == 16 and writeGdbRegister('v0',vector) and readGdbRegister('v0') == vector)
    assert(writeGdbRegister('v0',originalVector) and readGdbRegister('v0') == originalVector)
  end
end
assert(writeGdbRegister('x0',x0) and writeGdbRegister('pc',pc))
assert(readGdbRegister('x0') == x0 and readGdbRegister('pc') == pc)
writeBytes(base,original); sameRAM()
assert(disconnectProcess())
assert(getTargetInfo() == nil and readInteger(base) == nil and readGdbRegister('x0') == nil)
print('GDB_LUA_RESULT=PASSED actual RAM and XML register state restored')
