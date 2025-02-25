import struct
import io
import os
import shelve
import numpy as np
import sys
import time
from collections import defaultdict
import threading
def to_uint32b(value):
    return value & 0xFFFFFFFF

class Record:
    def __init__(self, N=0, PC=0, EA=0):
        self.N = N
        self.PC = PC
        self.EA = EA

class BlockHeader:
    def __init__(self, Bytes=0, Recs=0):
        self.Bytes = Bytes
        self.Recs = Recs

class Trace:
    def __init__(self, read_seeker, trans, fsize):
        self.r = read_seeker
        self.trans = trans
        self.fsize = fsize
        self.recno = 0
        self.hdr = BlockHeader()
        self.blockEnd = 0
        self.blockData = bytearray()
        self.blockReader = None
        self.rec = Record()
        self.blockNum = 0
        self.begin_t = time.time()
        self.lock = threading.RLock()

    def read_block_header(self):
        header_data = self.r.read(16)
        if len(header_data) != 16:
            raise IOError("Failed to read block header")
        self.hdr.Bytes, self.hdr.Recs = struct.unpack('<QQ', header_data)
        self.blockEnd = self.recno + self.hdr.Recs

    def read_block_content(self):
        size = self.hdr.Bytes - 16
        if size > len(self.blockData):
            self.blockData = bytearray(size * 2)
        self.blockData = self.r.read(size)
        if len(self.blockData) != size:
            raise IOError("Failed to read block content")
        self.blockReader = io.BytesIO(self.blockData)
        self.rec = Record()

    def read_record(self):
        deltaPC = self.read_varint()
        deltaEA = self.read_varint()
        self.rec.N = self.recno
        self.rec.PC += to_uint32b(deltaPC)
        self.rec.PC = to_uint32b(self.rec.PC)
        self.rec.EA += to_uint32b(deltaEA)
        self.rec.EA = to_uint32b(self.rec.EA)
        self.recno += 1

    def read_varint(self):
        s = 0
        uresult = 0
        MAX_VARINT_LEN64 = 10
        for i in range(MAX_VARINT_LEN64):
            byte = self.blockReader.read(1)
            if len(byte) == 0:
                raise IOError("Unexpected EOF while reading varint")
            b = byte[0]
            if b < 0x80:
                if i == MAX_VARINT_LEN64 - 1 and b > 1:
                    raise ValueError("varint overflow")
                uresult = uresult | (b << s)
                break
            uresult |= (b & 0x7F) << s
            s += 7

        result = (uresult >> 1)
        if uresult&1 != 0:
            result = ~result
        return result

    def seek(self, recno):
        self.r.seek(0)
        self.recno = 0
        while True:
            self.read_block_header()
            if self.blockEnd > recno:
                break
            self.r.seek(self.hdr.Bytes - 16, io.SEEK_CUR)
            self.recno += self.hdr.Recs
        self.read_block_content()
        while self.recno < recno:
            self.read_record()

    def read_records(self, recs):
        for i in range(len(recs)):
            if self.recno == self.blockEnd:
                if self.blockNum % 10 == 0:
                    current_pos = self.r.tell() / float(1024 * 1024)
                    self.trans.update_shelve_set()
                    end_t = time.time()
                    if self.blockNum > 0:
                        print("sync " + str(self.blockNum) + " blocks, loaded " + str(current_pos * 100 // self.fsize) + "%, ftell " + str(self.r.tell()) + ", speed " + str((end_t - begin_t) // self.blockNum) + "s/block")
                    self.begin_t = end_t
                self.blockNum += 1
                self.read_block_header()
                self.read_block_content()
            self.read_record()
            recs[i] = self.rec
        return len(recs)

    def get_block(self, recs, begin, nums):
        self.lock.aquire()
        beginrecno = self.recno
        self.read_block_header()
        self.read_block_content()
        while True:
            if self.recno == self.blockEnd:
                if self.blockNum % 1 == 0:
                    current_pos = self.r.tell() / float(1024 * 1024)
                    self.trans.update_shelve_set()
                    end_t = time.time()
                    print("sync " + str(self.blockNum) + " blocks, loaded " + str(current_pos * 100 // self.fsize) + "%, ftell " + str(self.r.tell()) + ", speed " + str(self.blockNum // (end_t - begin_t)) + "blocks/s")
                    self.begin_t = end_t
                    self.blockNum += 1
                self.read_block_header()
                self.read_block_content()
            self.read_record()
            recs[i] = self.rec
        return len(recs)

class TransMemAccess:
	def __init__(self, heap_file, mem_access_file, out_file):
		self.heap_file = heap_file
		self.mem_access_file = mem_access_file
		self.start = 0
		self.out_file = out_file
		self.prepare()
    
	def base_adjust(self, hexaddr):
		return hexaddr - self.start + 0x10000

	def base_adjust_str(self, hexaddr):
		return hex(int(hexaddr, 16) - self.start + 0x10000)[2:]

	def prepare(self):
		# collect heap objects
		heapinfo = {}
		start = -1
		end = -1
		with open(self.heap_file, "r") as f:
			lines = f.readlines()
			i = 0
			while i < len(lines):
				if lines[i].startswith("img"):
					line = lines[i][5:]
					start, end = line.split(", ")
					start = int(start, 16)
					self.start = start
					end = int(end, 16)
					self.end = end
					i += 1
					continue
				else:
					items = lines[i].strip().split(", ")
					if items[0] == "malloc" or items[0] == "calloc":
						instr = items[1]
						if int(instr, 16) > end or int(instr, 16) < start:
							i += 2
							continue
						if lines[i] == lines[i + 1]:
							i += 1
							continue
						instr = self.base_adjust_str(instr)
						size = items[3]
						addr = lines[i+1].strip()
						heapinfo[addr] = [instr, size]
						i += 2
					elif items[0] == "realloc":
						instr = items[1]
						instr = self.base_adjust_str(instr)
						addr = items[3]
						size = items[4]
						if addr in heapinfo:
							heapinfo[addr][1] = size
						else:
							heapinfo[addr] = [instr, size]
						i += 1
					else:
						i += 1

		# heap object intervals
		intervals = []
		for addr in heapinfo:
			size = heapinfo[addr][1]
			intervals.append(int(addr,16))
			intervals.append(int(addr,16) + int(size,16) - 1)
		intervals.sort()
		self.intervals = intervals
		self.heapinfo = heapinfo

		# read ground truth mem access, translate to aloc
		self.mem_access_gt = shelve.open(self.out_file + '.shl')
		self.mem_access_gt_dict = defaultdict(set)
		self.large_obj = defaultdict(dict)
		self.stackframe = []
		self.stackframe2func = {}
		self.largesize = 100000
		
	def infer_stride(self, addr, newset):
		if addr in self.large_obj:
			for newobj in newset:
				key = newobj[0]
				newoffset = newobj[1]
				if key in self.large_obj[addr]:
					stride, minoffset, maxoffset = self.large_obj[addr][key]
					if (newoffset - minoffset) % stride != 0:
						stride = min(stride, (newoffset - minoffset) % stride)
					minoffset = min(minoffset, newoffset)
					maxoffset = max(maxoffset, newoffset)
					self.large_obj[addr][key] = (stride, minoffset, maxoffset)
		else:
			stride = sys.maxsize
			objmap = defaultdict(set)
			addr_str = hex(addr)
			allaccess = self.mem_access_gt[addr_str]
			allaccess.update(newset)
			for obj in allaccess:
				key = obj[0]
				newoffset = obj[1]
				objmap[key].add(newoffset)
			for key in objmap:
				if len(objmap[key]) < self.largesize:
					continue
				offsets = list(objmap[key])
				offsets.sort()
				for idx in range(len(offsets)-1):
					stride = min(stride, offsets[idx+1] - offsets[idx])
				self.large_obj[addr][key] = (stride, offsets[0], offsets[-1])


	def update_shelve_set(self):
		for addr in self.mem_access_gt_dict:
			addr_str = hex(addr)
			if addr_str in self.mem_access_gt:
				if addr in self.large_obj:
					self.infer_stride(addr, self.mem_access_gt_dict[addr])
					continue
				old = self.mem_access_gt[addr_str]
				if len(old) > self.largesize: # avoid frequent read/write for large volumn offsets
					self.infer_stride(addr, self.mem_access_gt_dict[addr])
				else:
					old.update(self.mem_access_gt_dict[addr])
					self.mem_access_gt[addr_str] = old
			else:
				self.mem_access_gt[addr_str] = self.mem_access_gt_dict[addr]
		self.mem_access_gt.sync()
		self.mem_access_gt_dict.clear()

	def finish(self):
		with open(self.heap_file[:-4] + "_largeobj", "w") as f:
			f.write(str(self.large_obj))
		# for addr in self.large_obj:
		# 	old = self.mem_access_gt[addr]
		# 	for key in self.large_obj[addr]:
		# 		stride, minoffset, maxoffset = self.large_obj[addr][key]
		# 		keys = key.split("_")
		# 		if len(keys) == 2:
		# 			pos, start = key.split("_")
		# 			for offset in range(minoffset, maxoffset + 1, stride):
		# 				old.add((pos, start, offset))
		# 		elif len(keys) == 1:
		# 			for offset in range(minoffset, maxoffset + 1, stride):
		# 				old.add((key, hex(offset)[2:]))
		# 	self.mem_access_gt[addr] = old
		# 	self.mem_access_gt.sync()

	def read(self, addr, mem):
		addr = self.base_adjust(addr)
		# mem_addr = int(mem, 16)
		# if len(items) == 3:
		# 	if mem_addr != 0:
		# 		offset = items[2] # the stackframeaddr is larger than the one in disassembly, dk why
		# 		offset = int(offset, 16) - 4
		# 		mem_access_gt_dict[addr].add(("S", mem, -offset))
		if mem >= self.start and len(hex(mem)) <= len(hex(self.end)) and (len(self.intervals) == 0 or mem < self.intervals[0]):
			self.mem_access_gt_dict[addr].add(("G", self.base_adjust(mem)))
		else:
			self.mem_access_gt_dict[addr].add(("H", mem)) # idx = np.searchsorted(self.intervals, mem_addr)
			# if idx % 2 == 0:
			# 	return
			# else:
			# 	start_addr = self.intervals[idx - 1]
			# 	if hex(start_addr)[2:] in self.heapinfo:
			# 		self.mem_access_gt_dict[addr].add(("H", self.heapinfo[hex(start_addr)[2:]][0], mem-start_addr))

def getFileSize(filepath):
	fsize = os.path.getsize(filepath)
	fsize = fsize / float(1024 * 1024)
	return round(fsize, 2)

def process(id, trace, trans):
	begin = id
	num = 10
	try:
		if trace.get_block(records, begin, num) == 0:
			return
	except IOError as err:
		print(f"Read error: {err}")
		return

if __name__ == "__main__":
	cur_dir = os.path.dirname(os.path.abspath(__file__))
	prog_name = sys.argv[1]
	heapfile = cur_dir + "/../output_gcc9/pin_" + prog_name  + "_runspec_amd_1.csv"
	mem_access_file = "/root/gcloud/memtrace_" + prog_name + ".log"
	out_file = cur_dir + "/../output_gcc9/memaccess_" + prog_name
	trans = TransMemAccess(heapfile, mem_access_file, out_file)
	fsize = getFileSize(mem_access_file)
	with open(mem_access_file, 'rb') as f:
		trace = Trace(f, trans, fsize)
		records = [Record() for _ in range(1)]
		begin_t = time.time()
		while True:
			try:
				if trace.read_records(records) == 0:
					break
			except IOError as err:
				print(f"Read error: {err}")
				break
			
			trans.read(records[0].PC, records[0].EA)
			# if linenum % 100000 == 0:
			# 	print(str(linenum // (time.time() - begin_t)) + "lines/s")
			
		trans.finish()
		# trans.mem_access_gt.sync()
