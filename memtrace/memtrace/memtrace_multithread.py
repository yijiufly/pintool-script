import struct
import io
import os
import shelve
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


class Worker:
    def __init__(self, start, trace, output):
        self.start = start
        self.trace = trace
        self.output = output
        self.recno = 0
        self.hdr = BlockHeader()
        self.blockEnd = 0
        self.blockData = bytearray()
        self.blockReader = None
        self.rec = Record()
        self.blockNum = 0
        self.begin_t = time.time()
        self.mem_access_gt_dict = defaultdict(set)

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

    def read_record(self):
        deltaPC = self.read_varint()
        deltaEA = self.read_varint()
        self.rec.N = self.recno
        self.rec.PC += to_uint32b(deltaPC)
        self.rec.PC = to_uint32b(self.rec.PC)
        self.rec.EA += to_uint32b(deltaEA)
        self.rec.EA = to_uint32b(self.rec.EA)
        self.recno += 1

    def read(self, addr, mem):
        addr = self.output.base_adjust(addr)
        if mem >= self.output.start and len(hex(mem)) <= len(hex(self.output.end)) and (len(self.output.intervals) == 0 or mem < self.output.intervals[0]):
            self.mem_access_gt_dict[addr].add(("G", self.output.base_adjust(mem)))
        else:
            self.mem_access_gt_dict[addr].add(("H", mem)) # idx = np.searchsorted(self.intervals, mem_addr)

class Trace:
    def __init__(self, mem_access_file, trans, fsize):
        self.r = open(mem_access_file, 'rb')
        self.trans = trans
        self.fsize = fsize
        self.blockNum = 0
        self.lock = threading.RLock()

    def read_block_header(self, worker):
        header_data = self.r.read(16)
        if len(header_data) != 16:
            raise IOError("Failed to read block header")
        worker.hdr.Bytes, worker.hdr.Recs = struct.unpack('<QQ', header_data)
        worker.blockEnd = worker.recno + worker.hdr.Recs

    def read_block_content(self, worker):
        size = worker.hdr.Bytes - 16
        if size > len(worker.blockData):
            worker.blockData = bytearray(size * 2)
        worker.blockData = self.r.read(size)
        if len(worker.blockData) != size:
            raise IOError("Failed to read block content")
        worker.blockReader = io.BytesIO(worker.blockData)
        worker.rec = Record()


    def read_one_record(self, worker):
        if worker.recno == worker.blockEnd:
            if worker.blockNum % 10 == 0:
                self.lock.acquire()
                current_pos = self.r.tell()
                self.lock.release()

                self.trans.update_shelve_set(worker)
                end_t = time.time()
                if worker.blockNum > 0:
                    print("sync " + str(self.blockNum) + " blocks, loaded " + str((current_pos * 100) // (self.fsize * float(1024 * 1024))) + "%, ftell " + str(current_pos) + ", speed " + str((end_t - worker.begin_t) // worker.blockNum) + "s/block")
                    # return 0
                worker.begin_t = end_t

            worker.blockNum += 1
            self.lock.acquire()
            self.blockNum += 1
            self.read_block_header(worker)
            self.read_block_content(worker)
            self.lock.release()
        worker.read_record()
        worker.read(worker.rec.PC, worker.rec.EA)
        return 1

    def __del__(self):
        if not self.r.closed:
            self.r.close()

class MemAccessOutput:
    def __init__(self, heap_file, out_file):
        self.heap_file = heap_file
        self.start = 0
        self.out_file = out_file
        self.prepare()
        self.lock = threading.RLock()
    
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


    def update_shelve_set(self, worker):
        self.lock.acquire()
        for addr in worker.mem_access_gt_dict:
            addr_str = hex(addr)
            if addr_str in self.mem_access_gt:
                if addr in self.large_obj:
                    self.infer_stride(addr, worker.mem_access_gt_dict[addr])
                    continue
                old = self.mem_access_gt[addr_str]
                if len(old) > self.largesize: # avoid frequent read/write for large volumn offsets
                    self.infer_stride(addr, worker.mem_access_gt_dict[addr])
                else:
                    old.update(worker.mem_access_gt_dict[addr])
                    self.mem_access_gt[addr_str] = old
            else:
                self.mem_access_gt[addr_str] = worker.mem_access_gt_dict[addr]
        self.mem_access_gt.sync()
        # print(worker.mem_access_gt_dict)
        self.lock.release()
        worker.mem_access_gt_dict.clear()

    def finish(self):
        with open(self.heap_file[:-4] + "_largeobj", "a") as f:
            f.write(str(self.large_obj))

    
def getFileSize(filepath):
    fsize = os.path.getsize(filepath)
    fsize = fsize / float(1024 * 1024)
    return round(fsize, 2)

def process(i, worker):
    trace = worker.trace
    output = worker.output
    while True:
        try:
            if trace.read_one_record(worker) == 0:
                break
        except IOError as err:
            print(f"Read error: {err}")
            break


if __name__ == "__main__":
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    prog_name = sys.argv[1]
    heapfile = cur_dir + "/../output_gcc9/pin_" + prog_name  + "_runspec_amd_1.csv"
    mem_access_file = "/mnt/data/memtrace_" + prog_name + ".log"
    out_file = cur_dir + "/../output_gcc9/memaccess_" + prog_name
    fsize = getFileSize(mem_access_file)
    
    output = MemAccessOutput(heapfile, out_file)
    trace = Trace(mem_access_file, output, fsize)
    worker_count = 2
    workers = []
    for i in range(worker_count):
        w = Worker(i, trace, output)
        wkr = threading.Thread(target=process, args=(i+1, w))
        wkr.start()
        workers.append(wkr)

    for wkr in workers:
        wkr.join()

    output.finish()