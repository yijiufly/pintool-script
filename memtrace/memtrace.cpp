#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <asm/unistd.h>         // __NR_futex
#include <linux/futex.h>        // FUTEX_WAIT

#include "pin.H"

struct record 
{
        ADDRINT pc;
        ADDRINT ea;
};

TLS_KEY cbufKey;
BUFFER_ID buf;
int logFD;
PIN_LOCK logLock;
ADDRINT lowAddr = -1;
ADDRINT highAddr = -1;
std::ofstream outFileCSV;
#define CALLOC "calloc"
#define REALLOC "realloc"
#define MALLOC "malloc"
#define FREE "free"
#define MAIN "main"

KNOB<std::string> KnobI(KNOB_MODE_WRITEONCE, "pintool",
    "o", "out", "specify the part");


VOID RecordMemAccess(ADDRINT ip, ADDRINT addr) {

    std::stringstream stream;
    stream << std::hex << ip << ", " << std::hex << addr << std::endl;
    std::string result( stream.str() );
    outFileCSV << result;
    
}

VOID Arg1Before(ADDRINT retaddr, CHAR* name, ADDRINT size) { 
    outFileCSV << name << ", " << std::hex << retaddr - 5 << ", " << std::hex << retaddr << ", " << size  << std::endl; 
}

/* ===================================================================== */

VOID MallocAfter(ADDRINT ret) { 
    outFileCSV << std::hex << ret << std::endl; 
}

/* ===================================================================== */

VOID CallocBefore(ADDRINT retaddr, CHAR* name, ADDRINT size1, ADDRINT size2) { 
    outFileCSV << name << ", "<< std::hex << retaddr - 5 << ", " << std::hex << retaddr << ", " << size1*size2  << std::endl; 
}

/* ===================================================================== */

VOID CallocAfter(ADDRINT ret) { 
    outFileCSV << std::hex << ret << std::endl; 
}

VOID ReallocBefore(ADDRINT retaddr, CHAR* name, ADDRINT ptr, ADDRINT newsize) { 
    outFileCSV << name << ", " << std::hex << retaddr - 5 << ", " << std::hex << retaddr << ", " << std::hex << ptr << ", " << newsize  << std::endl; 
}



VOID
insInstruction(INS ins, VOID *v)
{
        ADDRINT addr = INS_Address(ins);
        if (addr < lowAddr || addr > highAddr)
                return;
        
        std::string disptr = INS_Disassemble(ins);
        if (disptr.find("push") != std::string::npos || disptr.find("pop") != std::string::npos) {
                return;
        }
        UINT32 memOperands = INS_MemoryOperandCount(ins);

        for (UINT32 i = 0; i < memOperands; i++) {
                if (!INS_MemoryOperandIsWritten(ins, i) && !INS_MemoryOperandIsRead(ins, i))
                        continue;

                INS_InsertFillBufferPredicated(
                        ins, IPOINT_BEFORE, buf,
                        IARG_INST_PTR, offsetof(struct record, pc),
                        IARG_MEMORYOP_EA, i, offsetof(struct record, ea),
                        IARG_END); 

                // INS_InsertPredicatedCall(
                //                  ins, IPOINT_BEFORE, (AFUNPTR)RecordMemAccess,
                //                  IARG_INST_PTR,
                //                  IARG_MEMORYOP_EA, i,
                //                  IARG_END);               
        }
}

VOID Image(IMG img, VOID* v)
{
    if (IMG_IsMainExecutable(img)) {
        lowAddr = IMG_LowAddress(img);
        highAddr = IMG_HighAddress(img);
        outFileCSV <<"img: " << std::hex << lowAddr << ", " << std::hex <<  highAddr << std::endl;
        // int dist = (highAddr - lowAddr) / sec;
        // lowAddr = lowAddr + dist * isec;
        // if (isec < sec - 1)
        //         highAddr = lowAddr + dist * (isec + 1);
        // outFileCSV <<"record: " << std::hex << lowAddr << ", " << std::hex <<  highAddr << std::endl;
    }

    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_RETURN_IP, IARG_ADDRINT, MALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(mallocRtn);
    }

    RTN callocRtn = RTN_FindByName(img, CALLOC);
    if (RTN_Valid(callocRtn))
    {
        RTN_Open(callocRtn);
        RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore, IARG_RETURN_IP, IARG_ADDRINT, CALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_END);
        RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)CallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        RTN_Close(callocRtn);
    }

    RTN reallocRtn = RTN_FindByName(img, REALLOC);
    if (RTN_Valid(reallocRtn))
    {
        RTN_Open(reallocRtn);
        RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore, IARG_RETURN_IP, IARG_ADDRINT, REALLOC, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_END);
        RTN_Close(reallocRtn);
    }
}

char *
putVarint(char *buf, int64_t n)
{
        uint64_t x = (n << 1) ^ (n >> 63);
        for (; x >= 0x80; x >>= 7) {
                *(buf++) = (x & 0x7F) | 0x80;
        }
        *(buf++) = x;
        return buf;
}

char *
putLEUint64(char *buf, uint64_t n)
{
        for (int i = 0; i < 8; i++, n >>= 8, buf++)
                *buf = (unsigned char)n;
        return buf;
}

size_t
compressRecords(struct record *recs, int n, char *out)
{
        char *outPos = out + 2 * 8;
        ADDRINT prevPC = 0, prevEA = 0;
        int count = 0;
        std::unordered_set<ADDRINT> accessedMems;
        for (int i = 0; i < n; i++, recs++) {
                if (recs->ea >> 24 == 0xff) continue;
                ADDRINT key = (recs->pc << 16) + (recs->ea & 0xfffffff);
                if (accessedMems.find(key) == accessedMems.end()) {
                        int64_t deltaPC = recs->pc - prevPC;
                        int64_t deltaEA = recs->ea - prevEA;
                        prevPC = recs->pc;
                        prevEA = recs->ea;
                        accessedMems.insert(key);
                        outPos = putVarint(outPos, deltaPC);
                        outPos = putVarint(outPos, deltaEA);
                        count += 1;
                }
        }
        putLEUint64(out, outPos - out);
        putLEUint64(out + 8, count);
        return outPos - out;

        // char *outPos = out + 2 * 8;
        // ADDRINT prevPC = 0, prevEA = 0;
        // for (int i = 0; i < n; i++, recs++) {
        //         int64_t deltaPC = recs->pc - prevPC;
        //         int64_t deltaEA = recs->ea - prevEA;
        //         prevPC = recs->pc;
        //         prevEA = recs->ea;
        //         outPos = putVarint(outPos, deltaPC);
        //         outPos = putVarint(outPos, deltaEA);
        // }
        // putLEUint64(out, outPos - out);
        // putLEUint64(out + 8, n);
        // return outPos - out;
}

void
xwrite(int fd, const void *buf, size_t count)
{
        while (count > 0) {
                ssize_t n = write(fd, buf, count);
                if (n <= 0) {
                        fprintf(stderr, "log write failed: %s\n",
                                strerror(errno));
                        PIN_ExitProcess(1);
                }
                count -= n;
                buf = (char*)buf + n;
        }
}

VOID *
flushBuf(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf,
         UINT64 numElements, VOID *v)
{
        char *cbuf = (char*)PIN_GetThreadData(cbufKey, tid);
        if (cbuf == NULL) {
                cbuf = new char[2 * 8 + numElements * 2 * 10];
                PIN_SetThreadData(cbufKey, cbuf, tid);
        }
        size_t bytes = compressRecords((struct record*)buf, numElements, cbuf);
        PIN_GetLock(&logLock, tid);
        xwrite(logFD, cbuf, bytes);
        PIN_ReleaseLock(&logLock);
        return buf;
}

void
freeCbuf(void *cbuf)
{
        delete[] (char*)cbuf;
}

struct timespec futexTimeout = {
        .tv_sec = 1000,
        .tv_nsec = 0,
};

VOID
insSyscall(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) 
{
        // Workaround: When a thread calls exit_group, PIN tries to
        // kick all threads out of system calls and exit them, but it
        // can't kick threads out of an untimed futex wait. Most
        // likely, this is because Go runs with syscall restarting
        // enabled, which means a signal won't kick an untimed futex
        // out of the syscall. Since futex wait is always allowed to
        // return spuriously, we can transform untimed waits into
        // timed waits. It doesn't matter what this timeout is; it
        // just needs to have one (probably because that makes it
        // interruptible with a signal).
        if (PIN_GetSyscallNumber(ctxt, std) == __NR_futex &&
            PIN_GetSyscallArgument(ctxt, std, 1) == FUTEX_WAIT &&
            PIN_GetSyscallArgument(ctxt, std, 3) == 0) {
                //fprintf(stderr, "overriding futex timeout\n");
                PIN_SetSyscallArgument(ctxt, std, 3, (ADDRINT)&futexTimeout);
        }
}

int
main(int argc, char **argv)
{
        PIN_InitSymbols();
        enum { NUM_BUF_PAGES = 131072}; //1G

        if (PIN_Init(argc, argv))
                return -1;

        cbufKey = PIN_CreateThreadDataKey(freeCbuf);
        if (cbufKey == -1) {
                fprintf(stderr, "failed to create TLS key for cbuf");
                return 1;
        }

        std::string siv = KnobI.Value();
        outFileCSV.open("/root/gcloud/memtrace/output_gcc9/pin_" + siv + "_runspec_amd_1.csv", std::ios::out);

        buf = PIN_DefineTraceBuffer(
                sizeof(struct record), NUM_BUF_PAGES, flushBuf, 0);
        if (buf == BUFFER_ID_INVALID) {
                fprintf(stderr, "could not allocate buffer\n");
                return 1;
        }

        // logFD = creat("memtrace.log", 0666);
        std::string filepath = "/mnt/data/memtrace_" + siv + ".log";
        logFD = open(filepath.c_str(), O_WRONLY|O_CREAT|O_TRUNC, 0666);
        if (logFD < 0) {
                fprintf(stderr, "failed to open memtrace.log\n");
                return 1;
        }

        PIN_InitLock(&logLock);

        IMG_AddInstrumentFunction(Image, 0);
        INS_AddInstrumentFunction(insInstruction, 0);

        PIN_AddSyscallEntryFunction(insSyscall, 0);

        PIN_StartProgram();
        return 0;
}
