#include "pin.H"
#include <fstream>
#include <iostream>
#include <string>
#include <set>
#include <map>
#include <cstdio>
#include <vector>
#include <algorithm>
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "pin_output.log", "specify output file name");

std::ofstream outFileCSV;
std::ofstream outFileHeap;
std::ofstream outFileStack;
pid_t trg_pid = 0;
std::map<ADDRINT, std::set<ADDRINT>> accessedMems;
std::set<ADDRINT> skippedInstr;
bool Record = false;

#define CALLOC "calloc"
#define REALLOC "realloc"
#define MALLOC "malloc"
#define FREE "free"
#define MAIN "main"
ADDRINT mallocCallSite = -1;
ADDRINT callocCallSite = -1;
ADDRINT reallocCallSite = -1;
ADDRINT lowAddr = -1;
ADDRINT highAddr = -1;

std::map<ADDRINT, ADDRINT> stackptr2funcentry;
std::vector<ADDRINT> stackframe;

template<typename T>
struct DescendingComparator {
    bool operator()(const T& a, const T& b) const {
        return a > b; // Reverse comparison for descending order
    }
};

VOID RecordMemAccess(ADDRINT ip, ADDRINT addr) {
    if (!Record) return;
    if (addr >> 24 != 0xff) return;
    if (accessedMems[ip].size() > 5) {
        // outFileCSV << std::hex<< ip << " is loop" << std::endl;  
        if (skippedInstr.find(ip) == skippedInstr.end()) {
            skippedInstr.insert(ip);
            outFileStack << std::hex<< ip << " is loop" << std::endl;
        }
        return;
    }

    std::stringstream stream;
    stream << std::hex << ip << ", ";
    if (addr >> 24 == 0xff) {
        auto insertPosition = std::lower_bound(stackframe.begin(), stackframe.end(), addr, DescendingComparator<int>());
        int index = insertPosition - stackframe.begin();
        if (index > 0) {
            ADDRINT sp = stackframe.at(index - 1);
            ADDRINT funcentry = stackptr2funcentry[sp];
            stream << std::hex << funcentry << ", " << sp - addr << std::endl;
            addr = funcentry + sp - addr;
         
        // else {
        //     stream << std::hex << addr << std::endl;
        // }
        
        std::set<ADDRINT> myset = accessedMems[ip];
        if (myset.find(addr) == myset.end()) {
            accessedMems[ip].insert(addr);
            std::string result( stream.str() );
            outFileCSV << result;
        }
        }
    }
    // else {
    //     stream << std::hex << addr << std::endl;
    // }
    // std::set<ADDRINT> myset = accessedMems[ip];
    // if (myset.find(addr) == myset.end()) {
        // accessedMems[ip].insert(addr);
        // accessedMems[ip].insert(addr);
        
    // }
}


VOID BeforeCall(ADDRINT rsp, ADDRINT callDest, ADDRINT callSite) {
    if (!Record) return;
    PIN_LockClient();
    RTN callDestRtn = RTN_FindByAddress(callDest);
    PIN_UnlockClient();
    std::string callDestName = RTN_Valid(callDestRtn) ? RTN_Name(callDestRtn) : "Unknown";
    if (callDestName.find(".plt", 0) != std::string::npos)
        return;
    // std::stringstream stream;
    // stream << "call entering " << std::hex << callDest << ", " << callDestName << ", sp " << std::hex << rsp << ", at "<< std::hex << callSite << std::endl;
    // std::string result( stream.str() );
    // outFileCSV << result;
    stackframe.push_back(rsp);
    stackptr2funcentry[rsp] = callDest;

    // if (callDestName.rfind(MALLOC, 0) == 0) {
    //     mallocCallSite = callSite;
    // }
    // if (callDestName.rfind(CALLOC, 0)==0) {
    //     callocCallSite = callSite;
    // }
    // if (callDestName.rfind(REALLOC, 0)==0) {
    //     reallocCallSite = callSite;
    // }
}

VOID BeforeTailCall(ADDRINT rsp, ADDRINT callDest, ADDRINT callSite) {
    if (!Record) return;
    PIN_LockClient();
    RTN callDestRtn = RTN_FindByAddress(callDest);
    RTN callSiteRtn = RTN_FindByAddress(callSite);
    PIN_UnlockClient();
    std::string callDestName = RTN_Valid(callDestRtn) ? RTN_Name(callDestRtn) : "Unknown";
    std::string callSiteName = RTN_Valid(callSiteRtn) ? RTN_Name(callSiteRtn) : "Unknown";
    // print the exit for the last function
    // std::stringstream stream;
    // stream << "exiting at " << std::hex << callSite << ", " << callSiteName << std::endl;
    
    // if (callDestName.find(".plt", 0) == std::string::npos)
    //     stream << "call entering " << std::hex << callDest << ", " << callDestName  << ", sp " << std::hex << rsp << ", at "<< std::hex << callSite << std::endl;
    // std::string result( stream.str() );
    // outFileCSV << result;
    ADDRINT poppedaddr = stackframe.back();
    stackframe.pop_back();
    stackptr2funcentry.erase(poppedaddr);
    if (callDestName.find(".plt", 0) == std::string::npos) {
        stackframe.push_back(rsp);
        stackptr2funcentry[rsp] = callDest;
    }
}

VOID BeforeReturn(ADDRINT ip) {
    if (!Record) return;
    // PIN_LockClient();
    // RTN callSiteRtn = RTN_FindByAddress(ip);
    // PIN_UnlockClient();
    // std::string callSiteName = RTN_Valid(callSiteRtn) ? RTN_Name(callSiteRtn) : "Unknown";
    // std::stringstream stream;
    // stream << "exiting at " << std::hex << ip  << ", " << callSiteName << std::endl;
    // std::string result( stream.str() );
    // outFileCSV << result;
    ADDRINT poppedaddr = stackframe.back();
    stackframe.pop_back();
    stackptr2funcentry.erase(poppedaddr);
}


VOID Instruction(INS ins, VOID *v) {
    ADDRINT addr = INS_Address(ins);
    if (addr < lowAddr || addr > highAddr)
        return;
    
    std::string disptr = INS_Disassemble(ins);
    if (disptr.find("push") != std::string::npos || disptr.find("pop") != std::string::npos) {
        return;
    }
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    // outFileStack << disptr << " at: " << std::hex<< INS_Address(ins) << std::endl;
    
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        // if (accessedMems[addr].size() > 10) {
        //     skippedInstr.insert(addr);
        //     break;
        // }
        if (INS_MemoryOperandIsRead(ins, memOp) || INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertPredicatedCall(
                                 ins, IPOINT_BEFORE, (AFUNPTR)RecordMemAccess,
                                 IARG_INST_PTR,
                                 IARG_MEMORYOP_EA, memOp,
                                 IARG_END);
        }
    }

    if (INS_IsCall(ins) && !INS_IsDirectControlFlow(ins)){
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeCall, IARG_REG_VALUE, REG_STACK_PTR, IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR, IARG_END);
    } else if (INS_IsDirectControlFlow(ins)) {
        RTN sourceRtn = RTN_FindByAddress(addr);
        RTN destRtn   = RTN_FindByAddress(INS_DirectControlFlowTargetAddress(ins));
        if (INS_IsCall(ins) && INS_IsProcedureCall(ins))  // INS_IsIndirectBranchOrCall(ins)) {  // INS_IsIndirectCall(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeCall, IARG_REG_VALUE, REG_STACK_PTR, IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR, IARG_END);
        else if (INS_IsCall(ins)) // PcMaterialization
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeTailCall, IARG_REG_VALUE, REG_STACK_PTR, IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR, IARG_END);
        else if (sourceRtn != destRtn) // tail call
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeTailCall, IARG_REG_VALUE, REG_STACK_PTR, IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR, IARG_END);
    } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeReturn, IARG_INST_PTR, IARG_END);
    }
}

/* ===================================================================== */

VOID Arg1Before(ADDRINT retaddr, CHAR* name, ADDRINT size) { 
    if (!Record) return;
    outFileHeap << name << ", " << std::hex << retaddr - 5 << ", " << std::hex << retaddr << ", " << size  << std::endl; 
}

/* ===================================================================== */

VOID MallocAfter(ADDRINT ret) { 
    if (!Record) return;
    outFileHeap << std::hex << ret << std::endl; 
}

/* ===================================================================== */

VOID CallocBefore(ADDRINT retaddr, CHAR* name, ADDRINT size1, ADDRINT size2) { 
    if (!Record) return;
    outFileHeap << name << ", "<< std::hex << callocCallSite << ", " << std::hex << retaddr << ", " << size1*size2  << std::endl; 
}

/* ===================================================================== */

VOID CallocAfter(ADDRINT ret) { 
    if (!Record) return;
    outFileHeap << std::hex << ret << std::endl; 
}

VOID ReallocBefore(ADDRINT retaddr, CHAR* name, ADDRINT ptr, ADDRINT newsize) { 
    if (!Record) return;
    outFileHeap << name << ", " << std::hex << reallocCallSite << ", " << std::hex << retaddr << ", " << std::hex << ptr << ", " << newsize  << std::endl; 
}

/* ===================================================================== */

VOID RecordMainBegin(ADDRINT rsp, ADDRINT addr) {
    Record = true;
    std::stringstream stream;
    stream << "call entering " << std::hex << addr << ", main, sp " << std::hex << rsp;
    std::string result( stream.str() );
    outFileCSV << result << std::endl;
}

VOID RecordMainEnd() {
  Record = false;
}

VOID Image(IMG img, VOID* v)
{
    if (IMG_IsMainExecutable(img)) {
        lowAddr = IMG_LowAddress(img);
        highAddr = IMG_HighAddress(img);
    }
    outFileCSV <<"img: " << lowAddr << ", " << highAddr << std::endl;
    RTN mainRtn = RTN_FindByName(img, MAIN);
      if (mainRtn.is_valid()) {
        RTN_Open(mainRtn);
        RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)RecordMainBegin, IARG_REG_VALUE, REG_STACK_PTR, IARG_INST_PTR, IARG_END);
        // RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)RecordMainEnd, IARG_END);
        RTN_Close(mainRtn);
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

    // RTN freeRtn = RTN_FindByName(img, FREE);
    // if (RTN_Valid(freeRtn))
    // {
    //     RTN_Open(freeRtn);
    //     RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before, IARG_INST_PTR, IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
    //                    IARG_END);
    //     RTN_Close(freeRtn);
    // }
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    outFileCSV.close();
    outFileHeap.close();
    outFileStack.close();
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        std::cerr << "Initialization error" << std::endl;
        return -1;
    }

    outFileCSV.open((KnobOutputFile.Value() + ".csv").c_str(), std::ios::out);
    if(!outFileCSV.is_open()) {
        std::cerr << "Could not open log file" << std::endl;
        return -1;
    }

    outFileHeap.open((KnobOutputFile.Value() + "_heap.csv").c_str(), std::ios::out);
    if(!outFileHeap.is_open()) {
        std::cerr << "Could not open log file" << std::endl;
        return -1;
    }

    outFileStack.open((KnobOutputFile.Value() + "_skipped.csv").c_str(), std::ios::out);
    if(!outFileStack.is_open()) {
        std::cerr << "Could not open log file" << std::endl;
        return -1;
    }

    PIN_InitSymbols();


    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    // PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    // PIN_AddFollowChildProcessFunction(FollowChild, 0);

    PIN_StartProgram();

    return 0;
}