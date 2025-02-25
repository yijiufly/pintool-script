#include "pin.H"
#include <fstream>
#include <iostream>
#include <string>
#include <set>
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "pin_output.log", "specify output file name");

std::ofstream outFile;
ADDRINT baseAddress = 0;
pid_t trg_pid = 0;
std::set<std::string> myset;

BOOL FollowChild(CHILD_PROCESS cProcess, VOID* userData)
{
    int argcc;
    char ** argvv;
    CHILD_PROCESS_GetCommandLine(cProcess,&argcc,(const char* const**)&argvv);
    if(std::string(argvv[0]).find("expr") != std::string::npos)
    {
        trg_pid = PIN_GetPid();
        if(outFile.is_open()) {
            outFile <<"trgpid : "<<trg_pid << std::endl;
        }
    }
    return TRUE;
}

VOID ImgLoad (IMG img, VOID *v)
{
    
/*  fprintf(logfp, "load %s off=%08x low=%08x high=%08x start=%08x size=%08x\n",
            IMG_Name(img).c_str(),
            IMG_LoadOffset(img), IMG_LowAddress(img), IMG_HighAddress(img),
            IMG_StartAddress(img), IMG_SizeMapped(img));*/

    if (IMG_IsMainExecutable(img)){
        baseAddress = IMG_LowAddress(img);
    }
}

VOID BeforeCall(ADDRINT callDest, ADDRINT callSite) {
    if(outFile.is_open()) {
	    PIN_LockClient();
        RTN callDestRtn = RTN_FindByAddress(callDest);
        RTN callSiteRtn = RTN_FindByAddress(callSite);
	    PIN_UnlockClient();
	    std::string callDestName = RTN_Valid(callDestRtn) ? RTN_Name(callDestRtn) : "Unknown";
	    std::string callSiteName = RTN_Valid(callSiteRtn) ? RTN_Name(callSiteRtn): "Unknown";
        std::stringstream stream;
        stream << std::hex << callSite << " (" << callDestName << "), " << std::hex << callDest << " (" << callSiteName << "), " << std::endl;
        std::string result( stream.str() );
        if (myset.find(result) == myset.end()) {
            myset.insert(result);
            outFile << result;
        }
    } else {
        std::cerr << "Could not open log file" << std::endl;
        PIN_ExitProcess(1);
    }
}

 VOID print_ins(ADDRINT addr) {
    std::stringstream stream;
    stream <<std::hex<<addr<<std::endl;
    std::string result( stream.str() );
    outFile << result;      
 }

VOID Instruction(INS ins, VOID *v) {
    // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print_ins, IARG_INST_PTR,IARG_END);

    if (INS_IsCall(ins) && INS_IsIndirectControlFlow(ins)) {  // INS_IsIndirectBranchOrCall(ins)) {  // INS_IsIndirectCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeCall, IARG_BRANCH_TARGET_ADDR, IARG_INST_PTR, IARG_END);
    }
}

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    outFile << "Thread started: " << threadid << std::endl;
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v) {
    outFile << "Thread finished: " << threadid << std::endl;
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        std::cerr << "Initialization error" << std::endl;
        return -1;
    }

    outFile.open(KnobOutputFile.Value().c_str(), std::ios::out);
    if(!outFile.is_open()) {
        std::cerr << "Could not open log file" << std::endl;
        return -1;
    }

    PIN_InitSymbols();


/*
    INS_AddInstrumentFunction(ImgLoad, 0);
    if(outFile.is_open()) {
        outFile << std::hex << baseAddress << std::endl;
    } else {
        std::cerr << "Could not open log file" << std::endl;
    }
*/
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    // PIN_AddFollowChildProcessFunction(FollowChild, 0);

    PIN_StartProgram();

    return 0;
}

