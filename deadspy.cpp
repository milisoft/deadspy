// * BeginRiceCopyright *****************************************************
//
// Copyright ((c)) 2002-2011, Rice University
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of Rice University (RICE) nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// This software is provided by RICE and contributors "as is" and any
// express or implied warranties, including, but not limited to, the
// implied warranties of merchantability and fitness for a particular
// purpose are disclaimed. In no event shall RICE or contributors be
// liable for any direct, indirect, incidental, special, exemplary, or
// consequential damages (including, but not limited to, procurement of
// substitute goods or services; loss of use, data, or profits; or
// business interruption) however caused and on any theory of liability,
// whether in contract, strict liability, or tort (including negligence
// or otherwise) arising in any way out of the use of this software, even
// if advised of the possibility of such damage.
//
// ******************************************************* EndRiceCopyright *


#include <stdio.h>
#include <stdlib.h>
#include "pin.H"
#include <map>
#include <ext/hash_map>
#include <list>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <locale>
#include <unistd.h>
#include <sys/syscall.h>
#include <iostream>
#include <assert.h>
#include <sys/mman.h>
#include <exception>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <sstream>
// Need GOOGLE sparse hash tables
#include <google/sparse_hash_map>
#include <google/dense_hash_map>
using google::sparse_hash_map;      // namespace where class lives by default
using google::dense_hash_map;      // namespace where class lives by default
using namespace __gnu_cxx;
using namespace std;



//#define PRINT_ALL_CTXT

#define CONTINUOUS_DEADINFO


//#define IP_AND_CCT
//#define MERGE_SAME_LINES	
//#define TESTING_BYTES
//#define GATHER_STATS
//MT
//#define MULTI_THREADED

// All globals
#define CONTEXT_TREE_VECTOR_SIZE (10)
#define MAX_CCT_PRINT_DEPTH (20)
#define MAX_FILE_PATH   (200)
#ifndef MAX_DEAD_CONTEXTS_TO_LOG 
#define MAX_DEAD_CONTEXTS_TO_LOG   (1000)
#endif //MAX_DEAD_CONTEXTS_TO_LOG

// 64KB shadow pages
#define PAGE_OFFSET_BITS (16LL)
#define PAGE_OFFSET(addr) ( addr & 0xFFFF)
#define PAGE_OFFSET_MASK ( 0xFFFF)

#define PAGE_SIZE (1 << PAGE_OFFSET_BITS)

// 2 level page table
#define PTR_SIZE (sizeof(struct Status *))
#define LEVEL_1_PAGE_TABLE_BITS  (20)
#define LEVEL_1_PAGE_TABLE_ENTRIES  (1 << LEVEL_1_PAGE_TABLE_BITS )
#define LEVEL_1_PAGE_TABLE_SIZE  (LEVEL_1_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_2_PAGE_TABLE_BITS  (12)
#define LEVEL_2_PAGE_TABLE_ENTRIES  (1 << LEVEL_2_PAGE_TABLE_BITS )
#define LEVEL_2_PAGE_TABLE_SIZE  (LEVEL_2_PAGE_TABLE_ENTRIES * PTR_SIZE )

#define LEVEL_1_PAGE_TABLE_SLOT(addr) ((((uint64_t)addr) >> (LEVEL_2_PAGE_TABLE_BITS + PAGE_OFFSET_BITS)) & 0xfffff)
#define LEVEL_2_PAGE_TABLE_SLOT(addr) ((((uint64_t)addr) >> (PAGE_OFFSET_BITS)) & 0xFFF)


// have R, W representative macros
#define READ_ACTION (0) 
#define WRITE_ACTION (0xff) 

#define ONE_BYTE_READ_ACTION (0)
#define TWO_BYTE_READ_ACTION (0)
#define FOUR_BYTE_READ_ACTION (0)
#define EIGHT_BYTE_READ_ACTION (0)

#define ONE_BYTE_WRITE_ACTION (0xff)
#define TWO_BYTE_WRITE_ACTION (0xffff)
#define FOUR_BYTE_WRITE_ACTION (0xffffffff)
#define EIGHT_BYTE_WRITE_ACTION (0xffffffffffffffff)



#ifndef MULTI_THREADED
uint64_t g1ByteWriteInstrCount;
uint64_t g2ByteWriteInstrCount;
uint64_t g4ByteWriteInstrCount;
uint64_t g8ByteWriteInstrCount;
uint64_t g10ByteWriteInstrCount;
uint64_t g16ByteWriteInstrCount;
uint64_t gLargeByteWriteInstrCount;
uint64_t gLargeByteWriteByteCount;
#endif

#ifdef TESTING_BYTES 
uint64_t gFullyKilling1;
uint64_t gFullyKilling2;
uint64_t gFullyKilling4;
uint64_t gFullyKilling8;
uint64_t gFullyKilling10;
uint64_t gFullyKilling16;
uint64_t gFullyKillingLarge;

uint64_t gPartiallyKilling1;
uint64_t gPartiallyKilling2;
uint64_t gPartiallyKilling4;
uint64_t gPartiallyKilling8;
uint64_t gPartiallyKilling10;
uint64_t gPartiallyKilling16;
uint64_t gPartiallyKillingLarge;

uint64_t gPartiallyDeadBytes1;
uint64_t gPartiallyDeadBytes2;
uint64_t gPartiallyDeadBytes4;
uint64_t gPartiallyDeadBytes8;
uint64_t gPartiallyDeadBytes10;
uint64_t gPartiallyDeadBytes16;
uint64_t gPartiallyDeadBytesLarge;
#endif // end TESTING_BYTES


// All fwd declarations

struct ContextNode;
struct DeadInfo;


#ifdef IP_AND_CCT
struct MergedDeadInfo;
struct TraceNode;
struct DeadInfoForPresentation;
inline ADDRINT GetIPFromInfo(void * ptr);
inline string GetLineFromInfo(void * ptr);
#endif // end IP_AND_CCT


#ifdef CONTINUOUS_DEADINFO
//#define PRE_ALLOCATED_BUFFER_SIZE (1L << 35)
// default use this
#define PRE_ALLOCATED_BUFFER_SIZE (1L << 32)
void ** gPreAllocatedContextBuffer;
uint64_t gCurPreAllocatedContextBufferIndex;
#endif //end CONTINUOUS_DEADINFO

struct ContextNode {
    ContextNode * parent;
    sparse_hash_map<ADDRINT,ContextNode *> childContexts;
#ifdef IP_AND_CCT
    sparse_hash_map<ADDRINT,TraceNode *> childTraces;
#endif // end IP_AND_CCT    
    ADDRINT address;
    
#if defined(CONTINUOUS_DEADINFO) && !defined(IP_AND_CCT) 
    void* operator new (size_t size) {
        ContextNode  * ret =  ((ContextNode*)gPreAllocatedContextBuffer) + gCurPreAllocatedContextBufferIndex;
        gCurPreAllocatedContextBufferIndex ++;
        assert( gCurPreAllocatedContextBufferIndex  < (PRE_ALLOCATED_BUFFER_SIZE)/size);
        return ret;
    }
#endif //end  defined(CONTINUOUS_DEADINFO) && !defined(IP_AND_CCT)    
    
};


#ifdef IP_AND_CCT
struct MergedDeadInfo{
	ContextNode * context1;
	ContextNode * context2;
#ifdef MERGE_SAME_LINES
	string line1;
	string line2;
#else    // no MERGE_SAME_LINES
	ADDRINT ip1;
	ADDRINT ip2;
#endif // end MERGE_SAME_LINES
    
	bool operator==(const MergedDeadInfo  & x) const{
#ifdef MERGE_SAME_LINES
		if ( this->context1 == x.context1 && this->context2 == x.context2 &&
            this->line1 == x.line1 && this->line2 == x.line2)
#else            // no MERGE_SAME_LINES
            if ( this->context1 == x.context1 && this->context2 == x.context2 &&
				this->ip1 == x.ip1 && this->ip2 == x.ip2)
#endif //end MERGE_SAME_LINES
                return true;
		return false;
	}
    
    bool operator<(const MergedDeadInfo & x) const {
#ifdef MERGE_SAME_LINES
        if ((this->context1 < x.context1) ||
            (this->context1 == x.context1 && this->context2 < x.context2) ||
            (this->context1 == x.context1 && this->context2 == x.context2 && this->line1 < x.line1) ||
            (this->context1 == x.context1 && this->context2 == x.context2 && this->line1 == x.line1 && this->line2 < x.line2) )
#else            // no MERGE_SAME_LINES
            if ((this->context1 < x.context1) ||
                (this->context1 == x.context1 && this->context2 < x.context2) ||
                (this->context1 == x.context1 && this->context2 == x.context2 && this->ip1 < x.ip1) ||
                (this->context1 == x.context1 && this->context2 == x.context2 && this->ip1 == x.ip1 && this->ip2 < x.ip2) )
#endif // end  MERGE_SAME_LINES               
                return true;
        return false;
	}
    
};

struct DeadInfoForPresentation{
    const MergedDeadInfo * pMergedDeadInfo;
    uint64_t count;
};

struct TraceNode{
    ContextNode * parent;
    TraceNode ** childIPs;
    ADDRINT address;
    uint32_t nSlots;
};

#endif // end IP_AND_CCT

struct DeadInfo {
	void *firstIP;
	void *secondIP;
	uint64_t count;
};

inline bool DeadInfoComparer(const DeadInfo &first, const DeadInfo &second);
inline bool IsValidIP(ADDRINT ip);
inline bool IsValidIP(DeadInfo  di);


uint8_t ** gL1PageTable[LEVEL_1_PAGE_TABLE_SIZE];

//map < void *, Status > MemState;
#if defined(CONTINUOUS_DEADINFO)
hash_map<uint64_t, uint64_t> DeadMap;
hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
//dense_hash_map<uint64_t, uint64_t> DeadMap;
//dense_hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
//sparse_hash_map<uint64_t, uint64_t> DeadMap;
//sparse_hash_map<uint64_t, uint64_t>::iterator gDeadMapIt;
#else // no defined(CONTINUOUS_DEADINFO)
dense_hash_map<uint64_t, DeadInfo> DeadMap;
dense_hash_map<uint64_t, DeadInfo>::iterator gDeadMapIt;
//hash_map<uint64_t, DeadInfo> DeadMap;
//hash_map<uint64_t, DeadInfo>::iterator gDeadMapIt;
#endif //end defined(CONTINUOUS_DEADINFO)

FILE *gTraceFile;
#ifdef GATHER_STATS
FILE *statsFile;
#endif //end GATHER_STATS

uint64_t gTotalDead = 0;
#ifdef MULTI_THREADED
uint64_t gTotalMTDead = 0;
#endif // end MULTI_THREADED


// SEGVHANDLEING FOR BAD .plt
jmp_buf env;
struct sigaction gSigAct;
void SegvHandler(int);

ContextNode * gRootContext;
ContextNode * gCurrentContext;
sparse_hash_map<ADDRINT, ContextNode *>::iterator gContextIter;

/// MT 
#ifdef MULTI_THREADED

// Multi threaded codes keep counters in each CCT
struct ContextTree{
    ContextNode * rootContext;
    ContextNode * currentContext;
    
    uint64_t mt1ByteWriteInstrCount;
    uint64_t mt2ByteWriteInstrCount;
    uint64_t mt4ByteWriteInstrCount;
    uint64_t mt8ByteWriteInstrCount;
    uint64_t mt10ByteWriteInstrCount;
    uint64_t mt16ByteWriteInstrCount;
    uint64_t mtLargeByteWriteInstrCount;
    uint64_t mtLargeByteWriteByteCount;
    
    
};
vector<ContextTree> gContextTreeVector;
#endif //end MULTI_THREADED


#ifdef IP_AND_CCT
sparse_hash_map<ADDRINT, TraceNode *>::iterator gTraceIter;
//dense_hash_map<ADDRINT, void *> gTraceShadowMap;
hash_map<ADDRINT, void *> gTraceShadowMap;
TraceNode * gCurrentTrace;

bool gInitiatedCall = true;
TraceNode ** gCurrentIpVector;

uint32_t gContextTreeIndex;

struct ContextTree{
    ContextNode * rootContext;
    ContextNode * currentContext;
};
vector<ContextTree> gContextTreeVector;

VOID GoDownCallChain(ADDRINT);
VOID UpdateDataOnFunctionEntry(ADDRINT currentIp);
VOID Instruction(INS ins, uint32_t slot);

#ifndef MULTI_THREADED
// The following functions accummulates the number of bytes written in this basic block for the calling thread categorized by the write size. 

inline VOID InstructionContributionOfBBL1Byte(uint32_t count){
    g1ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL2Byte(uint32_t count){
    g2ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL4Byte(uint32_t count){
    g4ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL8Byte(uint32_t count){
    g8ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL10Byte(uint32_t count){
    g16ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL16Byte(uint32_t count){
    g16ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBLLargeByte(uint32_t count){
    gLargeByteWriteInstrCount += count;
}
#else  // no MULTI_THREADED

// The following functions accummulates the number of bytes written in this basic block categorized by the write size. 

inline VOID InstructionContributionOfBBL1Byte(uint32_t count){    
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt1ByteWriteInstrCount  +=  count;
}
inline VOID InstructionContributionOfBBL2Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt2ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL4Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt4ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL8Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt8ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL10Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt10ByteWriteInstrCount += count;
}
inline VOID InstructionContributionOfBBL16Byte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt16ByteWriteInstrCount +=  count;
}
inline VOID InstructionContributionOfBBLLargeByte(uint32_t count){
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteInstrCount += count;
}

#endif // end MULTI_THREADED


// Called each time a new trace is JITed.
// Given a trace this function adds instruction to each instruction in the trace. 
// It also adds the trace to a hash table "gTraceShadowMap" to maintain the reverse mapping from a write instruction's position in CCT back to its IP.

inline VOID PopulateIPReverseMapAndAccountTraceInstructions(TRACE trace){
    
    uint32_t traceSize = TRACE_Size(trace);    
    ADDRINT * ipShadow = (ADDRINT * )malloc( (1 + traceSize) * sizeof(ADDRINT)); // +1 to hold the number of slots as a metadata
    ADDRINT  traceAddr = TRACE_Address(trace);
    uint32_t slot = 0;
    
    
    // give space to account for nSlots which we record later once we know nWrites
    ADDRINT * pNumWrites = ipShadow;
    ipShadow ++;
    
    gTraceShadowMap[traceAddr] = ipShadow ;
    for( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) ){
    	uint32_t inst1ByteSize = 0;
        uint32_t inst2ByteSize = 0;
    	uint32_t inst4ByteSize = 0;
    	uint32_t inst8ByteSize = 0;
    	uint32_t inst10ByteSize = 0;
    	uint32_t inst16ByteSize = 0;
    	uint32_t instLargeByteSize  = 0;
        
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            // instrument instruction
            Instruction(ins,slot);		
            if(INS_IsMemoryWrite(ins)){
                // put next slot in corresponding ins start location;
                ipShadow[slot] = INS_Address(ins);
                slot++;
                
                // get instruction info in trace                
                USIZE writeSize = INS_MemoryWriteSize(ins);
                switch(writeSize){
                    case 1: inst1ByteSize++;
                        break;
                    case 2:inst2ByteSize++;
                        break;
                    case 4:inst4ByteSize++;
                        break;
                    case 8:inst8ByteSize++;
                        break;
                    case 10:inst10ByteSize++;
                        break;
                    case 16:inst16ByteSize++;
                        break;
                    default:
                        instLargeByteSize += writeSize;
                        //assert(0 && "NOT IMPLEMENTED ... SHOULD NOT SEE large writes in trace");
                }
            }
        }
        
        
        // Insert a call to corresponding count routines before every bbl, passing the number of instructions
        
        // Increment Inst count by trace
        if (inst1ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL1Byte, IARG_UINT32, inst1ByteSize, IARG_END);     
        if (inst2ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL2Byte, IARG_UINT32, inst2ByteSize, IARG_END);     
        if (inst4ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL4Byte, IARG_UINT32, inst4ByteSize, IARG_END);     
        if (inst8ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL8Byte, IARG_UINT32, inst8ByteSize, IARG_END);     
        if (inst10ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL10Byte, IARG_UINT32, inst10ByteSize, IARG_END);     
        if (inst16ByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBL16Byte, IARG_UINT32, inst16ByteSize, IARG_END);     
        if (instLargeByteSize)
            BBL_InsertCall(bbl,IPOINT_BEFORE, (AFUNPTR) InstructionContributionOfBBLLargeByte, IARG_UINT32, instLargeByteSize, IARG_END);     
        
    }
    
    // Record the number of child write IPs i.e., number of "slots"
    *pNumWrites = slot;
    
}



#ifdef CONTINUOUS_DEADINFO
// TODO - support MT. I dont think this needs to be thread safe since PIN guarantees that.
inline void ** GetNextIPVecBuffer(uint32_t size){
    void ** ret = gPreAllocatedContextBuffer + gCurPreAllocatedContextBufferIndex;
    gCurPreAllocatedContextBufferIndex += size;
    assert( gCurPreAllocatedContextBufferIndex  < (PRE_ALLOCATED_BUFFER_SIZE)/(sizeof(void **)));
    return ret;
}
#endif //end CONTINUOUS_DEADINFO



// Does necessary work on a trace entry (called during runtime)
// 1. If landed here due to function call, then go down in CCT.
// 2. Look up the current trace under the CCT node creating new if if needed.
// 3. Update global iterators and curXXXX pointers.

inline void InstrumentTraceEntry(ADDRINT currentIp){
    
    // if landed due to function call, create a child context node
    
    if(gInitiatedCall){
        UpdateDataOnFunctionEntry(currentIp); // it will reset   gInitiatedCall      
    }
    
    // Check if a trace node with currentIp already exists under this context node
    if( (gTraceIter = (gCurrentContext->childTraces).find(currentIp)) != gCurrentContext->childTraces.end()) {
        gCurrentTrace = gTraceIter->second;
        gCurrentIpVector = gCurrentTrace->childIPs;
    } else {
        // Create new trace node and insert under the context node.
        
        TraceNode * newChild = new TraceNode();
        newChild->parent = gCurrentContext;
        newChild->address = currentIp;
    	uint64_t * currentTraceShadowIP = (uint64_t *) gTraceShadowMap[currentIp];
        uint64_t recordedSlots = currentTraceShadowIP[-1]; // present one behind
        if(recordedSlots){
#ifdef CONTINUOUS_DEADINFO
            // if CONTINUOUS_DEADINFO is set, then all ip vecs come from a fixed 4GB buffer
            newChild->childIPs  = (TraceNode **)GetNextIPVecBuffer(recordedSlots);
#else            //no CONTINUOUS_DEADINFO
            newChild->childIPs = (TraceNode **) malloc( (recordedSlots) * sizeof(TraceNode **) );
#endif //end CONTINUOUS_DEADINFO
            newChild->nSlots = recordedSlots;
            //cerr<<"\n***:"<<recordedSlots; 
            for(uint32_t i = 0 ; i < recordedSlots ; i++) {
                newChild->childIPs[i] = newChild;
            }
        } else {
            newChild->nSlots = 0;
            newChild->childIPs = 0;            
        }          
        
        gCurrentContext->childTraces[currentIp] = newChild;
        gCurrentTrace = newChild;
        gCurrentIpVector = gCurrentTrace->childIPs;
    }    
}

// Instrument a trace, take the first instruction in the first BBL and insert the analysis function before that
static void InstrumentTrace(TRACE trace, void * f){
    BBL bbl = TRACE_BblHead(trace);
    INS ins = BBL_InsHead(bbl);
    INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)InstrumentTraceEntry,IARG_INST_PTR,IARG_END);    
    PopulateIPReverseMapAndAccountTraceInstructions(trace);
}


static void OnSig(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *ctxtFrom,
                  CONTEXT *ctxtTo, INT32 sig, VOID *v) {
#if 0    
    switch (reason) {
        case CONTEXT_CHANGE_REASON_FATALSIGNAL:
            cerr<<"\n FATAL SIGNAL";
        case CONTEXT_CHANGE_REASON_SIGNAL:
            
            cerr<<"\n SIGNAL";
            
            gContextTreeVector[gContextTreeIndex].currentContext = gCurrentContext;
            gContextTreeIndex++;
            gCurrentContext = gContextTreeVector[gContextTreeIndex].currentContext;
            gRootContext = gContextTreeVector[gContextTreeIndex].rootContext;
            // rest will be set as we enter the signal callee
            gInitiatedCall = true; // so that we create a child node        
            
            break;
            
        case CONTEXT_CHANGE_REASON_SIGRETURN:
        {
            
            cerr<<"\n SIG RET";
            gContextTreeIndex--;
            gCurrentContext = gContextTreeVector[gContextTreeIndex].currentContext;
            gRootContext = gContextTreeVector[gContextTreeIndex].rootContext;
            gCurrentTraceIP = gCurrentContext->address;
            gCurrentTraceShadowIP = gTraceShadowMap[gCurrentTraceIP];
            break;
        }
        default: assert(0 && "\n BAD CONTEXT SWITCH");
    }
#endif    
}


// Analysis routine called on entering a function (found in symbol table only)
inline VOID UpdateDataOnFunctionEntry(ADDRINT currentIp){
    
    // if I enter here due to a tail-call, then we will make it a child under the parent context node
    if (!gInitiatedCall){
        gCurrentContext = gCurrentContext->parent;
    } else {
        // normal function call, so unset gInitiatedCall
        gInitiatedCall = false;
    }
    
    // Let GoDownCallChain do the work needed to setup pointers for child nodes.
    GoDownCallChain(currentIp);
    
}

// Analysis routine called on making a function call
inline VOID SetCallInitFlag(){
    gInitiatedCall = true;
}


// Instrumentation for the function entry (found in symbol table only).
// Get the first instruction of the first BBL and insert call to the analysis routine before it.

inline VOID InstrumentFunctionEntry(RTN rtn, void *f){
    RTN_Open(rtn);
    INS ins = RTN_InsHeadOnly(rtn);
    INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)UpdateDataOnFunctionEntry, IARG_INST_PTR,IARG_END);
    RTN_Close(rtn);    
}
#endif //end IP_AND_CCT

// MT
#ifndef MULTI_THREADED

// Analysis routine called on function entry. 
// If the target IP is a child, make it gCurrentContext, else add one under gCurrentContext and point gCurrentContext to the newly added

VOID GoDownCallChain(ADDRINT callee){
    if( ( gContextIter = (gCurrentContext->childContexts).find(callee)) != gCurrentContext->childContexts.end()) {
        gCurrentContext = gContextIter->second;
    } else {
        ContextNode * newChild =  new ContextNode();
        newChild->parent = gCurrentContext;
        newChild->address = callee;
        gCurrentContext->childContexts[callee] = newChild;
        gCurrentContext = newChild;
    }
}

// Analysis routine called on function return. 
// Point gCurrentContext to its parent, if we reach the root, set gInitiatedCall.

inline VOID GoUpCallChain(){
#ifdef IP_AND_CCT
    //assert(gCurrentContext->parent && "NULL PARENT CTXT");
    
    if (gCurrentContext->parent == gRootContext) {
        gInitiatedCall = true;
    }
    gCurrentContext = gCurrentContext->parent;
    
    // RET & CALL end a trace hence the target should trigger a new trace entry for us ... pray pray.
    
#else    // no IP_AND_CCT
    gCurrentContext = gCurrentContext->parent;
#endif    //end IP_AND_CCT
    
}
#else // MULTI_THREADED

// Analysis routine called on function entry. 
// If the target IP is a child, make it gContextTreeVector[pinTID].currentContext, else add one under gContextTreeVector[pinTID].currentContext and point gContextTreeVector[pinTID].currentContext to the newly added

VOID GoDownCallChain(ADDRINT callee){
    
    sparse_hash_map<ADDRINT, ContextNode *>::iterator contextIter;
    uint32_t pinTID = (uint32_t)PIN_ThreadId();
    
    if( ( contextIter = (gContextTreeVector[pinTID].currentContext->childContexts).find(callee)) != gContextTreeVector[pinTID].currentContext->childContexts.end()) {
        gContextTreeVector[pinTID].currentContext = contextIter->second;
    } else {
        ContextNode * newChild =  new ContextNode();
        newChild->parent = gContextTreeVector[pinTID].currentContext;
        newChild->address = callee;
        gContextTreeVector[pinTID].currentContext->childContexts[callee] = newChild;
        gContextTreeVector[pinTID].currentContext = newChild;
    }
}

// Analysis routine called on function return. 
// Point gContextTreeVector[pinTID].currentContext to its parent.

inline VOID GoUpCallChain(){
    uint32_t pinTID = (uint32_t)PIN_ThreadId();
    gContextTreeVector[pinTID].currentContext = gContextTreeVector[pinTID].currentContext->parent;
}
#endif //end ifndef MULTI_THREADED

// Instrumentation added at function call/ret sites

inline VOID ManageCallingContext(INS ins){
#ifdef TESTING_BYTES
	return; // no CCT
#endif // end TESTING_BYTES
    
    // manage context
    if(INS_IsProcedureCall(ins) ) {
#ifdef IP_AND_CCT
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) SetCallInitFlag,IARG_END);
#else        // no IP_AND_CCT        
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) GoDownCallChain, IARG_BRANCH_TARGET_ADDR, IARG_END);
#endif // end IP_AND_CCT        
    }else if(INS_IsRet(ins)){
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) GoUpCallChain, IARG_END);
    }
}


//// MT
#ifndef MULTI_THREADED 

// Initialized the fields of the root node of all context trees
VOID InitContextTree(){
#ifdef IP_AND_CCT
    // MAX 10 context trees
    gContextTreeVector.reserve(CONTEXT_TREE_VECTOR_SIZE);
    for(uint8_t i = 0 ; i < CONTEXT_TREE_VECTOR_SIZE ; i++){
        ContextNode * rootNode = new ContextNode();
        rootNode->address = 0;
        rootNode->parent = 0;        
        gContextTreeVector[i].rootContext = rootNode;
        gContextTreeVector[i].currentContext = rootNode;
    }
    gCurrentContext = gContextTreeVector[0].rootContext;
    gRootContext = gContextTreeVector[0].rootContext;
#else // no IP_AND_CCT
    gCurrentContext = gRootContext = new ContextNode();
    gRootContext->parent = 0;
    gRootContext->address = 0;
    
#endif // end IP_AND_CCT    
    
    // Init the  segv handler that may happen (due to PIN bug) when unwinding the stack during the printing    
    memset (&gSigAct, 0, sizeof(struct sigaction));
    gSigAct.sa_handler = SegvHandler;
    gSigAct.sa_flags = SA_NOMASK ;
    
}

#else // MULTI_THREADED

// Initialized the fields of the root node of all context trees
VOID InitContextTree(){
    // Multi threaded coded have a ContextTree per thread, my code assumes a max of 10 threads, for other values redefine CONTEXT_TREE_VECTOR_SIZE
    // We intialize all fields of the context tree which includes per thread stats
    
    
    // MAX 10 context trees
    gContextTreeVector.reserve(CONTEXT_TREE_VECTOR_SIZE);
    for(uint8_t i = 0 ; i < CONTEXT_TREE_VECTOR_SIZE ; i++){
        ContextNode * rootNode = new ContextNode();
        rootNode->address = 0;
        rootNode->parent = 0;        
        gContextTreeVector[i].rootContext = rootNode;
        gContextTreeVector[i].currentContext = rootNode;
        gContextTreeVector[i].mt1ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt2ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt4ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt8ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt10ByteWriteInstrCount = 0;
        gContextTreeVector[i].mt16ByteWriteInstrCount = 0;
        gContextTreeVector[i].mtLargeByteWriteInstrCount = 0;
        gContextTreeVector[i].mtLargeByteWriteByteCount = 0;
    }
    
    // Init the  segv handler that may happen (due to PIN bug) when unwinding the stack during the printing    
    
    memset (&gSigAct, 0, sizeof(struct sigaction));
    gSigAct.sa_handler = SegvHandler;
    gSigAct.sa_flags = SA_NOMASK ;
    
}

#endif // end MULTI_THREADED

// Given a address generated by the program, returns the corresponding shadow address FLOORED to  PAGE_SIZE
// If the shadow page does not exist a new one is MMAPed

inline uint8_t * GetOrCreateShadowBaseAddress(void * address) {
    // No entries at all ?
    uint8_t * shadowPage;
    uint8_t  *** l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if ( *l1Ptr == 0) {
        *l1Ptr =  (uint8_t **) calloc(1,LEVEL_2_PAGE_TABLE_SIZE);
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (1 + sizeof(uint8_t*)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        
        shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)] =  (uint8_t *) mmap(0, PAGE_SIZE * (1 + sizeof(uint8_t*)), PROT_WRITE | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    }
    
    return shadowPage;
}

// Given a address generated by the program, returns the corresponding shadow address FLOORED to  PAGE_SIZE
// If the shadow page does not exist none is created instead 0 is returned

inline uint8_t * GetShadowBaseAddress(void * address) {
    // No entries at all ?
    uint8_t * shadowPage;
    uint8_t *** l1Ptr = &gL1PageTable[LEVEL_1_PAGE_TABLE_SLOT(address)];
    if ( *l1Ptr == 0) {
        return 0;
    } else if((shadowPage = (*l1Ptr)[LEVEL_2_PAGE_TABLE_SLOT(address)]) == 0 ){
        return 0;
    }
    return shadowPage;
}


#ifndef MULTI_THREADED

// Increments bytes written in corresponding counters

inline VOID Do1ByteCount() {
	g1ByteWriteInstrCount ++;
}

inline VOID Do2ByteCount() {
	g2ByteWriteInstrCount ++;
}

inline VOID Do4ByteCount() {
	g4ByteWriteInstrCount ++;
}

inline VOID Do8ByteCount() {
	g8ByteWriteInstrCount ++;
}

inline VOID Do10ByteCount() {
	g10ByteWriteInstrCount ++;
}

inline VOID Do16ByteCount() {
	g16ByteWriteInstrCount ++;
}

inline VOID DoLargeByteCount(UINT32 cnt) {
#ifdef TESTING_BYTES    
    gLargeByteWriteInstrCount ++;
    gLargeByteWriteByteCount += cnt;    
#else //no  TESTING_BYTES   
	gLargeByteWriteInstrCount += cnt;
	//gTotalInstCount += cnt;
#endif //endof TESTING_BYTES
}

#else // MULTI_THREADED

// Increments bytes written in corresponding counters under the current thread's CCT

inline VOID Do1ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt1ByteWriteInstrCount ++;
}

inline VOID Do2ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt2ByteWriteInstrCount ++;
}

inline VOID Do4ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt4ByteWriteInstrCount ++;
}

inline VOID Do8ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt8ByteWriteInstrCount ++;
}

inline VOID Do10ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt10ByteWriteInstrCount ++;
}

inline VOID Do16ByteCount() {
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mt16ByteWriteInstrCount ++;
}

inline VOID DoLargeByteCount(UINT32 cnt) {    
#ifdef TESTING_BYTES
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteInstrCount ++;
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteByteCount += cnt;
    
#else // no TESTING_BYTES    
    gContextTreeVector[(uint32_t)PIN_ThreadId()].mtLargeByteWriteInstrCount += cnt;
	//gTotalInstCount += cnt;
#endif //endof TESTING_BYTES
}

#endif // end ifndef MULTI_THREADED


#if defined(CONTINUOUS_DEADINFO)

// make 64bit hash from 2 32bit deltas from 
// remove lower 3 bits so that when we need more than 4 GB HASH still continues to work

#define CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, oldCtxt, hashVar)  \
{\
uint64_t key = (uint64_t) (((void**)oldCtxt) - gPreAllocatedContextBuffer); \
hashVar = key << 32;\
key = (uint64_t) (((void**)curCtxt) - gPreAllocatedContextBuffer); \
hashVar |= key;\
}

#else // no defined(CONTINUOUS_DEADINFO)

#define CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, oldCtxt, hashVar)  \
{\
uint64_t key = (uint64_t) curCtxt; \
key = (~key) + (key << 18);\
key = key ^ (key >> 31);\
key = key * 21;\
key = key ^ (key >> 11);\
key = key + (key << 6);\
key = key ^ (key >> 22);\
hashVar = (uint64_t) (key << 32);\
key = (uint64_t) (oldCtxt);\
key = (~key) + (key << 18);\
key = key ^ (key >> 31);\
key = key * 21; \
key = key ^ (key >> 11);\
key = key + (key << 6);\
key = key ^ (key >> 22);\
hashVar = hashVar | ((int) key);\
}

#endif // end defined(CONTINUOUS_DEADINFO)


#ifdef IP_AND_CCT
#define OLD_CTXT (*lastIP)
#ifndef MULTI_THREADED
#define CUR_CTXT (&gCurrentIpVector[slot])
#else // no MULTI_THREADED
#define CUR_CTXT (assert( 0 && " NYI"))
#endif // end of ifndef MULTI_THREADED
#else // else IP_AND_CCT
#define OLD_CTXT (*lastIP)

#ifndef MULTI_THREADED
#define CUR_CTXT (gCurrentContext)
#else //MULTI_THREADED
#define CUR_CTXT (gContextTreeVector[PIN_ThreadId()].currentContext)
#endif // end of ifndef MULTI_THREADED

#endif // end of IP_AND_CCT




// NO FALSE NEGATIVES is always defined 


#if defined(CONTINUOUS_DEADINFO)

#define DECLARE_HASHVAR(name) uint64_t name

#define REPORT_DEAD(curCtxt, lastCtxt,hashVar, size) do { \
CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, lastCtxt,hashVar)  \
if ( (gDeadMapIt = DeadMap.find(hashVar))  == DeadMap.end()) {    \
DeadMap.insert(std::pair<uint64_t, uint64_t>(hashVar,size)); \
} else {    \
(gDeadMapIt->second) += size;    \
}   \
}while(0)

#else // no defined(CONTINUOUS_DEADINFO)
#define DECLARE_HASHVAR(name) uint64_t name

#define REPORT_DEAD(curCtxt, lastCtxt,hashVar, size) do { \
CONTEXT_HASH_128BITS_TO_64BITS(curCtxt, lastCtxt,hashVar)  \
if ( (gDeadMapIt = DeadMap.find(hashVar))  == DeadMap.end()) {    \
DeadInfo deadInfo = { lastCtxt,  curCtxt, size };   \
DeadMap.insert(std::pair<uint64_t, DeadInfo>(hashVar,deadInfo)); \
} else {    \
(gDeadMapIt->second.count) += size;    \
}   \
}while(0)

#endif // end defined(CONTINUOUS_DEADINFO)

#define REPORT_IF_DEAD(mask, curCtxt, lastCtxt, hashVar) do {if (state & (mask)){ \
REPORT_DEAD(curCtxt, lastCtxt,hashVar, 1);\
}}while(0)


#ifdef TESTING_BYTES
#define RecordNByteMemWrite(type, size, sizeSTR) do{\
uint8_t * status = GetOrCreateShadowBaseAddress(addr);\
if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - size - 2)){\
type state = *((type*)(status +  PAGE_OFFSET((uint64_t)addr)));\
if ( state != sizeSTR##_BYTE_READ_ACTION) {\
if (state == sizeSTR##_BYTE_WRITE_ACTION) {\
gFullyKilling##size ++;\
} else {\
gPartiallyKilling##size ++;\
for(type s = state; s != 0 ; s >>= 8)\
if(s & 0xff)\
gPartiallyDeadBytes##size++;\
}\
} \
*((type* )(status +  PAGE_OFFSET((uint64_t)addr))) = sizeSTR##_BYTE_WRITE_ACTION;\
} else {\
type state = *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr)));        \
*((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = ONE_BYTE_WRITE_ACTION;\
uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 :0;\
for(uint8_t i = 1 ; i < size; i++){\
status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);            \
state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));\
if(state == ONE_BYTE_WRITE_ACTION)\
deadBytes++;            \
*((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;\
}\
if(deadBytes == size)\
gFullyKilling##size ++;\
else if(deadBytes){\
gPartiallyKilling##size ++;\
gPartiallyDeadBytes##size += deadBytes;\
}        \
}\
}while(0)

#endif // end TESTING_BYTES


// Analysis routines to update the shadow memory for different size READs and WRITEs


VOID Record1ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    if (status) {
        // NOT NEEDED status->lastIP = ip;
        *(status + PAGE_OFFSET((uint64_t)addr))  = ONE_BYTE_READ_ACTION;
    }
}


#ifdef TESTING_BYTES
inline VOID Record1ByteMemWrite(VOID * addr) {
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    if(*(status +  PAGE_OFFSET((uint64_t)addr)) == ONE_BYTE_WRITE_ACTION){
        gFullyKilling1 ++;		
    }
    *(status +  PAGE_OFFSET((uint64_t)addr)) = ONE_BYTE_WRITE_ACTION;
}

#else  // no TESTING_BYTES
VOID Record1ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif // end IP_AND_CCT                          
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    
    void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint8_t*));
    if (*(status +  PAGE_OFFSET((uint64_t)addr)) == ONE_BYTE_WRITE_ACTION) {
        
        DECLARE_HASHVAR(myhash);
        REPORT_DEAD(CUR_CTXT, OLD_CTXT,myhash, 1);
        
    } else {
        *(status +  PAGE_OFFSET((uint64_t)addr)) = ONE_BYTE_WRITE_ACTION;
    }
    *lastIP = CUR_CTXT;
}
#endif // end TESTING_BYTES

inline VOID Record1ByteMemWriteWithoutDead(
#ifdef IP_AND_CCT
                                           uint32_t slot,
#endif
                                           VOID * addr) {
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    
    void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint8_t*));
    *(status +  PAGE_OFFSET((uint64_t)addr)) = ONE_BYTE_WRITE_ACTION;
    *lastIP = CUR_CTXT;
}


VOID Record2ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) != PAGE_OFFSET_MASK){
        if(status){
            *((uint16_t *)(status + PAGE_OFFSET((uint64_t)addr)))  = TWO_BYTE_READ_ACTION;
        }
    } else {
        if(status){
            *(status + PAGE_OFFSET_MASK)  = ONE_BYTE_READ_ACTION;
        }
        status = GetShadowBaseAddress(((char *)addr) + 1);
        if(status){
            *status  = ONE_BYTE_READ_ACTION;
        }
    }
}
#ifdef TESTING_BYTES
VOID Record2ByteMemWrite(VOID * addr) {
 	RecordNByteMemWrite(uint16_t, 2, TWO);
}
#else // no bytes test 
VOID Record2ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) != PAGE_OFFSET_MASK){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint8_t*));
        uint16_t state = *((uint16_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        if ( state != TWO_BYTE_READ_ACTION) { 
            DECLARE_HASHVAR(myhash);
            // fast path where all bytes are dead by same context
            if ( state == TWO_BYTE_WRITE_ACTION && lastIP[0] == lastIP[1]) {
                REPORT_DEAD(CUR_CTXT, (*lastIP), myhash, 2);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path 
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00ff, CUR_CTXT, lastIP[0], myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0xff00, CUR_CTXT, lastIP[1], myhash);
                // update state for all
                *((uint16_t* )(status +  PAGE_OFFSET((uint64_t)addr))) = TWO_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
        	*((uint16_t* )(status +  PAGE_OFFSET((uint64_t)addr))) = TWO_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;        
    } else {
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            addr);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 1);
    }
}
#endif  // end TESTING_BYTES

VOID Record4ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) -  (PAGE_OFFSET_MASK - 3);
    if(overflow <= 0 ){
        if(status){
            *((uint32_t *)(status + PAGE_OFFSET((uint64_t)addr)))  = FOUR_BYTE_READ_ACTION;
        }
    } else {
        if(status){
            status += PAGE_OFFSET((uint64_t)addr);
            for(int nonOverflowBytes = 0 ; nonOverflowBytes < 4 - overflow; nonOverflowBytes++){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
        status = GetShadowBaseAddress(((char *)addr) + 4); // +4 so that we get next page
        if(status){
            for( ; overflow; overflow--){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
    }
}

#ifdef TESTING_BYTES
VOID Record4ByteMemWrite(VOID * addr) {
    RecordNByteMemWrite(uint32_t, 4, FOUR);
}
#else // no TESTING_BYTES

VOID Record4ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - 2)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint8_t*));
        uint32_t state = *((uint32_t*)(status +  PAGE_OFFSET((uint64_t)addr)));   
        
        if (state != FOUR_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            if ( state == FOUR_BYTE_WRITE_ACTION &&
                ipZero == lastIP[0] && ipZero == lastIP[1] && ipZero  == lastIP[2] && ipZero  == lastIP[3] ) {
                REPORT_DEAD(CUR_CTXT, ipZero, myhash, 4);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path 
                // byte 1 dead ?
                REPORT_IF_DEAD(0x000000ff, CUR_CTXT, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x0000ff00,CUR_CTXT, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x00ff0000,CUR_CTXT, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0xff000000,CUR_CTXT, lastIP[3], myhash);
                // update state for all
                *((uint32_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = FOUR_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
        	*((uint32_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = FOUR_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;        
    } else {
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            addr);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 1);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 2);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 3);
    }
}
#endif // end TESTING_BYTES

VOID Record8ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) -  (PAGE_OFFSET_MASK - 7);
    if(overflow <= 0 ){
        if(status){
            *((uint64_t *)(status + PAGE_OFFSET((uint64_t)addr)))  = EIGHT_BYTE_READ_ACTION;
        }
    } else {
        if(status){
            status += PAGE_OFFSET((uint64_t)addr);
            for(int nonOverflowBytes = 0 ; nonOverflowBytes < 8 - overflow; nonOverflowBytes++){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }
        status = GetShadowBaseAddress(((char *)addr) + 8); // +8 so that we get next page
        if(status){
            for( ; overflow; overflow--){
                *(status++)  = ONE_BYTE_READ_ACTION;
            }
        }       
    }
}

#ifdef TESTING_BYTES
VOID Record8ByteMemWrite(VOID * addr) {
    RecordNByteMemWrite(uint64_t, 8, EIGHT);
}
#else // no TESTING_BYTES

VOID Record8ByteMemWrite(
#ifdef IP_AND_CCT
                         uint32_t slot,
#endif
                         VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - 6)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint8_t*));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));   
        
        if (state != EIGHT_BYTE_READ_ACTION) {
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            if ( state == EIGHT_BYTE_WRITE_ACTION &&
                ipZero  == lastIP[1] && ipZero  == lastIP[2] &&
                ipZero  == lastIP[3] && ipZero  == lastIP[4] &&
                ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7] ) {
                REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                // State is already written, so no need to dead write in a tool that detects dead writes
            } else {
                // slow path 
                // byte 1 dead ?
                REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
                // byte 2 dead ?
                REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[1], myhash);
                // byte 3 dead ?
                REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[2], myhash);
                // byte 4 dead ?
                REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[3], myhash);
                // byte 5 dead ?
                REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[4], myhash);
                // byte 6 dead ?
                REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[5], myhash);
                // byte 7 dead ?
                REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[6], myhash);
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[7], myhash);
                
                // update state for all
                *((uint64_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
            }
        } else {
            // record as written
        	*((uint64_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;
        lastIP[4] = CUR_CTXT;
        lastIP[5] = CUR_CTXT;
        lastIP[6] = CUR_CTXT;
        lastIP[7] = CUR_CTXT;        
    } else {
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            addr);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 1);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 2);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 3);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 4);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 5);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 6);
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            ((char *) addr ) + 7);
    }
}
#endif      // end TESTING_BYTES

VOID Record10ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) -  (PAGE_OFFSET_MASK - 15);
    if(overflow <= 0 ){
        if(status){
            *((uint64_t *)(status + PAGE_OFFSET((uint64_t)addr)))  = EIGHT_BYTE_READ_ACTION;
            *((uint16_t *)(status + PAGE_OFFSET(((uint64_t)addr + 8))))  = TWO_BYTE_READ_ACTION;
        }
    } else {
        // slow path
        Record8ByteMemRead(addr);
        Record2ByteMemRead((char*)addr + 8);
    }
}



#ifdef TESTING_BYTES
VOID Record10ByteMemWrite(VOID * addr) {
    
    
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - 14)){
        uint64_t state1 = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        uint16_t state2 = *((uint64_t*)(status +  PAGE_OFFSET(((uint64_t)addr) + 8 )));
        if ( (state1 != EIGHT_BYTE_READ_ACTION) || (state2 != TWO_BYTE_READ_ACTION)) {
            if ( (state1 == EIGHT_BYTE_WRITE_ACTION) && (state2 == TWO_BYTE_WRITE_ACTION)) {
                gFullyKilling10 ++;
            } else {
                gPartiallyKilling10 ++;
                for(uint64_t s = state1; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes10++;
                for(uint16_t s = state2; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes10++;
            }
        }
        *((uint64_t* )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        *((uint16_t* )(status +  PAGE_OFFSET(((uint64_t)addr) + 8))) = TWO_BYTE_WRITE_ACTION;
    } else {
        uint8_t state = *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = ONE_BYTE_WRITE_ACTION;
        uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 :0;
        for(uint8_t i = 1 ; i < 10; i++){
            status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);
            state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));
            if(state == ONE_BYTE_WRITE_ACTION)
                deadBytes++;
            *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
        }
        if(deadBytes == 10)
            gFullyKilling10 ++;
        else if(deadBytes){
            gPartiallyKilling10 ++;
            gPartiallyDeadBytes10 += deadBytes;
        }
    }
    
}
#else // no TESTING_BYTES

VOID Record10ByteMemWrite(
#ifdef IP_AND_CCT
                          uint32_t slot,
#endif
                          VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - 8)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint8_t*));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));   
        if (state != EIGHT_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            if ( state == EIGHT_BYTE_WRITE_ACTION && 
                ipZero  == lastIP[1] && ipZero  == lastIP[2] && 
                ipZero  == lastIP[3] && ipZero  == lastIP[4] && 
                ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7] ) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[1], myhash);                                                            
            	// byte 3 dead ?
            	REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[2], myhash);
            	// byte 4 dead ?
            	REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[3], myhash); 
            	// byte 5 dead ?
            	REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[4], myhash);                                                            
            	// byte 6 dead ?
            	REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[5], myhash);
            	// byte 7 dead ?
            	REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[6], myhash); 
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[7], myhash); 
                
                // update state of these 8 bytes could be some overwrites
                *((uint64_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;                
            }
        } else {
            // update state of these 8 bytes
            *((uint64_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }
        // This looks like it was a bug, should not OR with 0xffffffffffff0000 
        // state = (*((uint16_t*) (status +  PAGE_OFFSET((uint64_t)addr) + 8)) )| 0xffffffffffff0000;   
        state = (*((uint16_t*) (status +  PAGE_OFFSET((uint64_t)addr) + 8)) );   
        if (state != TWO_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[8];
            // fast path where all bytes are dead by same context
            if ( state == TWO_BYTE_WRITE_ACTION && 
                ipZero == lastIP[9]) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 2);
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0xff00,CUR_CTXT, lastIP[9], myhash);                                                            
                // update state
                *((uint16_t * )(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = TWO_BYTE_WRITE_ACTION;                
            }
        } else {
            // Update state of these 2 bytes
            *((uint16_t * )(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = TWO_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;
        lastIP[4] = CUR_CTXT;
        lastIP[5] = CUR_CTXT;
        lastIP[6] = CUR_CTXT;
        lastIP[7] = CUR_CTXT;
        lastIP[8] = CUR_CTXT;
        lastIP[9] = CUR_CTXT;
    } else {
        for(int i = 0; i < 10; i++) {
            Record1ByteMemWrite(
#ifdef IP_AND_CCT
                                slot,
#endif
                                ((char *) addr ) + i);
        }
    }
}
#endif // end TESTING_BYTES



VOID Record16ByteMemRead( VOID * addr) {
    uint8_t * status = GetShadowBaseAddress(addr);
    // status == 0 if not created.
    int overflow = PAGE_OFFSET((uint64_t)addr) -  (PAGE_OFFSET_MASK - 15);
    if(overflow <= 0 ){
        if(status){
            *((uint64_t *)(status + PAGE_OFFSET((uint64_t)addr)))  = EIGHT_BYTE_READ_ACTION;
            *((uint64_t *)(status + PAGE_OFFSET(((uint64_t)addr + 8))))  = EIGHT_BYTE_READ_ACTION;
        }
    } else {
        // slow path
        Record8ByteMemRead(addr);
        Record8ByteMemRead((char*)addr + 8);
    }
}


#ifdef TESTING_BYTES
VOID Record16ByteMemWrite(VOID * addr) {
    
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - 14)){
        uint64_t state1 = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        uint64_t state2 = *((uint64_t*)(status +  PAGE_OFFSET(((uint64_t)addr) + 8 )));
        if ( (state1 != EIGHT_BYTE_READ_ACTION) || (state2 != EIGHT_BYTE_READ_ACTION)) {
            if ( (state1 == EIGHT_BYTE_WRITE_ACTION) && (state2 == EIGHT_BYTE_WRITE_ACTION)) {
                gFullyKilling16 ++;
            } else {
                gPartiallyKilling16 ++;
                for(uint64_t s = state1; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes16++;
                for(uint64_t s = state2; s != 0 ; s >>= 8)
                    if(s & 0xff)
                        gPartiallyDeadBytes16++;
            }
        }
        *((uint64_t* )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        *((uint64_t* )(status +  PAGE_OFFSET(((uint64_t)addr) + 8))) = EIGHT_BYTE_WRITE_ACTION;
    } else {
        uint8_t state = *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr)));
        *((uint8_t*)(status +  PAGE_OFFSET((uint64_t)addr))) = ONE_BYTE_WRITE_ACTION;
        uint8_t deadBytes =  state == ONE_BYTE_WRITE_ACTION ? 1 :0;
        for(uint8_t i = 1 ; i < 16; i++){
            status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);
            state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));
            if(state == ONE_BYTE_WRITE_ACTION)
                deadBytes++;
            *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
        }
        if(deadBytes == 16)
            gFullyKilling16 ++;
        else if(deadBytes){
            gPartiallyKilling16 ++;
            gPartiallyDeadBytes16 += deadBytes;
        }
    }
    
}
#else // no TESTING_BYTES

VOID Record16ByteMemWrite(
#ifdef IP_AND_CCT
                          uint32_t slot,
#endif
                          VOID * addr) {
    uint8_t * status = GetOrCreateShadowBaseAddress(addr);
    // status == 0 if not created.
    if(PAGE_OFFSET((uint64_t)addr) <  (PAGE_OFFSET_MASK - 14)){
        void **lastIP = (void **)(status + PAGE_SIZE +  PAGE_OFFSET((uint64_t)addr) * sizeof(uint8_t*));
        uint64_t state = *((uint64_t*)(status +  PAGE_OFFSET((uint64_t)addr)));   
        if (state != EIGHT_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[0];
            // fast path where all bytes are dead by same context
            if ( state == EIGHT_BYTE_WRITE_ACTION && 
                ipZero  == lastIP[1] && ipZero  == lastIP[2] && 
                ipZero  == lastIP[3] && ipZero  == lastIP[4] && 
                ipZero  == lastIP[5] && ipZero  == lastIP[6] && ipZero  == lastIP[7] ) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[1], myhash);                                                            
            	// byte 3 dead ?
            	REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[2], myhash);
            	// byte 4 dead ?
            	REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[3], myhash); 
            	// byte 5 dead ?
            	REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[4], myhash);                                                            
            	// byte 6 dead ?
            	REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[5], myhash);
            	// byte 7 dead ?
            	REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[6], myhash); 
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[7], myhash); 
                
                // update state of these 8 bytes could be some overwrites
                *((uint64_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;                
            }
        } else {
            // update state of these 8 bytes
            *((uint64_t * )(status +  PAGE_OFFSET((uint64_t)addr))) = EIGHT_BYTE_WRITE_ACTION;
        }
        
        state = *((uint64_t*) (status +  PAGE_OFFSET((uint64_t)addr) + 8));   
        if (state != EIGHT_BYTE_READ_ACTION) {
            
            DECLARE_HASHVAR(myhash);
            void * ipZero = lastIP[8];
            // fast path where all bytes are dead by same context
            if ( state == EIGHT_BYTE_WRITE_ACTION && 
                ipZero == lastIP[9] && ipZero  == lastIP[10] && ipZero  == lastIP[11] && 
                ipZero  == lastIP[12] && ipZero  == lastIP[13] && 
                ipZero  == lastIP[14] && ipZero  == lastIP[15]) {
            	REPORT_DEAD(CUR_CTXT, ipZero, myhash, 8);
                // No state update needed
            } else { 
                // slow path 
            	// byte 1 dead ?
            	REPORT_IF_DEAD(0x00000000000000ff, CUR_CTXT, ipZero, myhash);
            	// byte 2 dead ?
            	REPORT_IF_DEAD(0x000000000000ff00,CUR_CTXT, lastIP[9], myhash);                                                            
            	// byte 3 dead ?
            	REPORT_IF_DEAD(0x0000000000ff0000,CUR_CTXT, lastIP[10], myhash);
            	// byte 4 dead ?
            	REPORT_IF_DEAD(0x00000000ff000000,CUR_CTXT, lastIP[11], myhash); 
            	// byte 5 dead ?
            	REPORT_IF_DEAD(0x000000ff00000000,CUR_CTXT, lastIP[12], myhash);                                                            
            	// byte 6 dead ?
            	REPORT_IF_DEAD(0x0000ff0000000000,CUR_CTXT, lastIP[13], myhash);
            	// byte 7 dead ?
            	REPORT_IF_DEAD(0x00ff000000000000,CUR_CTXT, lastIP[14], myhash); 
                // byte 8 dead ?
                REPORT_IF_DEAD(0xff00000000000000,CUR_CTXT, lastIP[15], myhash); 
                // update state
                *((uint64_t * )(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = EIGHT_BYTE_WRITE_ACTION;                
            }
        } else {
            // Update state of these 8 bytes
            *((uint64_t * )(status +  PAGE_OFFSET(((uint64_t)addr + 8)))) = EIGHT_BYTE_WRITE_ACTION;
        }
        
        lastIP[0] = CUR_CTXT;
        lastIP[1] = CUR_CTXT;
        lastIP[2] = CUR_CTXT;
        lastIP[3] = CUR_CTXT;
        lastIP[4] = CUR_CTXT;
        lastIP[5] = CUR_CTXT;
        lastIP[6] = CUR_CTXT;
        lastIP[7] = CUR_CTXT;
        lastIP[8] = CUR_CTXT;
        lastIP[9] = CUR_CTXT;
        lastIP[10] = CUR_CTXT;
        lastIP[11] = CUR_CTXT;
        lastIP[12] = CUR_CTXT;
        lastIP[13] = CUR_CTXT;
        lastIP[14] = CUR_CTXT;
        lastIP[15] = CUR_CTXT;        
    } else {
        for(int i = 0; i < 16; i++) {
            Record1ByteMemWrite(
#ifdef IP_AND_CCT
                                slot,
#endif
                                ((char *) addr ) + i);
        }
    }
}
#endif  // end TESTING_BYTES


//// IMPROVE ME 
VOID RecordLargeMemRead( VOID * addr, UINT32 size) {
    for(UINT32 i = 0 ;i < size; i++){
        uint8_t * status = GetShadowBaseAddress(((char *) addr) + i);
        if(status){
            *(status + PAGE_OFFSET(((uint64_t)addr + i)))  = ONE_BYTE_READ_ACTION;
        }
    }	
}

#ifdef  TESTING_BYTES

VOID RecordLargeMemWrite(VOID * addr, UINT32 size) {
    uint8_t * status ;
    uint8_t state;
    uint8_t deadBytes =  0;
    for(uint8_t i = 0 ; i < size; i++){
	    status = GetOrCreateShadowBaseAddress(((char *) addr ) + i);
	    state = *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i))));
	    if(state == ONE_BYTE_WRITE_ACTION)
		    deadBytes++;
	    *((uint8_t*)(status +  PAGE_OFFSET((((uint64_t)addr) + i)))) = ONE_BYTE_WRITE_ACTION;
    }
    if(deadBytes == size){
	    gFullyKillingLarge ++;
    }
    else if(deadBytes){
	    gPartiallyKillingLarge ++;
    }
    // for large we just add them all to partially dead
    gPartiallyDeadBytesLarge += deadBytes;
    //assert(0 && "NOT IMPLEMENTED LARGE WRITE BYTE");
	
}

#else // no TESTING_BYTES

//// IMPROVE  ME 
VOID RecordLargeMemWrite(
#ifdef IP_AND_CCT
                         uint32_t     slot,
#endif
                         VOID * addr, UINT32 size) {
    for(UINT32 i = 0 ; i < size ; i++) {	
        // report dead for first byte if needed
        Record1ByteMemWrite(
#ifdef IP_AND_CCT
                            slot,
#endif
                            (char *)addr + i);
        
    } 
}
#endif      // end TESTING_BYTES

void InspectMemRead(VOID * addr, UINT32 sz){
    cerr<<"\n"<<addr<<":"<<sz;
}


#ifdef MULTI_THREADED
// MT support
volatile bool gDSLock;
inline VOID TakeLock(){
    do{
        while(gDSLock);   
    }while(!__sync_bool_compare_and_swap(&gDSLock,0,1));
}

inline VOID ReleaseLock(){
    gDSLock = 0;
}
#endif // end MULTI_THREADED




// Is called for every instruction and instruments reads and writes
#ifdef IP_AND_CCT
VOID Instruction(INS ins, uint32_t slot) {
#else
    VOID Instruction(INS ins, VOID * v) {
#endif            
        
        // Note: predicated instructions are correctly handled as given in PIN's sample example pinatrace.cpp
        
        /* Comment taken from PIN sample : 
         Instruments memory accesses using a predicated call, i.e.
         the instrumentation is called iff the instruction will actually be executed.
         
         The IA-64 architecture has explicitly predicated instructions.
         On the IA-32 and Intel(R) 64 architectures conditional moves and REP
         prefixed instructions appear as predicated instructions in Pin. */
        
        
        // How may memory operations?
        UINT32 memOperands = INS_MemoryOperandCount(ins);
        
        // If it is a memory write then count the number of bytes written 
#ifndef IP_AND_CCT  
        // IP_AND_CCT uses traces to detect instructions & their write size hence no instruction level counting is needed
        if(INS_IsMemoryWrite(ins)){
            USIZE writeSize = INS_MemoryWriteSize(ins);
            switch(writeSize){
                case 1:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do1ByteCount, IARG_END);
                    break;
                case 2:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do2ByteCount, IARG_END);
                    break;
                case 4:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do4ByteCount, IARG_END);
                    break;
                case 8:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do8ByteCount, IARG_END);
                    break;
                case 10:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do10ByteCount, IARG_END);
                    break;
                case 16:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Do16ByteCount, IARG_END);
                    break;
                default:
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) DoLargeByteCount,IARG_MEMORYWRITE_SIZE, IARG_END);
            }                
        }
#endif //end  ifndef IP_AND_CCT         
        
        
        // If it is a call/ret instruction, we need to adjust the CCT.
        ManageCallingContext(ins);
        
        
        // In Multi-threaded skip call, ret and JMP instructions
#ifdef MULTI_THREADED
        if(INS_IsBranchOrCall(ins) || INS_IsRet(ins)){
            return;
        }
#endif //end MULTI_THREADED
        
#ifdef MULTI_THREADED        
        // Support for MT
        // Acquire the lock before starting the analysis routine since we need analysis routine and original instruction to run atomically.
        bool lockNeeded = false;
        if (memOperands) {
            for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) TakeLock, IARG_END);
                lockNeeded = true;
                break;
            }
        }
#endif //end MULTI_THREADED        
        
        // Iterate over each memory operand of the instruction and add Analysis routine to check for dead writes.
        // We correctly handle instructions that do both read and write.
        
        for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
            UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
            switch(refSize){
                case 1:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record1ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);                        
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record1ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 2:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record2ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {   
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record2ByteMemWrite, 
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 4:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record4ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record4ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 8:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record8ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record8ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 10:{
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) Record10ByteMemRead, IARG_MEMORYOP_EA,memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record10ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,
                                                 memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                case 16:{ // SORRY! XMM regs use 16 bits :((
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,(AFUNPTR) Record16ByteMemRead, IARG_MEMORYOP_EA, memOp, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) Record16ByteMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,memOp, IARG_END);
                        
                    }
                }
                    break;
                    
                default: {
                    // seeing some stupid 10, 16, 512 (fxsave)byte operations. Suspecting REP-instructions.
                    if (INS_MemoryOperandIsRead(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,(AFUNPTR) RecordLargeMemRead, IARG_MEMORYOP_EA, memOp, IARG_MEMORYREAD_SIZE, IARG_END);
                        
                    }
                    if (INS_MemoryOperandIsWritten(ins, memOp)) {
                        
                        INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                                 (AFUNPTR) RecordLargeMemWrite,
#ifdef IP_AND_CCT
                                                 IARG_UINT32, slot,
#endif
                                                 IARG_MEMORYOP_EA,memOp, IARG_MEMORYWRITE_SIZE, IARG_END);
                        
                    }
                }
                    break;
                    //assert( 0 && "BAD refSize");
                    
            }
        }
        
#ifdef MULTI_THREADED
        // Support for MT
        // release the lock if we had taken it
        if (lockNeeded) {            
            INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR) ReleaseLock, IARG_END);
        }
#endif //end MULTI_THREADED
        
    }
    
    inline bool DeadInfoComparer(const DeadInfo &first, const DeadInfo &second) {
        return first.count > second.count ? true : false;
    }
    
    
    // Returns true if the given address belongs to one of the loaded binaries
    inline bool IsValidIP(ADDRINT ip){
        for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
            if(ip >= IMG_LowAddress(img) && ip <= IMG_HighAddress(img)){
                return true;
            }
        }
        return false;
    }
    
    // Returns true if the given deadinfo belongs to one of the loaded binaries
    inline bool IsValidIP(DeadInfo  di){
        bool res = false;
        for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
            if((ADDRINT)di.firstIP >= IMG_LowAddress(img) && (ADDRINT)di.firstIP <= IMG_HighAddress(img)){
                res = true;
                break;	
            }
        }
        if(!res)
            return false;
        for( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) ){
            if((ADDRINT)di.secondIP >= IMG_LowAddress(img) && (ADDRINT)di.secondIP <= IMG_HighAddress(img)){  
                return true;
            }
        }
        return false;
        
    }
    
    // Returns true if the address in the given context node corresponds to a sinature (assembly code: ) that corresponds to a .PLT section
    // Sample PLt signatire : ff 25 c2 24 21 00       jmpq   *2172098(%rip)        # 614340 <quoting_style_args+0x2a0>
    inline bool IsValidPLTSignature(ContextNode * ctxt){
        if( (*((unsigned char*)ctxt->address) == 0xff) && (*((unsigned char*)ctxt->address +1) == 0x25))
            return true;
        return false;
    }
    
    void SegvHandler(int sig){
        longjmp(env, 1);
    }
    
    bool EndsWith(string & str, string & substr){
        size_t i = str.rfind(substr);
        return (i != string::npos) && (i == (str.length() - substr.length()));
    }
    
#ifdef  MULTI_THREADED   
    
    // Return true if the given ContextNode is one of the root context nodes
    int IsARootContextNode(ContextNode * curContext){
        for(int i = 0 ; i < CONTEXT_TREE_VECTOR_SIZE; i++)
            if(gContextTreeVector[i].rootContext == curContext)
                return i;
        
        return -1;
    }
    
    // Returns true if the two given nodes belong to the same ContextTree
    bool IsSameContextTree(ContextNode * ctxt1, ContextNode * ctxt2){
        while(ctxt1->parent){            
            ctxt1 = ctxt1->parent;
        }    
        while(ctxt2->parent){            
            ctxt2 = ctxt2->parent;
        }
        return ctxt1 == ctxt2;        
    }
    
    
    
    // Returns the total N-byte size writes across all CCTs
    uint64_t GetTotalNByteWrites(uint32_t size) {
        uint64_t total = 0;
        for(int i = 0 ; i < CONTEXT_TREE_VECTOR_SIZE; i++) {
            switch (size) {
                case 1:
                {
                    total += gContextTreeVector[i].mt1ByteWriteInstrCount;
                    break;
                }
                case 2:
                {
                    total += gContextTreeVector[i].mt2ByteWriteInstrCount;
                    break;
                }
                case 4:
                {
                    total += gContextTreeVector[i].mt4ByteWriteInstrCount;
                    break;
                }
                case 8:
                {
                    total += gContextTreeVector[i].mt8ByteWriteInstrCount;
                    break;
                }
                case 10:
                {
                    total += gContextTreeVector[i].mt10ByteWriteInstrCount;
                    break;
                }
                case 16:
                {
                    total += gContextTreeVector[i].mt16ByteWriteInstrCount;
                    break;
                }
                default:{
                    // Not too sure :(
                    total += gContextTreeVector[i].mtLargeByteWriteInstrCount;
                    break;
                }
            }
            
        }//end for    
        return total;
    }
#endif //end MULTI_THREADED
    
    // Given a context node (curContext), traverses up in the chain till the root and prints the entire calling context 
    
    VOID PrintFullCallingContext(ContextNode * curContext){
        int depth = 0;
#ifdef MULTI_THREADED        
        int root;
#endif         //end MULTI_THREADED
        // set sig handler
        struct sigaction old;
        sigaction(SIGSEGV,&gSigAct,&old);
        
        // Dont print if the depth is more than MAX_CCT_PRINT_DEPTH since files become too large
        while(curContext && (depth ++ < MAX_CCT_PRINT_DEPTH)){            
            if(IsValidIP(curContext->address)){
                if(PIN_UndecorateSymbolName(RTN_FindNameByAddress(curContext->address),UNDECORATION_COMPLETE) == ".plt"){
                    if(setjmp(env) == 0) {
                        
                        if(IsValidPLTSignature(curContext) ) { 
                            uint64_t nextByte = (uint64_t) curContext->address + 2;
                            int * offset = (int*) nextByte;
                            
                            uint64_t nextInst = (uint64_t) curContext->address + 6;
                            ADDRINT loc = *((uint64_t *)(nextInst + *offset));
                            if(IsValidIP(loc)){
                                fprintf(gTraceFile,"\n!%s",PIN_UndecorateSymbolName(RTN_FindNameByAddress(loc),UNDECORATION_COMPLETE).c_str() );
                            }else{
                                fprintf(gTraceFile,"\nIN PLT BUT NOT VALID GOT");	
                            } 
                        } else {
                            fprintf(gTraceFile,"\nUNRECOGNIZED PLT SIGNATURE");	
                            
                            //fprintf(gTraceFile,"\n plt plt plt %x", * ((UINT32*)curContext->address));	
                            //for(int i = 1; i < 4 ; i++)
                            //	fprintf(gTraceFile," %x",  ((UINT32 *)curContext->address)[i]);	
                            
                        }
                    }   
                    else {
                        fprintf(gTraceFile,"\nCRASHED !!");	
                    }
                } else {
                    fprintf(gTraceFile,"\n%s",PIN_UndecorateSymbolName(RTN_FindNameByAddress(curContext->address),UNDECORATION_COMPLETE).c_str() );
                }
            } 
#ifndef MULTI_THREADED 
            else if (curContext == gRootContext){
                fprintf(gTraceFile, "\nROOT_CTXT");	
            }
#else //MULTI_THREADED
            else if ( (root=IsARootContextNode(curContext)) != -1){
                fprintf(gTraceFile, "\nROOT_CTXT_THREAD %d", root);	
            } 
#endif //end  ifndef MULTI_THREADED            
            else if (curContext->address == 0){
                fprintf(gTraceFile, "\nIND CALL");	
            } else{
                fprintf(gTraceFile, "\nBAD IP ");	
            }
            curContext = curContext->parent;
        }
        //reset sig handler
        sigaction(SIGSEGV,&old,0);
    }
    
    
    // Returns true of the given ContextNode is in memset() function
    int IsInMemset(ContextNode * curContext){
        int retVal = 0;
        
        // set sig handler
        struct sigaction old;
        sigaction(SIGSEGV,&gSigAct,&old);
        if(curContext){
            if(IsValidIP(curContext->address)){
                string fun = PIN_UndecorateSymbolName(RTN_FindNameByAddress(curContext->address),UNDECORATION_COMPLETE);
                string sub = "memset";
                if(fun == ".plt"){
                    if(setjmp(env) == 0) {
                        
                        if(IsValidPLTSignature(curContext) ) {
                            uint64_t nextByte = (uint64_t) curContext->address + 2;
                            int * offset = (int*) nextByte;
                            
                            uint64_t nextInst = (uint64_t) curContext->address + 6;
                            ADDRINT loc = *((uint64_t *)(nextInst + *offset));
                            if(IsValidIP(loc)){
                                string s = PIN_UndecorateSymbolName(RTN_FindNameByAddress(loc),UNDECORATION_COMPLETE);
                                retVal = EndsWith(s, sub);
                            }
                        } 
                        
                    }
                } else if (EndsWith(fun,sub)){
                    retVal = true;
                }
            } 
        }
        //reset sig handler
        sigaction(SIGSEGV,&old,0);
        return retVal;
    }
    
    // Given the DeadInfo data, prints the two Calling contexts
    VOID PrintCallingContexts(const DeadInfo & di){
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
        PrintFullCallingContext((ContextNode *) di.firstIP);
        fprintf(gTraceFile,"\n***********************\n");
        PrintFullCallingContext((ContextNode *)di.secondIP);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
    }
    
    
#ifdef TESTING_BYTES
    // Prints the collected statistics on writes along with their sizes and dead/killing writes and their sizes
    inline VOID PrintInstructionBreakdown(){
        fprintf(gTraceFile,"\n%lu,%lu,%lu,%lu ",g1ByteWriteInstrCount, gFullyKilling1, gPartiallyKilling1, gPartiallyDeadBytes1);
        fprintf(gTraceFile,"\n%lu,%lu,%lu,%lu ",g2ByteWriteInstrCount, gFullyKilling2, gPartiallyKilling2, gPartiallyDeadBytes2);
        fprintf(gTraceFile,"\n%lu,%lu,%lu,%lu ",g4ByteWriteInstrCount, gFullyKilling4, gPartiallyKilling4, gPartiallyDeadBytes4);
        fprintf(gTraceFile,"\n%lu,%lu,%lu,%lu ",g8ByteWriteInstrCount, gFullyKilling8, gPartiallyKilling8, gPartiallyDeadBytes8);
        fprintf(gTraceFile,"\n%lu,%lu,%lu,%lu ",g10ByteWriteInstrCount, gFullyKilling10, gPartiallyKilling10, gPartiallyDeadBytes10);
        fprintf(gTraceFile,"\n%lu,%lu,%lu,%lu ",g16ByteWriteInstrCount, gFullyKilling16, gPartiallyKilling16, gPartiallyDeadBytes16);        
        fprintf(gTraceFile,"\n%lu,%lu,%lu,%lu,%lu ",gLargeByteWriteInstrCount,  gFullyKillingLarge, gPartiallyKillingLarge, gLargeByteWriteByteCount, gPartiallyDeadBytesLarge);        
    }
#endif //end TESTING_BYTES
    
#ifdef GATHER_STATS
    inline void PrintStats(
#ifdef IP_AND_CCT
                           list<DeadInfoForPresentation> & deadList,
#else // no IP_AND_CCT
                           list<DeadInfo> & deadList,
#endif  // end IP_AND_CCT
                           uint64_t deads){
#ifdef IP_AND_CCT        
        list<DeadInfoForPresentation>::iterator it = deadList.begin();
#else //no IP_AND_CCT        
        list<DeadInfo>::iterator it = deadList.begin();
#endif //end IP_AND_CCT        
        uint64_t bothMemsetContribution = 0;
        uint64_t bothMemsetContexts = 0;
        uint64_t singleMemsetContribution = 0;
        uint64_t singleMemsetContexts = 0;
        uint64_t runningSum = 0;
        int curContributionIndex = 1;
        
        uint64_t deadCount = 0;
        for (; it != deadList.end(); it++) {
            deadCount++;
#ifdef IP_AND_CCT        
            int memsetVal = IsInMemset(it->pMergedDeadInfo->context1);
            memsetVal += IsInMemset(it->pMergedDeadInfo->context2);
#else //no IP_AND_CCT
            int memsetVal = IsInMemset((ContextNode*) it->firstIP);
            memsetVal += IsInMemset((ContextNode*) it->secondIP);
#endif //end IP_AND_CCT            
            if(memsetVal == 2){
                bothMemsetContribution += it->count;	
                bothMemsetContexts++;
            } else if (memsetVal > 0){
                singleMemsetContribution += it->count;	
                singleMemsetContexts++;
            }
            
            runningSum += it->count;
            double contrib = runningSum * 100.0 / gTotalDead;
            if(contrib >= curContributionIndex){
                while(contrib >= curContributionIndex){
                    fprintf(statsFile,",%lu:%e",deadCount, deadCount * 100.0 / deads);
                    curContributionIndex++;
                }	
            }
        }
        static bool firstTime = true;
        if(firstTime){
            fprintf(statsFile,"\nbothMemsetContribution %lu = %e", bothMemsetContribution, bothMemsetContribution * 100.0 / gTotalDead);
            fprintf(statsFile,"\nsingleMemsetContribution %lu = %e", singleMemsetContribution, singleMemsetContribution * 100.0 / gTotalDead);
            fprintf(statsFile,"\nbothMemsetContext %lu = %e", bothMemsetContexts, bothMemsetContexts * 100.0 / deads);
            fprintf(statsFile,"\nsingleMemsetContext %lu = %e", singleMemsetContexts, singleMemsetContexts * 100.0 / deads);
            fprintf(statsFile,"\nTotalDeadContexts %lu", deads);
            firstTime = false;
        }        
    }
#endif //end GATHER_STATS    
    
    
    
    
    inline uint64_t GetMeasurementBaseCount(){
        // byte count
        
#ifdef MULTI_THREADED        
        uint64_t measurementBaseCount =  GetTotalNByteWrites(1) + 2 * GetTotalNByteWrites(2) + 4 * GetTotalNByteWrites(4) + 8 * GetTotalNByteWrites(8) + 10 * GetTotalNByteWrites(10)+ 16 * GetTotalNByteWrites(16) + GetTotalNByteWrites(-1);
#else //no MULTI_THREADED        
        uint64_t measurementBaseCount =  g1ByteWriteInstrCount + 2 * g2ByteWriteInstrCount + 4 * g4ByteWriteInstrCount + 8 * g8ByteWriteInstrCount + 10 * g10ByteWriteInstrCount + 16 * g16ByteWriteInstrCount + gLargeByteWriteInstrCount;
#endif  //end MULTI_THREADED
        return measurementBaseCount;        
    }
    
    // Prints the collected statistics on writes along with their sizes
    inline void PrintEachSizeWrite(){
#ifdef MULTI_THREADED
        fprintf(gTraceFile,"\n1:%lu",GetTotalNByteWrites(1));
        fprintf(gTraceFile,"\n2:%lu",GetTotalNByteWrites(2));
        fprintf(gTraceFile,"\n4:%lu",GetTotalNByteWrites(4));
        fprintf(gTraceFile,"\n8:%lu",GetTotalNByteWrites(8));
        fprintf(gTraceFile,"\n10:%lu",GetTotalNByteWrites(10));
        fprintf(gTraceFile,"\n16:%lu",GetTotalNByteWrites(16));
        fprintf(gTraceFile,"\nother:%lu",GetTotalNByteWrites(-1));
        
#else  //no MULTI_THREADED        
        fprintf(gTraceFile,"\n1:%lu",g1ByteWriteInstrCount);
        fprintf(gTraceFile,"\n2:%lu",g2ByteWriteInstrCount);
        fprintf(gTraceFile,"\n4:%lu",g4ByteWriteInstrCount);
        fprintf(gTraceFile,"\n8:%lu",g8ByteWriteInstrCount);
        fprintf(gTraceFile,"\n10:%lu",g10ByteWriteInstrCount);
        fprintf(gTraceFile,"\n16:%lu",g16ByteWriteInstrCount);
        fprintf(gTraceFile,"\nother:%lu",gLargeByteWriteInstrCount);
#endif //end MULTI_THREADED
    }
    
    
    
#ifdef IP_AND_CCT  
    // Given a pointer (i.e. slot) within a trace node, returns the IP corresponding to that slot
    inline ADDRINT GetIPFromInfo(void * ptr){
		TraceNode * traceNode = *((TraceNode **) ptr);
        
		// what is my slot id ?
		uint32_t slotNo = 0;
		for( ; slotNo < traceNode->nSlots; slotNo++){
			if (&traceNode->childIPs[slotNo] == (TraceNode **) ptr)
				break;
		}
        
		ADDRINT *ip = (ADDRINT *) gTraceShadowMap[traceNode->address] ;
		return ip[slotNo];
	}
    
    // Given a pointer (i.e. slot) within a trace node, returns the Line number corresponding to that slot
	inline string GetLineFromInfo(void * ptr){
		ADDRINT ip = GetIPFromInfo(ptr);
        string file;
        INT32 line;
        PIN_GetSourceLocation(ip, NULL, &line,&file);
		std::ostringstream retVal;
		retVal << line;
		return file + ":" + retVal.str();
    }    
    
    
    inline bool MergedDeadInfoComparer(const DeadInfoForPresentation & first, const DeadInfoForPresentation  &second) {
        return first.count > second.count ? true : false;
    }
    
    
    // Prints the complete calling context including the line nunbers and the context's contribution, given a DeadInfo 
    inline VOID PrintIPAndCallingContexts(const DeadInfoForPresentation & di, uint64_t measurementBaseCount){
        
        fprintf(gTraceFile,"\n%lu = %e",di.count, di.count * 100.0 / measurementBaseCount);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line1.c_str());                                    
#else // no MERGE_SAME_LINES
        string file;
        INT32 line;
        PIN_GetSourceLocation( di.pMergedDeadInfo->ip1, NULL, &line,&file);
        fprintf(gTraceFile,"\n%p:%s:%d",(void *)(di.pMergedDeadInfo->ip1),file.c_str(),line);                                    
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context1);
        fprintf(gTraceFile,"\n***********************\n");
#ifdef MERGE_SAME_LINES
        fprintf(gTraceFile,"\n%s",di.pMergedDeadInfo->line2.c_str());                                    
#else //no MERGE_SAME_LINES        
        PIN_GetSourceLocation( di.pMergedDeadInfo->ip2, NULL, &line,&file);
        fprintf(gTraceFile,"\n%p:%s:%d",(void *)(di.pMergedDeadInfo->ip2),file.c_str(),line);
#endif //end MERGE_SAME_LINES        
        PrintFullCallingContext(di.pMergedDeadInfo->context2);
        fprintf(gTraceFile,"\n-------------------------------------------------------\n");
    }
    
    
    // On each Unload of a loaded image, the accummulated deadness information is dumped
    VOID ImageUnload(IMG img, VOID * v) {
        fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
        
        
        // Update gTotalInstCount first 
        uint64_t measurementBaseCount =  GetMeasurementBaseCount(); 
        
        fprintf(gTraceFile, "\nTotal Instr = %lu", measurementBaseCount);
        fflush(gTraceFile);
        
#if defined(CONTINUOUS_DEADINFO)
        //sparse_hash_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
        hash_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
        //dense_hash_map<uint64_t, uint64_t>::iterator mapIt = DeadMap.begin();
#else //no defined(CONTINUOUS_DEADINFO)        
        dense_hash_map<uint64_t, DeadInfo>::iterator mapIt = DeadMap.begin();
        //hash_map<uint64_t, DeadInfo>::iterator mapIt = DeadMap.begin();
#endif //end defined(CONTINUOUS_DEADINFO)        
        map<MergedDeadInfo,uint64_t> mergedDeadInfoMap;
        
        
#if defined(CONTINUOUS_DEADINFO)
        for (; mapIt != DeadMap.end(); mapIt++) {
            MergedDeadInfo tmpMergedDeadInfo;
            uint64_t hash = mapIt->first;
            TraceNode ** ctxt1 = (TraceNode **)(gPreAllocatedContextBuffer + (hash >> 32));
            TraceNode ** ctxt2 = (TraceNode **)(gPreAllocatedContextBuffer + (hash & 0xffffffff));
            
            tmpMergedDeadInfo.context1 = (*ctxt1)->parent;
            tmpMergedDeadInfo.context2 = (*ctxt2)->parent;
#ifdef MERGE_SAME_LINES
            tmpMergedDeadInfo.line1 = GetLineFromInfo(ctxt1);
            tmpMergedDeadInfo.line2 = GetLineFromInfo(ctxt2);
#else  //no MERGE_SAME_LINES            
            tmpMergedDeadInfo.ip1 = GetIPFromInfo(ctxt1);
            tmpMergedDeadInfo.ip2 = GetIPFromInfo(ctxt2);
#endif //end MERGE_SAME_LINES            
            map<MergedDeadInfo,uint64_t>::iterator tmpIt;
            if( (tmpIt = mergedDeadInfoMap.find(tmpMergedDeadInfo)) == mergedDeadInfoMap.end()) {
                mergedDeadInfoMap[tmpMergedDeadInfo] = mapIt->second;
            } else {
                
                tmpIt->second  += mapIt->second;
            }
        }
        
	    // clear dead map now
        DeadMap.clear();
        
        
#else   // no defined(CONTINUOUS_DEADINFO)        
        for (; mapIt != DeadMap.end(); mapIt++) {
            MergedDeadInfo tmpMergedDeadInfo;
            tmpMergedDeadInfo.context1 = (*((TraceNode **)((mapIt->second).firstIP)))->parent;
            tmpMergedDeadInfo.context2 = (*((TraceNode **)((mapIt->second).secondIP)))->parent;
#ifdef MERGE_SAME_LINES
            tmpMergedDeadInfo.line1 = GetLineFromInfo(mapIt->second.firstIP);
            tmpMergedDeadInfo.line2 = GetLineFromInfo(mapIt->second.secondIP);
#else //no MERGE_SAME_LINES            
            tmpMergedDeadInfo.ip1 = GetIPFromInfo(mapIt->second.firstIP);
            tmpMergedDeadInfo.ip2 = GetIPFromInfo(mapIt->second.secondIP);
#endif //end MERGE_SAME_LINES            
            map<MergedDeadInfo,uint64_t>::iterator tmpIt;
            if( (tmpIt = mergedDeadInfoMap.find(tmpMergedDeadInfo)) == mergedDeadInfoMap.end()) {
                mergedDeadInfoMap[tmpMergedDeadInfo] = mapIt->second.count;
            } else {
                
                tmpIt->second  += mapIt->second.count;
            }
        }
        
	    // clear dead map now
        DeadMap.clear();
#endif  // end defined(CONTINUOUS_DEADINFO)        
        
        map<MergedDeadInfo,uint64_t>::iterator it = mergedDeadInfoMap.begin();	
        list<DeadInfoForPresentation> deadList;
        for (; it != mergedDeadInfoMap.end(); it ++) {
            DeadInfoForPresentation deadInfoForPresentation;
            deadInfoForPresentation.pMergedDeadInfo = &(it->first);
            deadInfoForPresentation.count = it->second;
            deadList.push_back(deadInfoForPresentation);
        }
        deadList.sort(MergedDeadInfoComparer);
        
	    //present and delete all
        
        list<DeadInfoForPresentation>::iterator dipIter = deadList.begin();
        PIN_LockClient();
        uint64_t deads = 0;
        for (; dipIter != deadList.end(); dipIter++) {
#ifdef MULTI_THREADED
            assert(0 && "NYI");    
#endif //end MULTI_THREADED            
            // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
            if(deads < MAX_DEAD_CONTEXTS_TO_LOG){
                try{
                    PrintIPAndCallingContexts(*dipIter, measurementBaseCount);
                } catch (...) {
                    fprintf(gTraceFile,"\nexcept");
                }
            } else {
                // print only dead count
#ifdef PRINT_ALL_CTXT
                fprintf(gTraceFile,"\nCTXT_DEAD_CNT:%lu = %e",dipIter->count, dipIter->count * 100.0 / measurementBaseCount);
#endif                //end PRINT_ALL_CTXT
            }
            
            gTotalDead += dipIter->count ;
            deads++;
        }
        
        
        PrintEachSizeWrite();
        
#ifdef TESTING_BYTES
        PrintInstructionBreakdown();
#endif //end TESTING_BYTES        
        
#ifdef GATHER_STATS
        PrintStats(deadList, deads);
#endif //end GATHER_STATS        
        
        mergedDeadInfoMap.clear();
        deadList.clear();
        PIN_UnlockClient();
	}
    
#else //no IP_AND_CCT
    // On each Unload of a loaded image, the accummulated deadness information is dumped (JUST the CCT case, no IP)
    VOID ImageUnload(IMG img, VOID * v) {
        fprintf(gTraceFile, "\nUnloading %s", IMG_Name(img).c_str());
        static bool done = false;
        
        //if (done)
        //    return;
        
        //if(IMG_Name(img) != "/opt/apps/openmpi/1.3.3-gcc/lib/openmpi/mca_osc_rdma.so")
        //if(IMG_Name(img) != "/users/mc29/mpi_dead/Gauss.exe")
        //if(IMG_Name(img) != "/users/mc29/chombo/chombo/Chombo-4.petascale/trunk/benchmark/AMRGodunovFBS/exec/amrGodunov3d.Linux.64.mpicxx.mpif90.OPTHIGH.MPI.ex")
        //return;
        
        // get  measurementBaseCount first 
        uint64_t measurementBaseCount =  GetMeasurementBaseCount();         
        fprintf(gTraceFile, "\nTotal Instr = %lu", measurementBaseCount);
        fflush(gTraceFile);
        
#if defined(CONTINUOUS_DEADINFO)
        hash_map<uint64_t, uint64_t>::iterator mapIt;
        //dense_hash_map<uint64_t, uint64_t>::iterator mapIt;
        //sparse_hash_map<uint64_t, uint64_t>::iterator mapIt;
#else // no defined(CONTINUOUS_DEADINFO)        
        dense_hash_map<uint64_t, DeadInfo>::iterator mapIt;
        //hash_map<uint64_t, DeadInfo>::iterator mapIt;
#endif  //end defined(CONTINUOUS_DEADINFO)        
        list<DeadInfo> deadList;
        
        
#if defined(CONTINUOUS_DEADINFO)
        for (mapIt = DeadMap.begin(); mapIt != DeadMap.end(); mapIt++) {
            uint64_t hash = mapIt->first;
            uint64_t elt1 = (hash >> 32) * sizeof(void **) / sizeof(ContextNode);
            uint64_t elt2 = (hash & 0xffffffff) * sizeof(void **) / sizeof(ContextNode);
            void ** ctxt1 = (void**) ((ContextNode*)gPreAllocatedContextBuffer + elt1);
            void ** ctxt2 = (void**)((ContextNode*)gPreAllocatedContextBuffer + elt2);
            DeadInfo tmpDeadInfo = {(void*)ctxt1, (void*)ctxt2,  mapIt->second};
            deadList.push_back(tmpDeadInfo);
        }
        DeadMap.clear();
        
#else   // no defined(CONTINUOUS_DEADINFO)        
        for (mapIt = DeadMap.begin(); mapIt != DeadMap.end(); mapIt++) {
            deadList.push_back(mapIt->second);
        }
        DeadMap.clear();
#endif  // end defined(CONTINUOUS_DEADINFO)        
        deadList.sort(DeadInfoComparer);
        list<DeadInfo>::iterator it = deadList.begin();
        PIN_LockClient();
        uint64_t deads = 0;
        for (; it != deadList.end(); it++) {
            
#ifdef MULTI_THREADED
            // for MT, if they are from the same CCT, skip
            if(IsSameContextTree((ContextNode*) it->firstIP, (ContextNode*)it->secondIP)){
            	gTotalDead += it->count ;
                continue;
            } 
#endif //end MULTI_THREADED            
            
            // Print just first MAX_DEAD_CONTEXTS_TO_LOG contexts
            if(deads < MAX_DEAD_CONTEXTS_TO_LOG){
                try{
                    fprintf(gTraceFile,"\n%lu = %e",it->count, it->count * 100.0 / measurementBaseCount);
                    PrintCallingContexts(*it);
                } catch (...) {
                    fprintf(gTraceFile,"\nexcept");
                }
            } else {
#ifdef PRINT_ALL_CTXT
                // print only dead count
                fprintf(gTraceFile,"\nCTXT_DEAD_CNT:%lu = %e",it->count, it->count * 100.0 / measurementBaseCount);
#endif //end PRINT_ALL_CTXT                
            }
            
#ifdef MULTI_THREADED
            gTotalMTDead += it->count ;
#endif //end MULTI_THREADED            
            gTotalDead += it->count ;
            deads++;
        }
        
        PrintEachSizeWrite();
        
        
#ifdef TESTING_BYTES
        PrintInstructionBreakdown();
#endif //end TESTING_BYTES        
        
#ifdef GATHER_STATS
        PrintStats(deadList, deads);
#endif //end GATHER_STATS        
        
        deadList.clear();
        PIN_UnlockClient();
        done = true;
    }
    
#endif   //end IP_AND_CCT    
    
    
    
    // On program termination output all gathered data and statistics
    VOID Fini(INT32 code, VOID * v) {
        // byte count
        uint64_t measurementBaseCount = GetMeasurementBaseCount();
        fprintf(gTraceFile, "\n#deads");
        fprintf(gTraceFile, "\nGrandTotalWrites = %lu",measurementBaseCount);
        fprintf(gTraceFile, "\nGrandTotalDead = %lu = %e%%",gTotalDead, gTotalDead * 100.0 / measurementBaseCount);
#ifdef MULTI_THREADED        
        fprintf(gTraceFile, "\nGrandTotalMTDead = %lu = %e%%",gTotalMTDead, gTotalMTDead * 100.0 / measurementBaseCount);
#endif // end MULTI_THREADED        
        fprintf(gTraceFile, "\n#eof");
        fclose(gTraceFile);
    }
    
    
    INT32 Usage() {
        PIN_ERROR("DeadSPy is a PinTool which tracks each memory access and reports dead writes.\n" + KNOB_BASE::StringKnobSummary() + "\n");        
        return -1;        
    }
    
    // When we make System calls we need to update the shadow regions with the effect of the system call
    // TODO: handle other system calls. Currently only SYS_write is handled.
    
    VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std,
                      VOID *v) {
        ADDRINT number = PIN_GetSyscallNumber(ctxt, std);
        switch (number) {
            case SYS_write: {
                char * bufStart = (char *) PIN_GetSyscallArgument(ctxt, std, 1);
                char * bufEnd = bufStart
                + (size_t) PIN_GetSyscallArgument(ctxt, std, 2);
#ifdef DEBUG
                printf("\n WRITE %p - %p\n",bufStart, bufEnd);
#endif //end DEBUG                
                while (bufStart < bufEnd)
                    Record1ByteMemRead( bufStart++);
            }
                break;
            default: 
                break;//NOP     
        }
        
    }
    
    
    
    // Initialized the needed data structures before launching the target program
    void InitDeadSpy(int argc, char *argv[]){
        
        
#if defined(CONTINUOUS_DEADINFO)
        // prealloc 4GB (or 32GB) ip vec
        // IMPROVEME ... actually this can be as high as 24 GB since lower 3 bits are always zero for pointers
        gPreAllocatedContextBuffer = (void **) mmap(0, PRE_ALLOCATED_BUFFER_SIZE, PROT_WRITE
                                                    | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        // start from index 1 so that we can use 0 as empty key for the google hash table
        gCurPreAllocatedContextBufferIndex = 1;
        //DeadMap.set_empty_key(0);
#else //no defined(CONTINUOUS_DEADINFO)        
        // FIX ME FIX ME ... '3092462950186394283' may not be the right one to use, but dont know what to use :(.
        // 3092462950186394283 is derived as the hash of two '0' contexts which is impossible.
        DeadMap.set_empty_key(3092462950186394283);
#endif //end defined(CONTINUOUS_DEADINFO)        
        // 0 can never be a ADDRINT key of a trace        
#ifdef IP_AND_CCT
        //gTraceShadowMap.set_empty_key(0);
#endif //end   IP_AND_CCT   
        
        
        
        // Create output file 
        
        char name[MAX_FILE_PATH] = "deadspy.out.";
        char * envPath = getenv("DEADSPY_OUTPUT_FILE");
        if(envPath){
            // assumes max of MAX_FILE_PATH
            strcpy(name, envPath);
        } 
        gethostname(name + strlen(name), MAX_FILE_PATH - strlen(name));
        pid_t pid = getpid();
        sprintf(name + strlen(name),"%d",pid);
        cerr << "\n Creating dead info file at:" << name << "\n";
        
        gTraceFile = fopen(name, "w");
        // print the arguments passed
        fprintf(gTraceFile,"\n");
        for(int i = 0 ; i < argc; i++){
            fprintf(gTraceFile,"%s ",argv[i]);
        }
        fprintf(gTraceFile,"\n");
        
#ifdef GATHER_STATS
        string statFileName(name);
        statFileName += ".stats";
        statsFile = fopen(statFileName.c_str() , "w");
        fprintf(statsFile,"\n");
        for(int i = 0 ; i < argc; i++){
            fprintf(statsFile,"%s ",argv[i]);
        }
        fprintf(statsFile,"\n");
#endif //end   GATHER_STATS      
        
        // Initialize the context tree
        InitContextTree();        
    }
    
    // Main for DeadSpy, initialize the tool, register instrumentation functions and call the target program.
    
    int main(int argc, char *argv[]) {
        
        // Initialize PIN
        if (PIN_Init(argc, argv))
            return Usage();
        
        // Initialize Symbols, we need them to report functions and lines
        PIN_InitSymbols();
        
        // Intialize DeadSpy
        InitDeadSpy(argc, argv);
        
        
#ifdef IP_AND_CCT
        // Register for context change in case of signals .. Actually this is never used. // Todo: - fix me
        PIN_AddContextChangeFunction(OnSig, 0);
        
        // Instrument the entry to each "known" function. Some functions may not be known
        RTN_AddInstrumentFunction(InstrumentFunctionEntry,0);
        
        // Since some functions may not be known, instrument every "trace"
        TRACE_AddInstrumentFunction(InstrumentTrace,0);
#else //no IP_AND_CCT        
        //IP_AND_CCT case calls via TRACE_AddInstrumentFunction
        
        // When line level info in not needed, simplt instrument each instruction
        INS_AddInstrumentFunction(Instruction, 0);
#endif //end  IP_AND_CCT    
        
        // capture write or other sys call that read from user space
        PIN_AddSyscallEntryFunction(SyscallEntry, 0);
        
        
        // Add a function to report entire stats at the termination.
        PIN_AddFiniFunction(Fini, 0);
        
        // Register ImageUnload to be called when an image is unloaded
        IMG_AddUnloadFunction(ImageUnload, 0);
        
        // Launch program now
        PIN_StartProgram();
        return 0;        
    }

