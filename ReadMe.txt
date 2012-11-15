DeadSpy is a tool to detect dead writes in an execution of a program.




--------------------------------------------------
	Supported platform
--------------------------------------------------
1. Linux x86_64

--------------------------------------------------
	Requirements	
--------------------------------------------------

1. Download and install the latest PIN tool matching your platform from
http://www.pintool.org/downloads.html . 

2. Download and install google hash tables (Sparsehash) source from
http://code.google.com/p/sparsehash/

--------------------------------------------------
	Compiling
--------------------------------------------------


1. make SPARSEHASH_PATH=<path to google sparse hash table directory>
PIN_PATH=<path to PIN installation directory> 
 
 e.g. 
   make SPARSEHASH_PATH=/projects/hpc/software/sparsehash-1.11/
PIN_PATH=/projects/hpc/pin-2.9-39599-gcc.3.4.6-ia32_intel64-linux/

This produces deadspy.so

--------------------------------------------------
	Running
--------------------------------------------------

Run deadspy as a pin tool.

E.g., /projects/hpc/pin-2.9-39599-gcc.3.4.6-ia32_intel64-linux/pin -t
/projects/hpc/deadspy/deadspy.so -- ls


This generates the deadspy output file in ./deadspy.out.MachineNamePid

To override the default output file set the environment variable
DEADSPY_OUTPUT_FILE to a path and deadspy will produce results at
$DEADSPY_OUTPUT_FILEMachineNamePid
E.g. if you set DEADSPY_OUTPUT_FILE to /user/me/dump and your machine name is
MyMachine and the Pid is 1234, the deadspy log will be at
/user/me/dumpMyMachine1234

By default DeadSpy logs provide only call paths that contain the callstack but
no line number information. If you need line-level attribution, compile
DeadSpy with the IP_AND_CCT flag.
E.g.: make IP_AND_CCT=1  SPARSEHASH_PATH=<path> PIN_PATH=<path>

By default, when IP_AND_CCT=1 is set, DeadSpy shows different IPs corresponding to the same source line as coming from different contexts. If you want to see all IPs that correspond to the same source line as one context set MERGE_SAME_LINES=1 flag.
E.g.: make IP_AND_CCT=1 MERGE_SAME_LINES=1  SPARSEHASH_PATH=<path> PIN_PATH=<path>

By default DeadSpy assumes a single-threaded application. If you need support
for multi threading, compile DeadSpy with MULTI_THREADED flag.
E.g.: make MULTI_THREADED=1  SPARSEHASH_PATH=<path> PIN_PATH=<path>

Currently, we do not support line-level attribution in multi-threaded case,
hence simultaneous use of MULTI_THREADED=1 and IP_AND_CCT=1 is not supported.


By default, DeadSpy prints the top most 1000 dead contexts. This is sufficient for all practical purposes and keeps the logs small. If you want a different value pass MAX_DEAD_CONTEXTS_TO_LOG=<number> during the make step.
E.g.: make MAX_DEAD_CONTEXTS_TO_LOG=99999  SPARSEHASH_PATH=<path> PIN_PATH=<path>

 

