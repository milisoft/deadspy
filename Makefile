CXX = g++
CFLAGS = -c -Wno-deprecated -Wall -Werror -Wno-unknown-pragmas  -O3 -fomit-frame-pointer -fno-stack-protector -fno-strict-aliasing -DNDEBUG -DBIGARRAY_MULTIPLIER=2 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX
INCLUDES = -I$(SPARSEHASH_PATH)/src -I$(PIN_PATH)/extras/xed2-intel64/include -I$(PIN_PATH)/extras/components/include -I$(PIN_PATH)/source/include -I$(PIN_PATH)/source/include/gen
LIBRARIES = -L$(PIN_PATH)/extras/xed2-intel64/lib -L$(PIN_PATH)/intel64/lib -L$(PIN_PATH)/intel64/lib-ext -lpin -lxed -ldwarf -lelf -ldl
LINKFLAGS = -Wl,--hash-style=sysv -shared -Wl,-Bsymbolic -Wl,--version-script=$(PIN_PATH)/source/include/pintool.ver

ifeq ($(IP_AND_CCT), 1)
 CFLAGS := -DIP_AND_CCT $(CFLAGS)
endif

ifeq ($(MULTI_THREADED), 1)
 CFLAGS := -DMULTI_THREADED $(CFLAGS)
endif

ifdef MAX_DEAD_CONTEXTS_TO_LOG
 CFLAGS := -DMAX_DEAD_CONTEXTS_TO_LOG=$(MAX_DEAD_CONTEXTS_TO_LOG) $(CFLAGS)
endif

ifeq ($(MERGE_SAME_LINES), 1)
 CFLAGS := -DMERGE_SAME_LINES $(CFLAGS)
endif


all: deadspy.so

deadspy.so: deadspy.cpp
ifndef  SPARSEHASH_PATH
	$(error echo "SPARSEHASH_PATH NOT SET!!")
endif
ifndef  PIN_PATH
	$(error echo "PIN_PATH NOT SET!!")
endif
	$(CXX)  $(CFLAGS) $(INCLUDES) -o deadspy.o deadspy.cpp
	$(CXX)  $(LINKFLAGS) -o deadspy.so deadspy.o  $(LIBRARIES)

clean:
	rm -f deadspy.o deadspy.so

