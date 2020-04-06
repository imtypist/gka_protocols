# Generated automatically from Makefile.in by configure.
#
# str_api Makefile.in
# Wrote by: Damian Hasse
#
# CLIQUES Project                                                  
# Information Sciences Institute                                   
# University of Southern California   
#

#OS
OS_NAME=linux

#SSL stuff
SSL_INCLUDE=/usr/include/openssl

# STR stuff
STR_DIR=.
COMMON_DIR=../common
STR_DIST = $(STR_DIR)/$(OS_NAME)
STR_INCLUDE=$(STR_DIR)/src
STR_OBJDIR=$(STR_DIR)/$(OS_NAME)/obj
STR_LIBDIR=$(STR_DIR)/$(OS_NAME)/lib
STR_BINDIR=$(STR_DIR)/$(OS_NAME)/bin
SRC=$(STR_DIR)/src/str_api.c 
HDR=$(STR_INCLUDE)/str_api.h
OBJ=$(STR_OBJDIR)/str_api.o
STR_LIB=$(STR_LIBDIR)/libstr_api.a
STR_ERROR_HDR=$(COMMON_DIR)/error.h

#STR_MISC stuff
MISC_SRC=$(STR_DIR)/src/str_api_misc.c
MISC_HDR=$(STR_INCLUDE)/str_api_misc.h
MISC_OBJ=$(STR_OBJDIR)/str_api_misc.o

#STR_CERT
STR_CERT_SRC=$(COMMON_DIR)/common.c
STR_CERT_HDR=$(COMMON_DIR)/common.h
STR_CERT_OBJ=$(STR_OBJDIR)/str_cert.o

#STR_SIG
STR_SIG_SRC=$(STR_DIR)/src/str_sig.c
STR_SIG_HDR=$(STR_INCLUDE)/str_sig.h
STR_SIG_OBJ=$(STR_OBJDIR)/str_sig.o

#STR_TEST
STR_TEST_SRC=$(STR_DIR)/src/str_test.c
STR_TEST_HDR=$(STR_INCLUDE)/str_test.h
STR_TEST_OBJ=$(STR_OBJDIR)/str_test.o
STR_TEST_BIN=$(STR_BINDIR)/str_test

#STR_TEST_MISC
STR_TEST_MISC_SRC=$(STR_DIR)/src/str_test_misc.c
STR_TEST_MISC_HDR=$(STR_INCLUDE)/str_test_misc.h
STR_TEST_MISC_OBJ=$(STR_OBJDIR)/str_test_misc.o

# General stuff
CC=gcc
#AIX_CFLAGS=-qupconv -qfullpath -qdbxextra -qlinedebug -qarch=604 \
#	   -qcheck=all -qtune=604 
#AIX_CFLAGS=-qwarn64  -bnoquiet -qextchk -qstrict
INCLUDES= -I$(SSL_INCLUDE) -I$(STR_INCLUDE) -I$(COMMON_DIR)
LIB=-lpthread -lcrypto -lm
# Define explantation:
# It should be define during a testing stage only.
# DEBUG and DEBUG_MISC print a lot of extra debug information.
# TIMING computes the times of some functions in the api.
CFLAGS=-g -O2 -Wall 
#CFLAGS=-g -Wall -DDEBUG_MISC -DNO_SANITY_CHECK -DDEBUG
#CFLAGS=-g -Wall -DNO_SANITY_CHECK -DTIMING -DDEBUG_MISC
# CFLAGS=-Wall -DNO_SANITY_CHECK -g -DDEBUG_MISC 
# -DUSE_STR_READ_DSA
#CFLAGS=-g -DDEBUG_MISC $(AIX_CFLAGS) $(SIGNATURES)
#Optimized CFLAGS
#CFLAGS=-O3 $(AIX_CFLAGS) -DNO_SANITY_CHECK
# CFLAGS=-Wall -DNO_SANITY_CHECK -O3 -DTIMING -DDEBUG_MISC
#CFLAGS=-Wall -DNO_SANITY_CHECK -pg -O3 -DPROFILE

LDFLAGS=

# uncomment for compiling with dmalloc
#LIB += -ldmalloc
#CFLAGS += -DUSE_DMALLOC

# uncomment for testing
CFLAGS += -DNO_SANITY_CHECK

# Library 
AR=ar
ARFLAG=-vru


all: $(STR_TEST_BIN) $(STR_LIB) 

lib: $(STR_LIB)

$(STR_LIB): $(OBJ) $(MISC_OBJ) $(STR_CERT_OBJ) \
	$(STR_SIG_OBJ)
	@if [ ! -d $(STR_LIBDIR) ]; then mkdir $(STR_LIBDIR); fi
	$(AR) $(ARFLAG) $@ $?

$(OBJ):	$(SRC)  $(HDR) $(STR_ERROR_HDR)
	@if [ ! -d $(STR_DIST) ]; then mkdir $(STR_DIST); fi
	@if [ ! -d $(STR_OBJDIR) ]; then mkdir $(STR_OBJDIR); fi
	$(CC) $(SRC) -c -o $(OBJ) $(CFLAGS) $(INCLUDES)

$(MISC_OBJ): $(MISC_SRC)  $(MISC_HDR) $(HDR) $(STR_ERROR_HDR)
	@if [ ! -d $(STR_OBJDIR) ]; then mkdir $(STR_OBJDIR); fi
	$(CC) $(MISC_SRC) -c -o $(MISC_OBJ) $(CFLAGS) $(INCLUDES)

$(STR_CERT_OBJ): $(STR_CERT_SRC)  $(STR_CERT_HDR) $(HDR) 
	@if [ ! -d $(STR_OBJDIR) ]; then mkdir $(STR_OBJDIR); fi
	$(CC) $(STR_CERT_SRC) -c -o $(STR_CERT_OBJ) $(CFLAGS) $(INCLUDES)

$(STR_SIG_OBJ): $(STR_SIG_SRC)  $(STR_SIG_HDR) $(HDR) $(STR_CERT_HDR)
	@if [ ! -d $(STR_OBJDIR) ]; then mkdir $(STR_OBJDIR); fi
	$(CC) $(STR_SIG_SRC) -c -o $(STR_SIG_OBJ) $(CFLAGS) $(INCLUDES)

#For testing purposes.
$(STR_TEST_BIN): $(STR_TEST_SRC)  $(STR_TEST_HDR) $(STR_LIB) \
		 $(STR_TEST_MISC_OBJ) $(MISC_OBJ)
	@if [ ! -d $(STR_BINDIR) ]; then mkdir $(STR_BINDIR); fi
	$(CC) $(STR_TEST_SRC) $(CFLAGS) $(TEST_MODE) $(INCLUDES) $(LDFLAGS) $(STR_LIB) \
	$(LIB)  $(STR_TEST_MISC_OBJ) -o $(STR_TEST_BIN)

$(STR_TEST_MISC_OBJ): $(STR_TEST_MISC_SRC)  \
	$(STR_TEST_MISC_HDR)
	@if [ ! -d $(STR_OBJDIR) ]; then mkdir $(STR_OBJDIR); fi
	$(CC) $(STR_TEST_MISC_SRC) -c $(CFLAGS) $(INCLUDES) \
	-o $(STR_TEST_MISC_OBJ) 

ALL_C_FILES=$(SRC) $(MISC_SRC) $(STR_TEST_SRC) \
	$(STR_TEST_MISC_SRC) $(STR_CERT_SRC) \
	$(STR_SIG_SRC)

ALL_H_FILES=$(HDR) $(MISC_HDR) $(STR_TEST_HDR)  \
	$(STR_TEST_MISC_HDR) $(STR_CERT_HDR) $(STR_ERROR_HDR) \
	$(STR_SIG_HDR)

CONFIG_FILES=$(STR_DIR)/Makefile.in $(STR_DIR)/configure.in \
	$(STR_DIR)/README.txt $(STR_DIR)/configure $(STR_DIR)/PEMS.tar.gz

BKP_FILES=$(ALL_C_FILES) $(ALL_H_FILES) $(CONFIG_FILES)

PUBLIC_BKP_DIR=$(HOME)/public

BKP:	
	pax -wvf $(PUBLIC_BKP_DIR)/str_api.tar -s "/..\/..\///gp" $(BKP_FILES)
#	tar -cvf $(PUBLIC_BKP_DIR)/str_api.tar  $(BKP_FILES)
	gzip -9 -f $(PUBLIC_BKP_DIR)/str_api.tar
	chmod 644 $(PUBLIC_BKP_DIR)/str_api.tar.gz


mbkp:
	@if [ ! -d $(STR_DIR)/bkp ]; then mkdir $(STR_DIR)/bkp; fi
	mbkp $(STR_DIR)/src/*.c $(STR_DIR)/include/*.h $(CONFIG_FILES)
	mv bkp_* $(STR_DIR)/bkp

#New version of api is ready for the outside world
cp:
	cp $(ALL_C_FILES) $(STR_DIR)/src/Makefile $(HOME)/STR_API/src
	cp $(ALL_H_FILES) $(HOME)/STR_API/include

clean:
	/bin/rm -f $(STR_OBJDIR)/*.o $(STR_TEST_BIN) \
	$(STR_BINDIR)/core $(STR_LIB) \
#	$(STR_BINDIR)/*.str 

distclean:
	rm -rf $(OS_NAME)
