# Generated automatically from Makefile.in by configure.
#
# clq_api Makefile.in
# Wrote by: Damian Hasse
#
# CLIQUES Project                                                  
# Information Sciences Institute                                   
# University of Southern California   
#

#OS
OS_NAME=linux

#SSL stuff
SSL_LIB=/usr/include/openssl

# CLQ stuff
OSDIR=./linux
CLQ_DIR=.
COMMON_DIR=../common
CLQ_SRC_DIR=src
CLQ_INCLUDE=$(CLQ_DIR)/$(CLQ_SRC_DIR)
CLQ_DIST = $(CLQ_DIR)/$(OS_NAME)
CLQ_OBJDIR=$(CLQ_DIST)/obj
CLQ_LIBDIR=$(CLQ_DIST)/lib
CLQ_BINDIR=$(CLQ_DIST)/bin
SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/clq_api.c 
HDR=$(CLQ_INCLUDE)/clq_api.h
OBJ=$(CLQ_OBJDIR)/clq_api.o
CLQ_LIB=$(CLQ_LIBDIR)/libclq_api.a
CLQ_ERROR_HDR=$(COMMON_DIR)/error.h

#CLQ_MERGE
MERGE_SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/clq_merge.c
MERGE_HDR=$(CLQ_INCLUDE)/clq_merge.h
MERGE_OBJ=$(CLQ_OBJDIR)/clq_merge.o

#CLQ_MISC stuff
MISC_SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/clq_api_misc.c
MISC_HDR=$(CLQ_INCLUDE)/clq_api_misc.h
MISC_OBJ=$(CLQ_OBJDIR)/clq_api_misc.o

#CKD_API
CKD_API_SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/ckd_api.c
CKD_API_HDR=$(CLQ_INCLUDE)/ckd_api.h
CKD_API_OBJ=$(CLQ_OBJDIR)/ckd_api.o

#CLQ_CERT
CLQ_CERT_SRC=$(COMMON_DIR)/common.c
CLQ_CERT_HDR=$(COMMON_DIR)/common.h
CLQ_CERT_OBJ=$(CLQ_OBJDIR)/clq_cert.o

#CLQ_SIG
CLQ_SIG_SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/clq_sig.c
CLQ_SIG_HDR=$(CLQ_INCLUDE)/clq_sig.h
CLQ_SIG_OBJ=$(CLQ_OBJDIR)/clq_sig.o

#CLQ_TEST
CLQ_TEST_SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/clq_test.c
CLQ_TEST_HDR=$(CLQ_INCLUDE)/clq_test.h
CLQ_TEST_OBJ=$(CLQ_OBJDIR)/clq_test.o
CLQ_TEST_BIN=$(CLQ_BINDIR)/clq_test

#CLQ_TEST_MISC
CLQ_TEST_MISC_SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/clq_test_misc.c
CLQ_TEST_MISC_HDR=$(CLQ_INCLUDE)/clq_test_misc.h
CLQ_TEST_MISC_OBJ=$(CLQ_OBJDIR)/clq_test_misc.o

#CKD_TEST
CKD_TEST_SRC=$(CLQ_DIR)/$(CLQ_SRC_DIR)/ckd_test.c
#CKD_TEST_HDR=$(CLQ_INCLUDE)/ckd_test.h
CKD_TEST_OBJ=$(CLQ_OBJDIR)/ckd_test.o
CKD_TEST_BIN=$(CLQ_BINDIR)/ckd_test

LIB = -lcrypto

# General stuff
#CC=gcc -Wall
#CC=cc
CC=gcc
#AIX_CFLAGS=-qupconv -qfullpath -qdbxextra -qlinedebug -qarch=604 \
#	   -qcheck=all -qtune=604 
#AIX_CFLAGS=-qwarn64  -bnoquiet -qextchk -qstrict
INCLUDES= -I$(CLQ_INCLUDE) -I$(COMMON_DIR)

# Define explantation:
# NO_SANITY_CHECK avoids the expensive time consuming sanity check function. 
# It should be define during a testing stage only.
# DEBUG and DEBUG_MISC print a lot of extra debug information.
# TIMING computes the times of some functions in the api.
CFLAGS=-g -O2 -Wall -L $(SSL_LIB)
#CFLAGS=-g -Wall -DDEBUG_MISC -DNO_SANITY_CHECK -DDEBUG
#CFLAGS=-g -Wall -DNO_SANITY_CHECK -DTIMING -DDEBUG_MISC
# CFLAGS=-Wall -DNO_SANITY_CHECK -g -DDEBUG_MISC 
# -DUSE_CLQ_READ_DSA
#CFLAGS=-g -DDEBUG_MISC $(AIX_CFLAGS)
#Optimized CFLAGS
#CFLAGS=-O3 $(AIX_CFLAGS) -DNO_SANITY_CHECK
# CFLAGS=-Wall -DNO_SANITY_CHECK -O3 -DTIMING -DDEBUG_MISC
#CFLAGS=-Wall -DNO_SANITY_CHECK -pg -O3 -DPROFILE

DCFLAGS=-L $(SSL_LIB)

# uncomment to check the programs with dmalloc
#LIB += -ldmalloc
#CFLAGS += -DUSE_DMALLOC

# uncomment for testing
CFLAGS += -DNO_SANITY_CHECK

# Library 
AR=ar
ARFLAG=-vru


all: $(CLQ_TEST_BIN) $(CLQ_LIB) $(CKD_TEST_BIN)

lib: $(CLQ_LIB) \

$(CLQ_LIB): $(OBJ) $(MISC_OBJ) $(MERGE_OBJ) $(CKD_API_OBJ) $(CLQ_CERT_OBJ) \
	$(CLQ_SIG_OBJ)
	@if [ ! -d $(CLQ_LIBDIR) ]; then mkdir $(CLQ_LIBDIR); fi
	$(AR) $(ARFLAG) $@ $?

$(OBJ):	$(SRC)  $(HDR) $(CLQ_ERROR_HDR)
	@if [ ! -d $(CLQ_DIST) ]; then mkdir $(CLQ_DIST); fi
	@if [ ! -d $(CLQ_OBJDIR) ]; then mkdir $(CLQ_OBJDIR); fi
	$(CC) $(SRC) -c -o $(OBJ) $(CFLAGS) $(INCLUDES)

$(MISC_OBJ): $(MISC_SRC)  $(MISC_HDR) $(HDR) $(CLQ_ERROR_HDR)
	@if [ ! -d $(CLQ_OBJDIR) ]; then mkdir $(CLQ_OBJDIR); fi
	$(CC) $(MISC_SRC) -c -o $(MISC_OBJ) $(CFLAGS) $(INCLUDES)

$(MERGE_OBJ): $(MERGE_SRC) $(MERGE_HDR) $(HDR) $(CLQ_ERROR_HDR)
	@if [ ! -d $(CLQ_OBJDIR) ]; then mkdir $(CLQ_OBJDIR); fi
	$(CC) $(MERGE_SRC) -c -o $(MERGE_OBJ) $(CFLAGS) $(INCLUDES)

$(CKD_API_OBJ): $(CKD_API_SRC) $(CKD_API_HDR) $(HDR) 
	@if [ ! -d $(CLQ_OBJDIR) ]; then mkdir $(CLQ_OBJDIR); fi
	$(CC) $(CKD_API_SRC) -c -o $(CKD_API_OBJ) $(CFLAGS) $(INCLUDES)

$(CLQ_CERT_OBJ): $(CLQ_CERT_SRC)  $(CLQ_CERT_HDR) $(HDR) 
	@if [ ! -d $(CLQ_OBJDIR) ]; then mkdir $(CLQ_OBJDIR); fi
	$(CC) $(CLQ_CERT_SRC) -c -o $(CLQ_CERT_OBJ) $(CFLAGS) $(INCLUDES)

$(CLQ_SIG_OBJ): $(CLQ_SIG_SRC)  $(CLQ_SIG_HDR) $(HDR) $(CLQ_CERT_HDR)
	@if [ ! -d $(CLQ_OBJDIR) ]; then mkdir $(CLQ_OBJDIR); fi
	$(CC) $(CLQ_SIG_SRC) -c -o $(CLQ_SIG_OBJ) $(CFLAGS) $(INCLUDES)

#For testing purposes.
$(CLQ_TEST_BIN): $(CLQ_TEST_SRC)  $(CLQ_TEST_HDR) $(CLQ_LIB) \
		 $(CLQ_TEST_MISC_OBJ)
	@if [ ! -d $(CLQ_BINDIR) ]; then mkdir $(CLQ_BINDIR); fi
	$(CC) $(CLQ_TEST_SRC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) $(CLQ_LIB) \
	$(LIB)  $(CLQ_TEST_MISC_OBJ) -o $(CLQ_TEST_BIN)

$(CKD_TEST_BIN): $(CKD_TEST_SRC)  $(CKD_TEST_HDR) $(CLQ_LIB) \
		 $(CLQ_TEST_MISC_OBJ)
	@if [ ! -d $(CLQ_BINDIR) ]; then mkdir $(CLQ_BINDIR); fi
	$(CC) $(CKD_TEST_SRC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) $(CLQ_LIB) \
	$(LIB) $(CLQ_TEST_MISC_OBJ) -o $(CKD_TEST_BIN) 

$(CLQ_TEST_MISC_OBJ): $(CLQ_TEST_MISC_SRC)  $(CLQ_TEST_MISC_HDR)
	@if [ ! -d $(CLQ_OBJDIR) ]; then mkdir $(CLQ_OBJDIR); fi
	$(CC) $(CLQ_TEST_MISC_SRC) -c $(CFLAGS) $(INCLUDES) \
	-o $(CLQ_TEST_MISC_OBJ) 

ALL_C_FILES=$(SRC) $(MERGE_SRC) $(MISC_SRC) $(CKD_API_SRC) $(CLQ_TEST_SRC) \
	$(CLQ_TEST_MISC_SRC) $(CKD_TEST_SRC) $(CLQ_CERT_SRC) $(CLQ_SIG_SRC)

ALL_H_FILES=$(HDR) $(MERGE_HDR) $(MISC_HDR) $(CKD_API_HDR) $(CLQ_TEST_HDR) \
	$(CLQ_TEST_MISC_HDR) $(CLQ_CERT_HDR) $(CLQ_ERROR_HDR) $(CLQ_SIG_HDR)

CONFIG_FILES=$(CLQ_DIR)/Makefile.in $(CLQ_DIR)/configure.in \
	$(CLQ_DIR)/README.txt $(CLQ_DIR)/configure $(CLQ_DIR)/PEMS.tar.gz \
	$(CLQ_DIR)/PEMS1.tar.gz 

BKP_FILES=$(ALL_C_FILES) $(ALL_H_FILES) $(CONFIG_FILES)

PUBLIC_BKP_DIR=$(HOME)/public

clean:
	rm -f $(CLQ_OBJDIR)/*.o $(CLQ_TEST_BIN) \
	$(CLQ_BINDIR)/core $(CLQ_LIB) $(CLQ_TEST_BIN)_merge \
	$(CKD_TEST_BIN)

distclean: 
	rm -rf $(CLQ_DIST)





