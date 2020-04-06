# Generated automatically from Makefile.in by configure.
#
# bd_api Makefile.in
# Wrote by: Damian Hasse
#
# CLIQUES Project                                                  
# Information Sciences Institute                                   
# University of Southern California   
#

#OS
OS_NAME=linux

#SSL stuff
SSL_LIB=-I/usr/include/openssl

# BD stuff
BD_DIR=.
COMMON_DIR=../common
BD_DIST = $(BD_DIR)/$(OS_NAME)
BD_INCLUDE=$(BD_DIR)/src
BD_OBJDIR=$(BD_DIR)/$(OS_NAME)/obj
BD_LIBDIR=$(BD_DIR)/$(OS_NAME)/lib
BD_BINDIR=$(BD_DIR)/$(OS_NAME)/bin
SRC=$(BD_DIR)/src/bd_api.c 
HDR=$(BD_INCLUDE)/bd_api.h
OBJ=$(BD_OBJDIR)/bd_api.o
BD_LIB=$(BD_LIBDIR)/libbd_api.a
BD_ERROR_HDR=$(COMMON_DIR)/error.h

#BD_MISC stuff
MISC_SRC=$(BD_DIR)/src/bd_api_misc.c
MISC_HDR=$(BD_INCLUDE)/bd_api_misc.h
MISC_OBJ=$(BD_OBJDIR)/bd_api_misc.o

#BD_CERT
BD_CERT_SRC=$(COMMON_DIR)/common.c
BD_CERT_HDR=$(COMMON_DIR)/common.h
BD_CERT_OBJ=$(BD_OBJDIR)/common.o

#BD_SIG
BD_SIG_SRC=$(BD_DIR)/src/bd_sig.c
BD_SIG_HDR=$(BD_INCLUDE)/bd_sig.h
BD_SIG_OBJ=$(BD_OBJDIR)/bd_sig.o

#BD_TEST
BD_TEST_SRC=$(BD_DIR)/src/bd_test.c
BD_TEST_HDR=$(BD_INCLUDE)/bd_test.h
BD_TEST_OBJ=$(BD_OBJDIR)/bd_test.o
BD_TEST_BIN=$(BD_BINDIR)/bd_test

#BD_TEST_MISC
BD_TEST_MISC_SRC=$(BD_DIR)/src/bd_test_misc.c
BD_TEST_MISC_HDR=$(BD_INCLUDE)/bd_test_misc.h
BD_TEST_MISC_OBJ=$(BD_OBJDIR)/bd_test_misc.o

# General stuff
#CC=gcc -Wall
#CC=cc
CC=gcc
#AIX_CFLAGS=-qupconv -qfullpath -qdbxextra -qlinedebug -qarch=604 \
#	   -qcheck=all -qtune=604 
#AIX_CFLAGS=-qwarn64  -bnoquiet -qextchk -qstrict
INCLUDES= $(SSL_INCLUDE) -I$(BD_INCLUDE) -I$(COMMON_DIR)
LIB=-lpthread -lcrypto -lm
# Define explantation:
# DEBUG and DEBUG_MISC print a lot of extra debug information.
# TIMING computes the times of some functions in the api.
CFLAGS=-g -O2 -Wall 
#CFLAGS=-g -Wall -DDEBUG_MISC -DNO_SANITY_CHECK -DDEBUG
#CFLAGS=-g -Wall -DNO_SANITY_CHECK -DTIMING -DDEBUG_MISC
# CFLAGS=-Wall -DNO_SANITY_CHECK -g -DDEBUG_MISC 
# -DUSE_BD_READ_DSA
#CFLAGS=-g -DDEBUG_MISC $(AIX_CFLAGS) $(SIGNATURES)
#Optimized CFLAGS
#CFLAGS=-O3 $(AIX_CFLAGS) -DNO_SANITY_CHECK
# CFLAGS=-Wall -DNO_SANITY_CHECK -O3 -DTIMING -DDEBUG_MISC
#CFLAGS=-Wall -DNO_SANITY_CHECK -pg -O3 -DPROFILE

LDFLAGS=

# uncomment for dmalloc
#LIB += -ldmalloc
#CFLAGS += -DUSE_DMALLOC

# uncomment for testing
CFLAGS += -DNO_SANITY_CHECK

# Library 
AR=ar
ARFLAG=-vru


all: $(BD_TEST_BIN) $(BD_LIB) 

lib: $(BD_LIB)

$(BD_LIB): $(OBJ) $(MISC_OBJ) $(BD_CERT_OBJ) \
	$(BD_SIG_OBJ)
	@if [ ! -d $(BD_LIBDIR) ]; then mkdir $(BD_LIBDIR); fi
	$(AR) $(ARFLAG) $@ $?

$(OBJ):	$(SRC)  $(HDR) $(BD_ERROR_HDR)
	@if [ ! -d $(BD_DIST) ]; then mkdir $(BD_DIST); fi
	@if [ ! -d $(BD_OBJDIR) ]; then mkdir $(BD_OBJDIR); fi
	$(CC) $(SRC) -c -o $(OBJ) $(CFLAGS) $(INCLUDES)

$(MISC_OBJ): $(MISC_SRC)  $(MISC_HDR) $(HDR) $(BD_ERROR_HDR)
	@if [ ! -d $(BD_OBJDIR) ]; then mkdir $(BD_OBJDIR); fi
	$(CC) $(MISC_SRC) -c -o $(MISC_OBJ) $(CFLAGS) $(INCLUDES)

$(BD_CERT_OBJ): $(BD_CERT_SRC)  $(BD_CERT_HDR) $(HDR) 
	@if [ ! -d $(BD_OBJDIR) ]; then mkdir $(BD_OBJDIR); fi
	$(CC) $(BD_CERT_SRC) -c -o $(BD_CERT_OBJ) $(CFLAGS) $(INCLUDES)

$(BD_SIG_OBJ): $(BD_SIG_SRC)  $(BD_SIG_HDR) $(HDR) $(BD_CERT_HDR)
	@if [ ! -d $(BD_OBJDIR) ]; then mkdir $(BD_OBJDIR); fi
	$(CC) $(BD_SIG_SRC) -c -o $(BD_SIG_OBJ) $(CFLAGS) $(INCLUDES)

#For testing purposes.
$(BD_TEST_BIN): $(BD_TEST_SRC)  $(BD_TEST_HDR) $(BD_LIB) \
		 $(BD_TEST_MISC_OBJ) $(MISC_OBJ)
	@if [ ! -d $(BD_BINDIR) ]; then mkdir $(BD_BINDIR); fi
	$(CC) $(BD_TEST_SRC) $(CFLAGS) $(TEST_MODE) $(INCLUDES) $(LDFLAGS) $(BD_LIB) \
	$(LIB)  $(BD_TEST_MISC_OBJ) -o $(BD_TEST_BIN)

$(BD_TEST_MISC_OBJ): $(BD_TEST_MISC_SRC) \
	$(BD_TEST_MISC_HDR)
	@if [ ! -d $(BD_OBJDIR) ]; then mkdir $(BD_OBJDIR); fi
	$(CC) $(BD_TEST_MISC_SRC) -c $(CFLAGS) $(INCLUDES) \
	-o $(BD_TEST_MISC_OBJ) 

ALL_C_FILES=$(SRC) $(MISC_SRC) $(BD_TEST_SRC) \
	$(BD_TEST_MISC_SRC) $(BD_CERT_SRC) \
	$(BD_SIG_SRC)

ALL_H_FILES=$(HDR) $(MISC_HDR) $(BD_TEST_HDR) \
	$(BD_TEST_MISC_HDR) $(BD_CERT_HDR) $(BD_ERROR_HDR) \
	$(BD_SIG_HDR)

CONFIG_FILES=$(BD_DIR)/Makefile.in $(BD_DIR)/configure.in \
	$(BD_DIR)/README.txt $(BD_DIR)/configure $(BD_DIR)/PEMS.tar.gz

BKP_FILES=$(ALL_C_FILES) $(ALL_H_FILES) $(CONFIG_FILES)

PUBLIC_BKP_DIR=$(HOME)/public

BKP:	
	pax -wvf $(PUBLIC_BKP_DIR)/bd_api.tar -s "/..\/..\///gp" $(BKP_FILES)
#	tar -cvf $(PUBLIC_BKP_DIR)/bd_api.tar  $(BKP_FILES)
	gzip -9 -f $(PUBLIC_BKP_DIR)/bd_api.tar
	chmod 644 $(PUBLIC_BKP_DIR)/bd_api.tar.gz


mbkp:
	@if [ ! -d $(BD_DIR)/bkp ]; then mkdir $(BD_DIR)/bkp; fi
	mbkp $(BD_DIR)/src/*.c $(BD_DIR)/include/*.h $(CONFIG_FILES)
	mv bkp_* $(BD_DIR)/bkp

#New version of api is ready for the outside world
cp:
	cp $(ALL_C_FILES) $(BD_DIR)/src/Makefile $(HOME)/BD_API/src
	cp $(ALL_H_FILES) $(HOME)/BD_API/include

clean:
	/bin/rm -f $(BD_OBJDIR)/*.o $(BD_TEST_BIN)\
	$(BD_BINDIR)/core $(BD_LIB) \
#	$(BD_BINDIR)/*.bd 

distclean:
	rm -rf $(OS_NAME)
