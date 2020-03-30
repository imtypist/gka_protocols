# tgdh_api Makefile.in
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

# TGDH stuff
TGDH_DIR=.
COMMON_DIR=../common
TGDH_DIST = $(TGDH_DIR)/$(OS_NAME)
TGDH_INCLUDE=$(TGDH_DIR)/src/
TGDH_OBJDIR=$(TGDH_DIR)/$(OS_NAME)/obj
TGDH_LIBDIR=$(TGDH_DIR)/$(OS_NAME)/lib
TGDH_BINDIR=$(TGDH_DIR)/$(OS_NAME)/bin
SRC=$(TGDH_DIR)/src/tgdh_api.c 
HDR=$(TGDH_INCLUDE)/tgdh_api.h
OBJ=$(TGDH_OBJDIR)/tgdh_api.o
TGDH_LIB=$(TGDH_LIBDIR)/libtgdh_api.a
TGDH_ERROR_HDR=$(COMMON_DIR)/error.h

#TGDH_MISC stuff
MISC_SRC=$(TGDH_DIR)/src/tgdh_api_misc.c
MISC_HDR=$(TGDH_INCLUDE)/tgdh_api_misc.h
MISC_OBJ=$(TGDH_OBJDIR)/tgdh_api_misc.o

#TGDH_CERT
TGDH_CERT_SRC=$(COMMON_DIR)/common.c
TGDH_CERT_HDR=$(COMMON_DIR)/common.h
TGDH_CERT_OBJ=$(TGDH_OBJDIR)/common.o

#TGDH_SIG
TGDH_SIG_SRC=$(TGDH_DIR)/src/tgdh_sig.c
TGDH_SIG_HDR=$(TGDH_INCLUDE)/tgdh_sig.h
TGDH_SIG_OBJ=$(TGDH_OBJDIR)/tgdh_sig.o

#TGDH_TEST
TGDH_TEST_SRC=$(TGDH_DIR)/src/tgdh_test.c
TGDH_TEST_HDR=$(TGDH_INCLUDE)/tgdh_test.h
TGDH_TEST_OBJ=$(TGDH_OBJDIR)/tgdh_test.o
TGDH_TEST_BIN=$(TGDH_BINDIR)/tgdh_test

#TGDH_TEST_MISC
TGDH_TEST_MISC_SRC=$(TGDH_DIR)/src/tgdh_test_misc.c
TGDH_TEST_MISC_HDR=$(TGDH_INCLUDE)/tgdh_test_misc.h
TGDH_TEST_MISC_OBJ=$(TGDH_OBJDIR)/tgdh_test_misc.o

# General stuff
CC=gcc
#AIX_CFLAGS=-qupconv -qfullpath -qdbxextra -qlinedebug -qarch=604 \
#	   -qcheck=all -qtune=604 
#AIX_CFLAGS=-qwarn64  -bnoquiet -qextchk -qstrict
INCLUDES= -I$(SSL_INCLUDE) -I$(TGDH_INCLUDE) -I$(COMMON_DIR)
LIB=-lcrypto -lm
# Define explantation:
# It should be define during a testing stage only.
# DEBUG and DEBUG_MISC print a lot of extra debug information.
# TIMING computes the times of some functions in the api.
CFLAGS=-g -O2 -Wall 
#CFLAGS=-g -Wall -DDEBUG_MISC -DNO_SANITY_CHECK -DDEBUG
#CFLAGS=-g -Wall -DNO_SANITY_CHECK -DTIMING -DDEBUG_MISC
# CFLAGS=-Wall -DNO_SANITY_CHECK -g -DDEBUG_MISC 
# -DUSE_TGDH_READ_DSA
#CFLAGS=-g -DDEBUG_MISC $(AIX_CFLAGS) $(SIGNATURES)
#Optimized CFLAGS
#CFLAGS=-O3 $(AIX_CFLAGS) -DNO_SANITY_CHECK
# CFLAGS=-Wall -DNO_SANITY_CHECK -O3 -DTIMING -DDEBUG_MISC
#CFLAGS=-Wall -DNO_SANITY_CHECK -pg -O3 -DPROFILE

LDFLAGS=

# uncomment to compile with dmalloc
#LIB += -ldmalloc
#CFLAGS += -DUSE_DMALLOC

# uncomment for testing
CFLAGS += -DNO_SANITY_CHECK

# Library 
AR=ar
ARFLAG=-vru


all: $(TGDH_TEST_BIN) $(TGDH_LIB) 

lib: $(TGDH_LIB)

$(TGDH_LIB): $(OBJ) $(MISC_OBJ) $(TGDH_CERT_OBJ) \
	$(TGDH_SIG_OBJ)
	@if [ ! -d $(TGDH_LIBDIR) ]; then mkdir $(TGDH_LIBDIR); fi
	$(AR) $(ARFLAG) $@ $?

$(OBJ):	$(SRC)  $(HDR) $(TGDH_ERROR_HDR)
	@if [ ! -d $(TGDH_DIST) ]; then mkdir $(TGDH_DIST); fi
	@if [ ! -d $(TGDH_OBJDIR) ]; then mkdir $(TGDH_OBJDIR); fi
	$(CC) $(SRC) -c -o $(OBJ) $(CFLAGS) $(INCLUDES)

$(MISC_OBJ): $(MISC_SRC)  $(MISC_HDR) $(HDR) $(TGDH_ERROR_HDR)
	@if [ ! -d $(TGDH_OBJDIR) ]; then mkdir $(TGDH_OBJDIR); fi
	$(CC) $(MISC_SRC) -c -o $(MISC_OBJ) $(CFLAGS) $(INCLUDES)

$(TGDH_CERT_OBJ): $(TGDH_CERT_SRC)  $(TGDH_CERT_HDR) $(HDR) 
	@if [ ! -d $(TGDH_OBJDIR) ]; then mkdir $(TGDH_OBJDIR); fi
	$(CC) $(TGDH_CERT_SRC) -c -o $(TGDH_CERT_OBJ) $(CFLAGS) $(INCLUDES)

$(TGDH_SIG_OBJ): $(TGDH_SIG_SRC)  $(TGDH_SIG_HDR) $(HDR) $(TGDH_CERT_HDR)
	@if [ ! -d $(TGDH_OBJDIR) ]; then mkdir $(TGDH_OBJDIR); fi
	$(CC) $(TGDH_SIG_SRC) -c -o $(TGDH_SIG_OBJ) $(CFLAGS) $(INCLUDES)

#For testing purposes.
$(TGDH_TEST_BIN): $(TGDH_TEST_SRC)  $(TGDH_TEST_HDR) $(TGDH_LIB) \
		 $(TGDH_TEST_MISC_OBJ) $(MISC_OBJ)
	@if [ ! -d $(TGDH_BINDIR) ]; then mkdir $(TGDH_BINDIR); fi
	$(CC) $(TGDH_TEST_SRC) $(CFLAGS) $(TEST_MODE) $(INCLUDES) $(LDFLAGS) $(TGDH_LIB) \
	$(LIB)  $(TGDH_TEST_MISC_OBJ) -o $(TGDH_TEST_BIN)

$(TGDH_TEST_MISC_OBJ): $(TGDH_TEST_MISC_SRC) \
	$(TGDH_TEST_MISC_HDR)
	@if [ ! -d $(TGDH_OBJDIR) ]; then mkdir $(TGDH_OBJDIR); fi
	$(CC) $(TGDH_TEST_MISC_SRC) -c $(CFLAGS) $(INCLUDES) \
	-o $(TGDH_TEST_MISC_OBJ) 

ALL_C_FILES=$(SRC) $(MISC_SRC) $(TGDH_TEST_SRC) \
	$(TGDH_TEST_MISC_SRC) $(TGDH_CERT_SRC) \
	$(TGDH_SIG_SRC)

ALL_H_FILES=$(HDR) $(MISC_HDR) $(TGDH_TEST_HDR) \
	$(TGDH_TEST_MISC_HDR) $(TGDH_CERT_HDR) $(TGDH_ERROR_HDR) \
	$(TGDH_SIG_HDR)

CONFIG_FILES=$(TGDH_DIR)/Makefile.in $(TGDH_DIR)/configure.in \
	$(TGDH_DIR)/README.txt $(TGDH_DIR)/configure $(TGDH_DIR)/PEMS.tar.gz

BKP_FILES=$(ALL_C_FILES) $(ALL_H_FILES) $(CONFIG_FILES)

PUBLIC_BKP_DIR=$(HOME)/public

BKP:	
	pax -wvf $(PUBLIC_BKP_DIR)/tgdh_api.tar -s "/..\/..\///gp" $(BKP_FILES)
#	tar -cvf $(PUBLIC_BKP_DIR)/tgdh_api.tar  $(BKP_FILES)
	gzip -9 -f $(PUBLIC_BKP_DIR)/tgdh_api.tar
	chmod 644 $(PUBLIC_BKP_DIR)/tgdh_api.tar.gz


mbkp:
	@if [ ! -d $(TGDH_DIR)/bkp ]; then mkdir $(TGDH_DIR)/bkp; fi
	mbkp $(TGDH_DIR)/src/*.c $(TGDH_DIR)/include/*.h $(CONFIG_FILES)
	mv bkp_* $(TGDH_DIR)/bkp

#New version of api is ready for the outside world
cp:
	cp $(ALL_C_FILES) $(TGDH_DIR)/src/Makefile $(HOME)/TGDH_API/src
	cp $(ALL_H_FILES) $(HOME)/TGDH_API/include

clean:
	/bin/rm -f $(TGDH_OBJDIR)/*.o $(TGDH_TEST_BIN)\
	$(TGDH_BINDIR)/core $(TGDH_LIB) \
#	$(TGDH_BINDIR)/*.tgdh 

distclean:
	rm -rf $(OS_NAME)
