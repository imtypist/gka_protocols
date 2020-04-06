/*********************************************************************
 * bd_test.h                                                         * 
 * BD test include file.                                             * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef BD_TEST_H
#define BD_TEST_H

/*
  int do_update(BD_CONTEXT *ctx[],char user[][NAME_LENGTH], 
	      BD_TOKEN *in,int num_users);
*/

#include <string.h>

#ifdef TIMING
double bd_gettimeofday(void);
#endif

#endif
