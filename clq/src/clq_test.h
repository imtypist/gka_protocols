/*********************************************************************
 * clq_test.h                                                        * 
 * CLQ test include file.                                            * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef CLQ_TEST_H
#define CLQ_TEST_H

int do_update(CLQ_CONTEXT *ctx[],char user[][NAME_LENGTH], 
	      CLQ_TOKEN *in,int num_users);

#endif
