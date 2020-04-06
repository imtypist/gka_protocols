/*********************************************************************
 * clq_api_misc.h                                                    * 
 * CLQ api miscellaneous include file.                               * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef CLQ_API_MISC_H
#define CLQ_API_MISC_H

#include <stdio.h>

#include "clq_api.h"

#define FN_LENGTH 200
#define Q_SIZE_IN_BITS 160

/* clq_gen_params: Generates the common DSA parameters
 * (i.e. p,q,alpha). p_size specify the size of the prime p in bits.
 * Returns 1 if succeed 0 otherwise.
 */
int clq_gen_params (int p_size);
/* clq_gen_key_set: Generate a pair of public and private key for the
 * user_name.
 * Returns 1 if succeed 0 otherwise.
 */
int clq_gen_key_set(char *user_name);

/* clq_write_dsa: Writes the dsa structure into outfile. 
 * oper could be any of the following: 
 * PUB_FMT, PRV_FMT
 * dsa should be a valid pointer.
 * If outfile is NULL, then stdout will be used.
 * Returns 1 if succeed 0 otherwise.
 */
int clq_write_dsa(DSA *dsa, char *oper, char *outfile);

int clq_print_dsa(DSA *dsa);

#ifdef TIMING
void clq_print_times(char *str, double time);
/*
  void clq_print_times(char *str,struct timeval t_initial, struct timeval
  t_final);
*/
double clq_get_time (void);
#endif

/* clq_print_ctx: Prints ctx to stdout */
void clq_print_ctx(CLQ_CONTEXT *ctx);

/* clq_get_secret: Returns in a static variable with ctx->group_secret_hash */
clq_uchar *clq_get_secret(CLQ_CONTEXT *ctx);

void clq_print_group_secret(CLQ_CONTEXT *ctx);


#endif
