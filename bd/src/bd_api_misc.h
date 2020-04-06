/*********************************************************************
 * bd_api_misc.h                                                     * 
 * BD api miscellaneous include file.                                * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef BD_API_MISC_H
#define BD_API_MISC_H

#include <stdio.h>

#include "openssl/dsa.h"
#include "bd_api.h"

#define FN_LENGTH 200
#define Q_SIZE_IN_BITS 160

/* bd_write_dsa: Writes the dsa structure into outfile. 
 * oper could be any of the following: 
 * PUB_FMT, PRV_FMT
 * dsa should be a valid pointer.
 * If outfile is NULL, then stdout will be used.
 * Returns 1 if succeed 0 otherwise.
 */
int bd_write_dsa(DSA *dsa, char *oper, char *outfile);

int bd_print_dsa(DSA *dsa);

int compare_key(BD_CONTEXT *ctx[], int num);

/* bd_get_secret: Returns in a static variable with ctx->group_secret_hash */
clq_uchar *bd_get_secret(BD_CONTEXT *ctx);

void bd_print_group_secret(BD_CONTEXT *ctx);

#endif
