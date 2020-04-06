/*********************************************************************
 * str_api_misc.h                                                    * 
 * STR api miscellaneous include file.                               * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef STR_API_MISC_H
#define STR_API_MISC_H

#include <stdio.h>

#include "openssl/dsa.h"
#include "str_api.h"

#define FN_LENGTH 200
#define Q_SIZE_IN_BITS 160

/* str_write_dsa: Writes the dsa structure into outfile. 
 * oper could be any of the following: 
 * PUB_FMT, PRV_FMT
 * dsa should be a valid pointer.
 * If outfile is NULL, then stdout will be used.
 * Returns 1 if succeed 0 otherwise.
 */
int str_write_dsa(DSA *dsa, char *oper, char *outfile);

int str_print_dsa(DSA *dsa);

STR_KEY_TREE *str_search_number(STR_KEY_TREE *tree, int index);

void str_print_node(char *name, STR_KEY_TREE *tree);
void str_print_all(CLQ_NAME *name, STR_KEY_TREE *tree);
void str_print_ctx(char *name, STR_CONTEXT *ctx);
int compare_key(STR_CONTEXT *ctx[], int num);

/* str_get_secret: Returns in a static variable with ctx->group_secret_hash */
clq_uchar *str_get_secret(STR_CONTEXT *ctx);

void str_print_group_secret(STR_CONTEXT *ctx);

#endif
