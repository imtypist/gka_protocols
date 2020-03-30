/*********************************************************************
 * tgdh_api_misc.h                                                   * 
 * TREE api miscellaneous include file.                              * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *                                                                   *
 * Date      Tue March 24, 2020  9:48 PM                             *
 * Maintained by:                                                    *
 * Junqin Huang                                                      *
 *                                                                   *
 * Shanghai Jiao Tong University                                     *
 *********************************************************************/

#ifndef TGDH_API_MISC_H
#define TGDH_API_MISC_H

#include <stdio.h>

#include "openssl/dsa.h"
#include "tgdh_api.h"

#define FN_LENGTH 200
#define Q_SIZE_IN_BITS 160

int tgdh_print_dsa(DSA *dsa);

KEY_TREE *tgdh_search_number(KEY_TREE *tree, int index);

void tgdh_print_node(char *name, KEY_TREE *tree);
void tgdh_print_all(CLQ_NAME *name, KEY_TREE *tree);
void tgdh_print_ctx(char *name, TGDH_CONTEXT *ctx);
void tgdh_simple_ctx_print(TGDH_CONTEXT *ctx);
void tgdh_simple_node_print(KEY_TREE *tree);
void tgdh_print_bkey(char *name, KEY_TREE *tree);
void tgdh_print_simple(CLQ_NAME *name, KEY_TREE *tree);

int compare_key(TGDH_CONTEXT *ctx[], int num);

/* tgdh_get_secret: Returns in a static variable with ctx->group_secret_hash */
clq_uchar *tgdh_get_secret(TGDH_CONTEXT *ctx);

void tgdh_print_group_secret(TGDH_CONTEXT *ctx);

#endif
