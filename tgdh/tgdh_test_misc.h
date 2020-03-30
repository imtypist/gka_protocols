/*********************************************************************
 * tgdh_test_misc.h                                                  * 
 * TREE test misc include file.                                      * 
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

#ifndef TGDH_TEST_MISC_H
#define TGDH_TEST_MISC_H

#include "tgdh_api.h"

#define GROUP_NAME "gaga"
#define NUM_USERS 256
#define NAME_LENGTH 10

/* usr_lst creates a TGDH_NAME list with n users (NULL terminated) */
void usr_lst (CLQ_NAME *lst[NUM_USERS+1], int n, int num_users,
              int *c, CLQ_NAME *user[NUM_USERS+1],
              CLQ_NAME *current_users[NUM_USERS+1]);

void check_group_secret (TGDH_CONTEXT *ctx[], int num_users);

int parse_args (int argc, char **argv,int *num_users,int *num_round);

TOKEN_LIST *add_token(TOKEN_LIST *token_list, CLQ_TOKEN *token);
TOKEN_LIST *remove_token(TOKEN_LIST **token_list);
TOKEN_LIST *remove_all_token(TOKEN_LIST *token_list);

#ifdef TEST_COUNT_MOD
void initialize_counters(int exp_count[], int sign_count[],
                         int vrfy_count[], int encode_count[],
                         int decode_count[]);
#endif

#endif
