/*********************************************************************
 * str_test_misc.h                                                   * 
 * STR test misc include file.                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef STR_TEST_MISC_H
#define STR_TEST_MISC_H

#define GROUP_NAME "gaga"
#define NUM_USERS 256
#define NAME_LENGTH 10

/* usr_lst creates a CLQ_NAME list with n users (NULL terminated) */
void usr_lst (CLQ_NAME *lst[NUM_USERS+1], int n, int num_users,
              int *c, CLQ_NAME *user[NUM_USERS+1],
              CLQ_NAME *current_users[NUM_USERS+1]);

void check_group_secret (STR_CONTEXT *ctx[], int num_users);

int parse_args (int argc, char **argv,int *num_users,int *num_round);

int name2int(char *name);

STR_TOKEN_LIST *STR_add_token(STR_TOKEN_LIST *token_list, CLQ_TOKEN *token);
STR_TOKEN_LIST *STR_remove_token(STR_TOKEN_LIST **token_list);
STR_TOKEN_LIST *STR_remove_all_token(STR_TOKEN_LIST *token_list);

#ifdef TEST_COUNT_MOD
void initialize_counters(int exp_count[], int sign_count[],
                         int vrfy_count[], int encode_count[],
                         int decode_count[]);
#endif

#endif
