/*********************************************************************
 * str_test.h                                                        * 
 * STR test include file.                                            * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef STR_TEST_H
#define STR_TEST_H

/*
  int do_update(STR_CONTEXT *ctx[],char user[][NAME_LENGTH], 
	      STR_TOKEN *in,int num_users);
*/

#include <string.h>

/* STR_LIST: list of users */
typedef struct str_list {
  int num;
  int status;
  CLQ_NAME *list[NUM_USERS+1];
  CLQ_NAME *leaving_list[NUM_USERS+1];
  STR_TOKEN_LIST *token_list;
  struct str_list *next;
} STR_LIST;

void str_check_list_secret (STR_CONTEXT *ctx[], CLQ_NAME *list[], int num);

/* This function processes one token list... In Spread state diagram
   notation, this function is called in the NEW_TREE state */
int str_process_one_token_list(STR_LIST *list, STR_CONTEXT *ctx[]);

/* This function processes single token... In Spread state diagram
   notation, this function is called in the NEW_TREE state */
int str_process_one_token(STR_LIST *init_list, STR_LIST *list,
                          STR_CONTEXT *ctx[]);
/* This function generates a random event for the current group */
int str_generate_random_event(STR_LIST **init_list, STR_LIST *list,
                              STR_CONTEXT *ctx[], int seed);
/* str_generate_n_partition */
void str_generate_n_partition(STR_LIST **list, STR_CONTEXT *ctx[], int num_users);

/* generate_partition */
int str_generate_partition(STR_LIST *list, STR_CONTEXT *ctx[]);
/* generate_merge */
int str_generate_merge(STR_LIST **init_list, STR_LIST *list,
                       STR_CONTEXT *ctx[]) ;
/* destroy_list */
void str_destroy_list(STR_LIST **list);
void str_check_list_secret (STR_CONTEXT *ctx[], CLQ_NAME *list[], int num);

/* generate_partition */
int str_generate_partition(STR_LIST *list, STR_CONTEXT *ctx[]);

/* generate_n_partition */
void str_generate_n_partition(STR_LIST **list, STR_CONTEXT *ctx[], int num_users);

/* generate_i_partition */
void str_generate_i_partition(STR_LIST **list, STR_CONTEXT *ctx[], int num_users, int num_leaves);

/* generate_leave */
void str_generate_leave(STR_LIST **list, STR_CONTEXT *ctx[], int num_users);

/* generate_r_leave */
int str_generate_r_leave(STR_LIST **list, STR_CONTEXT *ctx[], int num_users, CLQ_NAME *user[]);

/* generate_all_merge_req */
void str_generate_all_merge_req(STR_LIST **list, STR_CONTEXT *ctx[],
                            int num_users, CLQ_NAME *user[]);  

void STR_remove_add_list(STR_LIST *src, STR_LIST *dst, int index);

#endif
