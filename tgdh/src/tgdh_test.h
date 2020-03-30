/*********************************************************************
 * tgdh_test.h                                                       * 
 * TREE test include file.                                           * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef TGDH_TEST_H
#define TGDH_TEST_H

/*
  int do_update(TGDH_CONTEXT *ctx[],char user[][NAME_LENGTH], 
	      TGDH_TOKEN *in,int num_users);
*/

#include <string.h>

/* TGDH_LIST: list of users */
typedef struct tgdh_list {
  int num;
  int status;
  CLQ_NAME *list[NUM_USERS+1];
  CLQ_NAME *leaving_list[NUM_USERS+1];
  TOKEN_LIST *token_list;
#ifdef TEST_TIMING
  double tmp_time;
  unsigned max_round;
  unsigned average_round;
#endif
  struct tgdh_list *next;
} TGDH_LIST;

/* This function processes single token... In Spread state diagram
   notation, this function is called in the NEW_TREE state */
int process_one_token(TGDH_LIST *list, TGDH_CONTEXT *ctx[]);

/* This function processes one token list... In Spread state diagram
   notation, this function is called in the NEW_TREE state */
int process_one_token_list(TGDH_LIST *list, TGDH_CONTEXT *ctx[]);

/* This function generate a random event for the current group */
int generate_random_event(TGDH_LIST **init_list, TGDH_LIST *list,
                           TGDH_CONTEXT *ctx[], int seed);

/* generate_partition */
int generate_partition(TGDH_LIST *list, TGDH_CONTEXT *ctx[]);

/* generate_n_partition */
void generate_n_partition(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users);

/* generate_leave */
void generate_leave(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users);

/* generate_r_leave */
int generate_r_leave(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users);

/* generate_all_merge_req */
void generate_all_merge_req(TGDH_LIST **list, TGDH_CONTEXT *ctx[],
                            int num_users, CLQ_NAME *user[]);  

/* generate_merge */
int generate_merge(TGDH_LIST **init_list, TGDH_LIST *list,
                    TGDH_CONTEXT *ctx[]);

/* generate3merge */
int generate3merge(TGDH_LIST **init_list, TGDH_LIST *list,
                   TGDH_CONTEXT *ctx[]);

void remove_add_list(TGDH_LIST *src, TGDH_LIST *dst, int index);

/* generate_i_partition */
void generate_i_partition(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users, int num_leaves);

/* destroy_list */
void destroy_list(TGDH_LIST **list);

void check_list_secret (TGDH_CONTEXT *ctx[], CLQ_NAME *list[], int num);

#endif
