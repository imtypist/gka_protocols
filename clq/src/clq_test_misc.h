/*********************************************************************
 * clq_test_misc.h                                                   * 
 * CLQ test misc include file.                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef CLQ_TEST_MISC_H
#define CLQ_TEST_MISC_H

#define GROUP_NAME "gaga"
#define NUM_USERS 100
#define NAME_LENGTH 10

int gen_keys(char user[][NAME_LENGTH]);

/* usr_lst creates a CLQ_NAME list with n users (NULL terminated) */
void usr_lst (CLQ_NAME *lst[NUM_USERS+1], int n, int num_users);

void check_group_secret (CLQ_CONTEXT *ctx[], int num_users);

int parse_args (int argc, char **argv,int *num_users,char
		user[][NAME_LENGTH]);

#endif
