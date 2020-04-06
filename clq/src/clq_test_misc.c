/*********************************************************************
 * clq_test_misc.c                                                   * 
 * CLQ test util file.                                               * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/bn.h"

#include "clq_api.h"
#include "clq_api_misc.h"
#include "clq_test_misc.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

void check_group_secret (CLQ_CONTEXT *ctx[], int num_users) {
  int i;
  int j;
  int same=TRUE;
  
  for (i=0; ctx[i]==NULL; i++);
  j=i;
  for (; i < num_users; i++) 
    if (ctx[i]!=NULL) 
      if (BN_cmp(ctx[j]->group_secret,ctx[i]->group_secret))
        same=FALSE;
  
  if (same){
#ifdef DEBUG_ALL
    printf ("Group secret is the same in the entire group :)\n");
#endif
  }
  else{
    printf ("Group secret is NOT the same :(\n");
  }
  
}

/* usr_lst creates a CLQ_NAME list with n users (NULL terminated) */
void usr_lst (CLQ_NAME *lst[NUM_USERS+1], int n, int num_users) {
  int i;
  int l;

  printf ("Users leaving : ");

  for (i=0; i < n; i++) {
    l=(int) rand()%num_users; /* User 'l' leaving */

    printf (" %03d",l);
    lst[i]=(CLQ_NAME *) malloc(sizeof(CLQ_NAME)*NAME_LENGTH);
    sprintf (lst[i],"%03d",l);
    
  }

  printf ("\n");
  lst[n]=NULL;

}


int parse_args (int argc, char **argv,int *num_users,char
		user[][NAME_LENGTH]) { 
  int c;
  int ret=1;
  int errflg=0;
  extern int optind;
  extern int opterr;

  opterr=0;
  if (argc==1) errflg=1;
  else {
    *num_users=atoi(argv[1]);
    if (*num_users==0) errflg=1;
    optind=2;
    while (!errflg && (c = getopt(argc, argv, "g")) != EOF) {
      if (opterr) errflg=1;
      
      switch (c) {
      case 'g':
#ifdef USE_CLQ_READ_DSA 	
	/* Generating parameters and keys */
	if (!(ret=clq_gen_params(512))) {errflg=1; break;}
	if (!(ret=gen_keys(user))) {errflg=1; break;}
#else
	errflg=1;
#endif
	break;
      }
    }
  }

  if (errflg) {
    printf ("\n%s usage:\n",argv[0]);
#ifdef USE_CLQ_READ_DSA
    printf ("\t%s # [-g]\n",argv[0]);
#endif
    printf ("\t\t# (integer number) indicates the number of users that\n");
    printf ("\t\t  will perform the test (max. value is %d.)\n",
	    NUM_USERS);
#ifdef USE_CLQ_READ_DSA
    printf ("\t\t-g generates the public and private information for "\
	    "the test.\n\n");
#endif
    if (ret!=1) printf ("Value returned %d\n",ret);
    exit(1);
  }

  if (*num_users <= 0 || *num_users > NUM_USERS) *num_users=NUM_USERS;

  return ret;
}
