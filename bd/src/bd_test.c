/*********************************************************************
 * bd_test.c                                                         * 
 * Burmester-Desmedt test source file.                               * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/types.h>
#include <time.h>
#include <sys/time.h>

#include "openssl/bn.h"
#include "bd_api.h"
#include "bd_api_misc.h"
#include "error.h"
#include "common.h"

#include "bd_test_misc.h"
#include "bd_test.h"

#ifdef TIMING
extern int print;
#endif

int main(int argc, char **argv) {
  CLQ_NAME *user[NUM_USERS+1]={NULL};
  CLQ_NAME *current_list[NUM_USERS+1]={NULL};
  
  BD_CONTEXT *ctx[NUM_USERS];
  TOKEN_LIST *input=NULL, *curr=NULL;
  CLQ_TOKEN *output[NUM_USERS+1]={NULL};
  
  int ret=OK;
  int i=0, j=0;
  int num_users=0;

#ifdef TIMING
  double Time=0.0;
  double max = 0.0;
  double maxround = 0.0;
  double Now = 0.0;
  double sum = 0.0;
  double spread = 0.0;
  print=1;
#endif

#if defined(PROFILE) | defined(TIMING)

#endif
  if (!parse_args(argc,argv,&num_users)) goto error;
  /*********************************/
  
  /* All the members will joing the group */
  /* First user joining group */
  for(i=0; i<NUM_USERS+1; i++){
    ctx[i]=NULL;
    current_list[i] = NULL;
  }
  for(i=0; i<NUM_USERS; i++){
    user[i] = (CLQ_NAME *)malloc(sizeof(CLQ_NAME)*MAX_LGT_NAME);
    sprintf (user[i],"%03d",i);
  }
  user[NUM_USERS] = NULL;

  for(i=0; i<num_users; i++){
    ret = bd_new_member(&ctx[i], user[i], GROUP_NAME); 
#ifndef TIMING
    printf ("\t::bd_new_member of %s returns %d \n",user[i],ret);
#endif
    if (ret!=OK) goto error;
  }
  
  for(i=2; i<num_users+1; i++){
#ifndef TIMING
    printf("\n\n\n++++++++++user %d'th join start\n",i);
#endif
    for(j=0; j<i; j++){
      current_list[j] = user[j];
    }
    for(j=0; j<i; j++){
#ifdef TIMING
      Now=bd_gettimeofday();
#endif
      ret = bd_membership_req(ctx[j], user[j], GROUP_NAME, current_list,
                              &output[j],1); 
#ifndef TIMING
      printf ("\t::bd_membership_req of %s returns %d \n",user[j],ret);
#endif
#ifdef TIMING
    max=bd_gettimeofday()-Now;
#endif
      if (ret!=OK) goto error;
    }

    for(j=0; j<i; j++){
      input = add_token(input, output[j]);
      output[j] = NULL;
      if(input == NULL) {
        goto error;
      }
    }

    curr = input;
    while(curr != NULL){
      for(j=0; j<i; j++){
#ifdef TIMING
        maxround =0;
        Now=bd_gettimeofday();
#endif
        ret = bd_compute_xi(ctx[j], user[j], GROUP_NAME, curr->token,
                            &output[j]);
#ifdef TIMING
        Time=bd_gettimeofday()-Now;
        maxround=MAX(maxround, Time);
      /*  printf("Duration:  %f\n", Time); */
#endif
#ifndef TIMING
        printf ("\t::bd_compute_xi of %s returns %d \n",user[j],ret);
#endif
        if ( (ret != OK) && (ret != CONTINUE) ) goto error;
      }
#ifdef TIMING
      max += maxround;
#endif
      curr = curr->next;
    }

    input = remove_all_token(input);
    for(j=0; j<i; j++){
      input = add_token(input, output[j]);
      output[j] = NULL;
      if(input == NULL) {
        goto error;
      }
    }

    curr = input;
#ifdef TIMING
    spread = max;
#endif
    while(curr != NULL){
#ifdef TIMING
      sum = 0;
#endif
      for(j=0; j<i; j++){
#ifdef TIMING
        Now=bd_gettimeofday();
#endif
        ret = bd_compute_key(ctx[j], user[j], GROUP_NAME,
                             curr->token); 
#ifdef TIMING
        Time=bd_gettimeofday()-Now;
        sum += Time;
#endif
#ifndef TIMING
        printf ("\t:bd_compute_key of %s returns %d \n",user[j],ret);
#endif
        if ( (ret != OK) && (ret != CONTINUE) ) goto error;
      }
#ifdef TIMING
      sum = (double)(sum/i);
      spread += sum;
#endif
      curr = curr->next;
    }

#ifdef TIMING
    printf("%2d %f\n", i-1, spread);
#endif
    input = remove_all_token(input);

    check_group_secret(ctx, i);
    compare_key(ctx, i);
  }
  
  

error:
  
  for (i=0; i < NUM_USERS; i++) {
    if (user[i] != NULL) free(user[i]);
    if (ctx[i] != NULL) bd_destroy_ctx(&ctx[i]);
  }

  return 1;
}

#ifdef TIMING

double bd_gettimeofday(void) {
  struct timeval used;
  
  gettimeofday(&used, 0);
  /*    printf (":%ld %ld:\n", used.tv_sec, used.tv_usec); */
  return (used.tv_sec + (double)((used.tv_usec) / 1e6));
}


#endif
