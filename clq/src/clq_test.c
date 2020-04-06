/*********************************************************************
 * clq_test.c                                                        * 
 * CLQ test source file.                                             * 
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
#include <sys/time.h>
#include <time.h>

#include "openssl/bn.h"
#include "clq_api.h"
#include "clq_api_misc.h"
#include "clq_merge.h"
#include "error.h"

#include "clq_test_misc.h"
#include "clq_test.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

int main(int argc, char **argv) {
  CLQ_NAME user[NUM_USERS][NAME_LENGTH];
  CLQ_NAME *users_leaving[NUM_USERS+1]={NULL};
  CLQ_CONTEXT *ctx[NUM_USERS];
  CLQ_TOKEN *out=NULL;
  CLQ_TOKEN *in=NULL;
  int ret=OK;
  int i=0, j=0, round = 0;
  int r=0;
  int num_users=NUM_USERS;

  for (i=0; i < NUM_USERS; i++) {
    ctx[i]=NULL; 
    sprintf (user[i],"%03d",i);
  }  

  if (!parse_args(argc,argv,&num_users,user)) goto error;
  /*********************************/

  /* All the members will joing the group */
  /* First user joining group */

  ret=clq_first_user(&ctx[0],user[0],GROUP_NAME);
  for(i=1; i<=num_users; i++){
    fprintf(stderr, "i = %d\n", i);
    users_leaving[0] = user[i];
    for(j=1; j<NUM_USERS+1; j++){
      users_leaving[j] = NULL;
    }
    /* New user generates context */
    ret=clq_new_user(&ctx[i],user[i],GROUP_NAME,FALSE);
    printf ("clq_new_user returns %d \n",ret);
    if (ret!=1) goto error;
    
    /* Controller generates token */
    ret=clq_update_key(ctx[i-1],users_leaving,NULL,&out);
    printf ("clq_update_key by %s returns %d \n",user[i-1], ret);
    
    j = i-1;
    while (ctx[j]->me->next != NULL) {
      in = out; out = NULL;
      ret=clq_update_key(ctx[j+1],NULL,in,&out);
      printf ("clq_update_key by %s returns %d \n",user[j+1], ret);
      j++;
      if (ret!=1) goto error;
      if(in != NULL) clq_destroy_token(&in);
    }
    
    in=out; out=NULL;
    
    for (j=0;out==NULL;j++) {
      CLQ_TOKEN *tmp_in;
      
      ret=clq_factor_out(ctx[j],in,&out);
      printf ("clq_factor_out by %s returns %d with %p\n",user[j],ret,out);
      if (ret!=1) goto error;
      if (out != NULL) {
        tmp_in=out; out=NULL;
        ret=clq_merge(ctx[i],user[j],tmp_in,&out);
        printf ("clq_merge returns %d with %p\n",ret, out);
        if(tmp_in != NULL) clq_destroy_token(&tmp_in); 
        if (ret!=1) goto error;
      }
    }
    if(in != NULL) clq_destroy_token(&in);
    in = out; out = NULL;
    
    for (j=0; j <=i; j++){
      if (ctx[j] != NULL) { 
        ret=clq_update_ctx(ctx[j],in);
        printf ("clq_update_ctx returns %d \n",ret);
        if (ret!=OK) break;
      }
    }
    if(in != NULL) clq_destroy_token(&in);
  }
  
  
  /********************************/
  /* Now I have num_users members */
  /* So start partition test first*/
  /********************************/

  for(round = 0; round<5; round++){
    fprintf(stderr, "round = %d\n", round);
    for(i=num_users; i>0; i--){
      for(j=i; j<=num_users; j++){
        users_leaving[j-i] = user[j];
      }
      for(j=num_users-i+1; j<NUM_USERS; j++){
        users_leaving[j]=NULL;
      }
      
      out = in = NULL;
      for (j=0; j<=num_users; j++) {
        ret=clq_leave(&ctx[j],users_leaving,&out,1);
        printf ("clq_leave by %s returns %d \n",user[j], ret);
        if (out != NULL) {
          assert (in==NULL);
          in=out;
          out=NULL;
          r=i;
        }
      }

      for (j=0; j < num_users; j++){
        if (ctx[j] != NULL) { 
          ret=clq_update_ctx(ctx[j],in);
          printf ("clq_update_ctx by %s returns %d \n",user[j], ret);
          if (ret!=OK) break;
        }
      }
      if(in != NULL) clq_destroy_token(&in);
      for(j=i; j<=num_users; j++){
        if (ctx[j] != NULL) clq_destroy_ctx(&ctx[j]);
      }

      /******************************/
      /* Now start merge test first */
      /******************************/
      
      for(j=i; j<=num_users; j++){
        ret=clq_new_user(&ctx[j],user[j],GROUP_NAME,FALSE);
        printf ("clq_new_user by %s returns %d \n",user[j], ret);
        if (ret!=1) goto error;
      }
      
      /* Controller generates token */
      ret=clq_update_key(ctx[i-1],users_leaving,NULL,&out);
      printf ("clq_update_key by %s returns %d \n",user[i-1], ret);
      
      j = i-1;
      while (ctx[j]->me->next != NULL) {
        in = out; out = NULL;
        ret=clq_update_key(ctx[j+1],NULL,in,&out);
        printf ("clq_update_key by %s returns %d \n",user[j+1], ret);
        j++;
        if (ret!=1) goto error;
        if(in != NULL) clq_destroy_token(&in);
      }
      
      in=out; out=NULL;
      
      for (j=0;out==NULL;j++) {
        CLQ_TOKEN *tmp_in;
        
        ret=clq_factor_out(ctx[j],in,&out);
        printf ("clq_factor_out by %s returns %d \n",user[j],ret);
        if (ret!=1) goto error;
        if (out != NULL) {
          tmp_in=out; out=NULL;
          ret=clq_merge(ctx[num_users],user[j],tmp_in,&out);
          printf ("clq_merge by %s returns %d \n",user[num_users], ret);
          if(tmp_in != NULL) clq_destroy_token(&tmp_in); 
          if (ret!=1) goto error;
        }
      }
      if(in != NULL) clq_destroy_token(&in); 
      
      in = out; out=NULL;
      
      for (j=0; j <=num_users; j++){
        if (ctx[j] != NULL) { 
          ret=clq_update_ctx(ctx[j],in);
          printf ("clq_update_ctx by %s returns %d \n",user[j], ret);
          if (ret!=OK) goto error;
        }
      }
      if(in != NULL) clq_destroy_token(&in);
    }
  }
  
error:

  for (i=0; i < num_users; i++) {
    if (ctx[i] != NULL) clq_destroy_ctx(&ctx[i]);
  }

  i=0;
  
  clq_destroy_token(&out);
  clq_destroy_token(&in);

  return 1;
}
    


int do_update(CLQ_CONTEXT *ctx[],char user[][NAME_LENGTH], CLQ_TOKEN
	      *in, int num_users) {
  int ret=OK;
  int i;

  for (i=0; i < num_users; i++)
    if (ctx[i] != NULL) { 
      ret=clq_update_ctx(ctx[i],in);
      printf ("clq_update_ctx returns %d \n",ret);
      if (ret!=OK) break;
      /*
      clq_print_group_secret(ctx[i]);
      clq_print_ctx(ctx[i]);
      */
    } 
  return ret;
}
