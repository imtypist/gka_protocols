/*********************************************************************
 * ckd_test.c                                                        * 
 * CKD test source file.                                             * 
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
#include "clq_api.h"
#include "clq_api_misc.h"
#include "clq_merge.h"
#include "error.h"
#include "clq_test_misc.h"

#include "ckd_api.h"
/* #include "ckd_test.h" */

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

int main(int argc, char **argv) {
  CLQ_NAME user[NUM_USERS][NAME_LENGTH];
  CLQ_NAME *users_leaving[NUM_USERS+1]={NULL};
  CLQ_CONTEXT *ctx[NUM_USERS];
  CLQ_TOKEN *out=NULL;
  CLQ_TOKEN *in=NULL;
  CLQ_TOKEN *tmp_in=NULL;
  CLQ_TOKEN *new_in=NULL;
  enum MSG_TYPE msg_type=INVALID;
  int ret=OK;
  int i=0;
  int j=0;
  int r=0;
  int num_users=NUM_USERS;
  int ctr=-1;

  for (i=0; i < NUM_USERS; i++) {
    ctx[i]=NULL; 
    sprintf (user[i],"%03d",i);
  }

  if (!parse_args(argc,argv,&num_users,user)) goto error;
  /*********************************/

  /* All the members will joing the group */
  /* First user joining group */
  ret=clq_first_user(&ctx[0],user[0],GROUP_NAME);
  printf ("clq_first_user by %03d returns %d \n",0, ret);
  if (ret!=OK) goto error;

  /* All the other users joining group */
  for (i=1; i < num_users; i++) {
    ret=clq_new_user(&ctx[i],user[i],GROUP_NAME,FALSE);
    printf ("clq_new_user by %03d returns %d \n",ret, i);
    if (ret!=OK) goto error;
    
    /* Every member already in the group is processing the event */
    for (j=0; j < i; j++) {
      ret=ckd_proc_event(&ctx[j],user[i],CKD_JOIN,&msg_type,&out);
      printf ("ckd_proc_event by %03d returns %d \n",j,ret);
      if (ret!=OK) goto error;
      if (out != NULL){
        if (in == NULL) { in=out; out=NULL; }
        else { 
          printf ("Error in ckd_proc_event two output returns.\n");
          goto error;
        }
      }
    }
    
    tmp_in=in; in=NULL;
    for (j=0; j <= i; j++) {
      ret=ckd_comp_new_share(ctx[j],tmp_in,&out);
      printf ("ckd_comp_new_share by %03d returns %d \n",j, ret);
      if (ret!=OK) goto error;
      
      if (out!=NULL) {
        in=out; out=NULL;
        /* ctx[0] is the controller */
        ret=ckd_generates_key(ctx[0], user[j],in,&out);
        printf ("ckd_generates_key by %03d returns %d \n", j, ret);
        if (ret!=OK) goto error;
        
        clq_destroy_token(&in);
        if (out!=NULL){
          if (new_in==NULL) { new_in=out; out=NULL; }
          else {
            printf ("Error in ckd_generates_key two output returns.\n");
            goto error;
          }
        }
      }
    }

    if(tmp_in != NULL) {
      clq_destroy_token(&tmp_in);
    }
    
    for (j=0; j <= i; j++) {
      ret=ckd_get_session_key (ctx[j],new_in);
      printf ("ckd_get_session_key by %03d returns %d \n", j, ret);
  
      {
	int s;
	for (s = 0; s < 16; s++){
	  printf("%02X", ((unsigned char*)(ctx[j]->group_secret_hash))[s]);
	}
	printf("\n");
      }   
      
      if (ret!=OK) goto error;
    }
    
    check_group_secret(ctx, i+1);

   
    
    clq_destroy_token(&out);
    clq_destroy_token(&in);
    clq_destroy_token(&tmp_in);
    clq_destroy_token(&new_in);
  }
  /*********************************/

  /*
  for (i=0; ctx[i] != NULL; i++)
    clq_print_ctx(ctx[i]);
  */

  /* Some random users will leave the group */
  /* To make it a little more interesting :) */
  srand(time(0));
  r=((int) rand()%(num_users-1))+1;
  printf (" %d users leaving group.\n",r);
  r = 1;
  /* 'r' users will leave the group */
  usr_lst(users_leaving,r,num_users); 
  /* r=1; */
  
  msg_type=INVALID;

  for (j=0; j < r; j++) {
    /* Skipping user that leaves more than once (to avoid error) */
    if (ctx[atoi(users_leaving[j])] == NULL) continue;
    for (i=0; i < num_users; i++) {
      if (ctx[i] != NULL) {
        ret=ckd_proc_event (&ctx[i],users_leaving[j],CKD_LEAVE,&msg_type,&out);
        printf ("ckd_proc_event by %03d returns %d \n", i, ret);
        if (ret!=OK) goto error;
        
        if (out!=NULL){
          /* Setting ctr to save time */
          if (new_in==NULL) { new_in=out; out=NULL; ctr=i;} 
          else {
            printf ("Error in ckd_proc_event two output returns.\n");
            goto error;
          }
        }
      }
    }

    if (msg_type==CKD_NEW_KEY_SHARE) {
      for (i=0; i < num_users; i++) {
        if (ctx[i] != NULL) {
          ret=ckd_comp_new_share(ctx[i],new_in,&out);
          printf ("ckd_comp_new_share by %03d returns %d \n", i, ret);
          if (ret!=OK) goto error;
          if (i==ctr) continue;
          
          if (out==NULL) { ret=-999; goto error; }
          
          in=out; out=NULL;
          /* ctx[ctr] is the controller (use ckd_get_controller_name) */
          ret=ckd_generates_key(ctx[ctr], user[i],in,&out);
          printf ("ckd_generates_key by %03d returns %d \n", ctr, ret);
          if (ret!=OK) goto error;
          
          clq_destroy_token(&in);
          if (out!=NULL){
            if (tmp_in==NULL) { tmp_in=out; out=NULL; }
            else {
              printf ("Error in ckd_generates_key two output returns.\n");
              goto error;
            }
          }
        }
      }
      if(new_in != NULL) {
        clq_destroy_token(&new_in);
      }
      new_in=tmp_in; tmp_in=NULL;
    }
    
    for (i=0; i < num_users; i++){
      if (ctx[i] != NULL) {
        ret=ckd_get_session_key (ctx[i],new_in);
        printf ("ckd_get_session_key by %03d returns %d \n", i, ret);
        if (ret!=OK) goto error;
      }
    }
    
    clq_destroy_token (&new_in);
  }
  
  for (i=0; i < num_users; i++)
    if (ctx[i]!=NULL)
      clq_print_ctx(ctx[i]);
  
  printf ("Users that left : ");
  for (i=0; users_leaving[i]!=NULL ; i++) printf ("%s ",users_leaving[i]);
  printf("\n");
  /* Checking if group_secrets are the same between users */
  check_group_secret(ctx, num_users);
  

error:
  
  for (i=0; i < num_users; i++) {
    clq_destroy_ctx(&ctx[i]);
  }
  
  i=0;
  while (users_leaving[i] != NULL) free(users_leaving[i++]);
  
  clq_destroy_token(&out);
  clq_destroy_token(&in);
  
  return 1;
}
