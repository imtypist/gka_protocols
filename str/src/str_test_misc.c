/*********************************************************************
 * str_test_misc.c                                                   * 
 * STR test misc file.                                               * 
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
#include <string.h>

#include "openssl/bn.h"

#include "str_api.h"
#include "str_api_misc.h"
#include "str_test_misc.h"

/* Needed by getrusgae */
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

void check_group_secret (STR_CONTEXT *ctx[], int num_users) {
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
    printf ("Group secret is the same in the entire group :)\n");
  }
  else{
    printf ("Group secret is NOT the same :(\n");
  }
  
}

/* usr_lst creates a CLQ_NAME list with n users (NULL terminated) */
void usr_lst (CLQ_NAME *lst[NUM_USERS+1], int n, int num_users,
              int *c, CLQ_NAME *user[NUM_USERS+1],
              CLQ_NAME *current_users[NUM_USERS+1]) {
  int i=0;
  int l=0;
  int k=0;
  int j=-1;
  struct rusage used;
  
  int ret=1;
  int tmp_ret=0;

  CLQ_NAME *tmp;

#ifdef DEBUG_ALL    
  printf ("Users leaving : ");
#endif
  tmp=(CLQ_NAME *) malloc(sizeof(CLQ_NAME)*NAME_LENGTH);
  
  while(i<n){
    getrusage(RUSAGE_SELF, &used);
    srand(used.ru_utime.tv_usec+l);
    l=((int) rand()) % (num_users); 
    sprintf (tmp,"%03d",l);
    for(k=0; k<i; k++)
      if(strcmp(lst[k], tmp)==0) ret = 0;
    tmp_ret=0;
    for(k=0; k<num_users; k++){
      if(strcmp(user[k], tmp)==0){
        tmp_ret=1;
        break;
      }
    }
    

    if(ret && tmp_ret){
      lst[i]=(CLQ_NAME *) malloc(sizeof(CLQ_NAME)*NAME_LENGTH);
      sprintf (lst[i],"%03d",l);
#ifdef DEBUG_ALL    
      printf("%03d ", l);
#endif
      for(k=0; k<num_users; k++){
        if(strcmp(lst[i], user[k]) == 0){
          j = k;
          break;
        }
      }
      i++;
#ifdef DEBUG_ALL    
      fprintf(stderr, "%d ", i);
#endif
    }
    
    ret=1;
    j = -1;
  }
  lst[n]=NULL;

  ret=0;
  k=0;
  for(i=0; i<num_users; i++){
    for(j=0; j<n; j++)
      if(strcmp(user[i], lst[j]) == 0)
        ret = 1;
    
    if(!ret){
      current_users[k] =
        (CLQ_NAME *)malloc(sizeof(CLQ_NAME)*MAX_LGT_NAME);
      strcpy(current_users[k], user[i]);
      k++;
    }
    ret = 0;
  }
  if(tmp != NULL) free(tmp);
  *c = k;
#ifdef DEBUG_ALL    
  printf("\n");
#endif
}

int parse_args (int argc, char **argv,int *num_users, int *num_round)
{
  
  int ret=1;
  int errflg=0;

  if((argc==1)||(argv[1] == NULL)||(argv[2] == NULL)){
    errflg=1;
    ret = 0;
  }
  else{
    *num_users=atoi(argv[1]);
    if (*num_users==0){
      errflg=1;
      ret=0;
    }
    *num_round=atoi(argv[2]);
    if (*num_round==0){
      errflg=1;
      ret=0;
    }
  }

  if (errflg) {
    printf ("\n%s usage:\n",argv[0]);
    printf ("\t%s #of users #of round \n",argv[0]);
    printf ("\tExample:%s 100 10 \n",argv[0]);
  }

  if (*num_users <= 0 || *num_users > NUM_USERS) *num_users=NUM_USERS;

  return ret;
}

STR_TOKEN_LIST *STR_add_token(STR_TOKEN_LIST *list_token, CLQ_TOKEN *token)
{
  STR_TOKEN_LIST *tmp_list=NULL;

  if(token == NULL) return NULL;
  
  if(list_token == NULL){
    list_token = (STR_TOKEN_LIST *) calloc(sizeof(STR_TOKEN_LIST), 1);
    if(list_token == NULL){
      return NULL;
    }
    list_token->token = token;
    list_token->end = list_token;
    list_token->next = NULL;
  }
  else{
    if(list_token->end != list_token){
      if(list_token->next == NULL){
        STR_remove_all_token(list_token);
        return NULL;
      }
    }
    else{
      if(list_token->end->next != NULL){
        STR_remove_all_token(list_token);
        return NULL;
      }
    }
    tmp_list = (STR_TOKEN_LIST *) calloc(sizeof(STR_TOKEN_LIST), 1);
    tmp_list->token = token;
    list_token->end->next = tmp_list;
    list_token->end = tmp_list;
    tmp_list->next = NULL;
    tmp_list->end = NULL;
  }

  return list_token;
}

STR_TOKEN_LIST *STR_remove_token(STR_TOKEN_LIST **list_token)
{
  STR_TOKEN_LIST *tmp_token;

  if((*list_token) == NULL) return NULL;
  str_destroy_token(&((*list_token)->token));
  (*list_token)->token=NULL;
  if((*list_token)->next){
#ifdef DEBUG_YD
    fprintf(stderr, "NT ");
#endif 
    tmp_token = (*list_token)->next;
    tmp_token->end = (*list_token)->end;
  }
  else{
    tmp_token = NULL;
  }

  if((*list_token) != NULL) free((*list_token));
  (*list_token) = NULL;

  return tmp_token;

}

STR_TOKEN_LIST *STR_remove_all_token(STR_TOKEN_LIST *list_token)
{
  while(list_token != NULL){
    list_token=STR_remove_token(&list_token);
  }

  return NULL;
}

