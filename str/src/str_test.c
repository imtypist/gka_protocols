/*********************************************************************
 * str_test.c                                                        * 
 * STR test source file.                                             * 
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
#include <sys/resource.h>

#include "openssl/bn.h"
#include "str_api.h"
#include "str_api_misc.h"
#include "error.h"

#include "str_test_misc.h"
#include "str_api_misc.h" /* str_get_time is defined here */

#include "str_test.h"

#define CMERGE 1
#define CPARTITION 2
#define DEFAULT 10

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

int main(int argc, char **argv) {
  CLQ_NAME *user[NUM_USERS+1]={NULL};

  STR_LIST *list=NULL, *init_list=NULL, *tmp_list=NULL;
  
  STR_CONTEXT *ctx[NUM_USERS];
  CLQ_TOKEN *output[NUM_USERS+1]={NULL};
  int num_users=NUM_USERS;
  int leaving_member=0;
  
  int ret=OK, Ret=CONTINUE;
  int i=0, j=0;
  int num_round=0;
  int round=0;
  
  list = (STR_LIST *) calloc(sizeof(STR_LIST), 1);
  if (!parse_args(argc,argv,&num_users,&num_round)) goto error;
  /*********************************/

  /* All the members will joing the group */
  /* First user joining group */
  for(i=0; i<NUM_USERS+1; i++){
    user[i] = NULL;
    ctx[i]=NULL;
  }
  for(i=0; i<num_users+1; i++){
    user[i] = (CLQ_NAME *)malloc(sizeof(CLQ_NAME)*MAX_LGT_NAME);
    sprintf (user[i],"%03d",i);
  }
  
  for(i=0; i<NUM_USERS+1; i++) {
    output[i] = NULL;
  }


  for(round = 0; round<5; round++){
    fprintf (stderr,"---------- Round %d\n", round);
    for(i=0; i<num_users+1; i++){
      list->leaving_list[i] = NULL;
    }
    
    ret=str_new_member(&ctx[0],user[0],GROUP_NAME);
    printf ("str_new_member returns %d \n",ret);
    if (ret!=1) goto error;

    for(i=1; i<num_users; i++){
      fprintf (stderr, "----------Start of %dth Join Event\n", i);
      
      ret=str_new_member(&ctx[i],user[i],GROUP_NAME);
      list->num = i;
      for(j=0; j<=i; j++){
        list->list[j] = user[j];
      }
      tmp_list = (STR_LIST *) calloc(sizeof(STR_LIST), 1);
      tmp_list->num = 1;
      tmp_list->list[0] = user[i];
      for(j=1; j<NUM_USERS+1; j++){
        tmp_list->list[j] = NULL;
        tmp_list->leaving_list[j] = NULL;
      }
      tmp_list->next = NULL;
      
      list->next = tmp_list;
      
      str_generate_all_merge_req(&list, ctx, i+1, user);
      
      Ret = 100;
      while (Ret != 1){
        Ret = str_process_one_token_list(list, ctx);
      }
      
      check_group_secret(ctx, i+1);
      
      if((i % 8) == 0){
        list->num = i+1;
        for(j=0; j<=i; j++){
          list->list[j] = user[j];
        }
        fprintf (stderr, "----------Generate random Leave Event\n");
        leaving_member = str_generate_r_leave(&list, ctx, i+1, user);
        
        Ret = 100;
        while (Ret != 1){
          Ret = str_process_one_token_list(list, ctx);
        }
        fprintf (stderr, "----------Make-up Join Event\n");
        
        tmp_list = (STR_LIST *) calloc(sizeof(STR_LIST), 1); 
        tmp_list->num = 1; 
        tmp_list->list[0] = user[leaving_member]; 
        for(j=1; j<NUM_USERS+1; j++){ 
          tmp_list->list[j] = NULL; 
          tmp_list->leaving_list[j] = NULL; 
        } 
        tmp_list->next = NULL; 
        
        list->next = tmp_list;
        
        str_generate_all_merge_req(&list, ctx, i+1, user);
        
        Ret = 100;
        while (Ret != 1){
          Ret = str_process_one_token_list(list, ctx);
        }
      }
    }
    if(round != 4){
      for(i=0; i<num_users; i++){
        if(ctx[i] != NULL) {
          str_destroy_ctx(&ctx[i],1);
        }
      }
    }
    list->token_list = STR_remove_all_token(list->token_list);
  }
  
  free(list);
  
  printf ("----------End of Join Event\n");
  check_group_secret(ctx, num_users);
  compare_key(ctx, num_users);

  list = (STR_LIST *) calloc(sizeof(STR_LIST), 1);
  ret=str_new_member(&ctx[num_users],user[num_users],GROUP_NAME);
  
  list->num = num_users;
  for(i=0; i<num_users; i++){
    list->list[i] = user[i];
  }

  for(i=0; i<5; i++){
    fprintf (stderr,"---------- Partition %d: fixed number Event\n", i);
    for(j=0; j<num_users-1; j++){
      list->token_list = STR_remove_all_token(list->token_list);
      tmp_list = list;
      str_generate_i_partition(&tmp_list, ctx, num_users, j+1);
      while(tmp_list != NULL){
        Ret = 100;
        if(tmp_list->num != 1){
          while (Ret != 1){
            Ret = str_process_one_token_list(tmp_list, ctx);
          }
        }
        tmp_list->token_list = STR_remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      fprintf (stderr, "----------Start of Make up Merge Event\n");

      list->token_list = STR_remove_all_token(list->token_list);
      list->next->token_list = STR_remove_all_token(list->next->token_list);

      str_generate_all_merge_req(&list, ctx, num_users, user);
      Ret = 100;
      while (Ret != 1){
        Ret = str_process_one_token_list(list, ctx);
      }
    }
  }
  
  
error:

  if(list != NULL){
    list->token_list = STR_remove_all_token(list->token_list);
    free(list);
  }
  
  for (i=0; i < NUM_USERS; i++) {
    if (ctx[i] != NULL) str_destroy_ctx(&(ctx[i]), 1);
    if (user[i] != NULL) free(user[i]);
  }
  if(init_list != NULL) str_destroy_list(&init_list);

  return 0;
}

/* str_generate_i_partition */
void str_generate_i_partition(STR_LIST **list, STR_CONTEXT *ctx[], int num_users, int num_leaves)
{
  int i, k, j, ret, leave_index=0;
  STR_LIST *tlist=NULL, *tlist1=NULL;
  STR_LIST *tmp_list[NUM_USERS+1]={NULL};
  CLQ_NAME *tmp_name[NUM_USERS+1], *tmp1_name[NUM_USERS+1];
  CLQ_TOKEN *tmp=NULL;
  struct rusage used;
  int N = 0, num=0, tmp_num=0, list_num=0;

  if((*list)->num < 2){
    fprintf(stderr, "  *\n");
    return;
  }

  if((*list)->token_list != NULL){
    (*list)->token_list = STR_remove_all_token((*list)->token_list);
  }
  (*list)->next = (STR_LIST *) calloc(sizeof(STR_LIST), 1);
  list_num = (*list)->num;

  for(i=0; i<NUM_USERS; i++){
    tmp1_name[i]=(*list)->list[i];
  }

  
  getrusage(RUSAGE_SELF, &used);
  srand(used.ru_utime.tv_usec+36218368);

  for(i=0; i<num_leaves; i++){
    leave_index = rand() % ((*list)->num);
    STR_remove_add_list((*list), (*list)->next, leave_index);
  }
  for(i=(*list)->num; i<NUM_USERS; i++){
    (*list)->list[i] = NULL;
  }
  
  if((*list)->next->num > 5){
    tmp_list[0]=tlist = (*list)->next;
    N = ((int)rand() % 3)+2;

    for(i=0; i<NUM_USERS+1; i++){
      tmp_name[i] = tlist->list[i];
      tlist->list[i] = NULL;
    }
    num = tlist->num;
    tlist->num = 1;
    
    for(i=1; i<N; i++){
      tmp_list[i] = (STR_LIST *) calloc(sizeof(STR_LIST), 1);
      tmp_list[i]->list[0] = tmp_name[i];
      tmp_list[i]->num = 1;
      tmp_list[i-1]->next = tmp_list[i];
    }
    
    tlist->list[0] = tmp_name[0];
    
    for(i=N; i<num; i++){
      tmp_num = (int)rand() % N;
      tmp_list[tmp_num]->list[tmp_list[tmp_num]->num] = tmp_name[i];
      tmp_list[tmp_num]->num++;
    }
  }

  tlist = (*list);
  while(tlist != NULL){
    tlist1 = (*list);
    j=0;
    while(tlist1 != NULL){
      if(tlist != tlist1){
        for(k=0; k<tlist1->num; k++){
          tlist->leaving_list[j++] = tlist1->list[k];
        }
      }
      tlist1 = tlist1->next;
    }
    tlist = tlist->next;
  }
  
  
  tlist = (*list);

  while(tlist != NULL){
    for(i=0; i<tlist->num; i++){
      ret = str_cascade(&ctx[atoi(tlist->list[i])], GROUP_NAME,
                         tlist->leaving_list, NULL, &tmp);
      
      printf("\t::::str_cascade of %s returns %d with output %p\n",
             tlist->list[i],ret, tmp);
      if(ret <= 0) exit(ret);
      if(tmp != NULL){
        tlist->token_list = STR_add_token(tlist->token_list, tmp);
        tmp = NULL;
      }
      tmp=NULL;
    }
    for(i=0; i<NUM_USERS+1; i++){
      tlist->leaving_list[i] = NULL;
    }
    tlist = tlist->next;
  }

  return;
}

/* str_generate_r_leave */
int str_generate_r_leave(STR_LIST **list, STR_CONTEXT *ctx[], int num_users, CLQ_NAME *user[])
{
  int i, ret, N;
  CLQ_TOKEN *tmp=NULL;
  CLQ_NAME *tmp_name=NULL;

  if((*list)->token_list != NULL){
    (*list)->token_list = STR_remove_all_token((*list)->token_list);
  }
  N = (int)(rand()) % num_users;
  (*list)->leaving_list[0] = user[N];
  for(i=N; i<num_users-1; i++){
    (*list)->list[i] = (*list)->list[i+1];
  }
  
  (*list)->list[num_users-1] = NULL;
  (*list)->num--;
  
  for(i=0; i<(*list)->num; i++){
    ret = str_cascade(&ctx[atoi((*list)->list[i])], GROUP_NAME,
                       (*list)->leaving_list, NULL, &tmp);
    printf("\t::::str_cascade of %s returns %d with output %p\n",
           (*list)->list[i],ret, tmp);
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      (*list)->token_list = STR_add_token((*list)->token_list, tmp);
      tmp = NULL;
    }
    tmp=NULL;
  }

  ret = str_cascade(&ctx[N], GROUP_NAME, (*list)->list, NULL, &tmp);
  printf("\t::::str_cascade of %s returns %d with output %p\n", 
        tmp_name,ret, tmp); 
  
  return N;
}

/* str_generate_leave */
void str_generate_leave(STR_LIST **list, STR_CONTEXT *ctx[], int num_users)
{
  int i, ret;
  CLQ_TOKEN *tmp=NULL;
  CLQ_NAME *tmp_name=NULL;

  if((*list)->token_list != NULL){
    (*list)->token_list = STR_remove_all_token((*list)->token_list);
  }
  tmp_name = (*list)->list[num_users];
  (*list)->leaving_list[0] = (*list)->list[num_users];
  (*list)->list[num_users] = NULL;
  (*list)->num--;
  
  for(i=0; i<(*list)->num; i++){
    ret = str_cascade(&ctx[atoi((*list)->list[i])], GROUP_NAME,
                       (*list)->leaving_list, NULL, &tmp);
    printf("\t::::str_cascade of %s returns %d with output %p\n",
           (*list)->list[i],ret, tmp);
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      (*list)->token_list = STR_add_token((*list)->token_list, tmp);
      tmp = NULL;
    }
    tmp=NULL;
  }

  ret = str_cascade(&ctx[num_users], GROUP_NAME, (*list)->list, NULL, &tmp);
  printf("\t::::str_cascade of %s returns %d with output %p\n",
         tmp_name,ret, tmp);
  
  return;
}

/* str_generate_all_merge_req */
void str_generate_all_merge_req(STR_LIST **list, STR_CONTEXT *ctx[],
                                int num_users, CLQ_NAME *user[])
{
  STR_LIST *tmp_list[NUM_USERS+1]={NULL}, *tlist = NULL;
  int i=0, num=0, ret=0;
  CLQ_TOKEN *tmp=NULL;
  STR_TOKEN_LIST *tmp_token_list=NULL;

  for(i=0; i<NUM_USERS+1; i++){
    tmp_list[i] = NULL;
  }
  
  tlist = (*list)->next;
  for(i=0; i<num_users; i++){
    (*list)->list[i] = user[i];
  }
  (*list)->num = num_users;

  while(tlist != NULL){
    tmp_list[num] = tlist;
    num++;
    tlist = tlist->next;
  }
  str_destroy_list(&tmp_list[0]);
  (*list)->next = NULL;
  
  for(i=0; i<(*list)->num; i++){
    ret=str_merge_req(ctx[atoi((*list)->list[i])], (*list)->list[i],
                       GROUP_NAME, &tmp); 
    printf ("\t::str_merge_req of %s returns %d with output %p\n",
            (*list)->list[i],ret,tmp);
    if (ret!=1) {
      exit(0);
    }
    if(tmp != NULL){
      (*list)->token_list = STR_add_token((*list)->token_list, tmp);
    }
    tmp=NULL;
  }
  for(i=0; i<(*list)->num; i++){
    ret = str_cascade(&ctx[atoi((*list)->list[i])], GROUP_NAME, NULL,
                       (*list)->token_list, &tmp);
    printf("\t::::str_cascade of %s returns %d with output %p\n",
           (*list)->list[i],ret, tmp);
    if(ret <= 0){
      exit(0);
    }
    if(tmp != NULL){
      tmp_token_list = STR_add_token(tmp_token_list, tmp);
    }
    tmp=NULL;
  }
  (*list)->token_list = STR_remove_all_token((*list)->token_list);

  (*list)->token_list = tmp_token_list;

  return;
}

/* str_generate_n_partition */
void str_generate_n_partition(STR_LIST **list, STR_CONTEXT *ctx[], int num_users)
{
  STR_LIST *tmp_list[NUM_USERS+1]={NULL}, *tlist=NULL;
  int i, j, k, l, num, N, tmp_num, ret;
  CLQ_NAME *tmp_name[NUM_USERS+1];
  CLQ_TOKEN *tmp=NULL;
  struct rusage used;

  for(i=0; i<NUM_USERS; i++){
    tmp_list[i] = NULL;
  }
  
  if((*list)->num < 2){
    fprintf(stderr, "  *\n");
    return;
  }

  if((*list)->token_list != NULL){
    (*list)->token_list = STR_remove_all_token((*list)->token_list);
  }
  tlist=tmp_list[0] = (*list);

  getrusage(RUSAGE_SELF, &used);
  srand(used.ru_utime.tv_usec+36218368);
  N = rand() % (num_users-2);
  N += 2;
  
  for(i=0; i<NUM_USERS+1; i++){
    tmp_name[i] = (*list)->list[i];
    (*list)->list[i] = NULL;
  }
  num = (*list)->num;
  (*list)->num = 1;
  
  for(i=1; i<N; i++){
    tmp_list[i] = (STR_LIST *) calloc(sizeof(STR_LIST), 1);
    tmp_list[i]->list[0] = tmp_name[i];
    tmp_list[i]->num = 1;
    tmp_list[i-1]->next = tmp_list[i];
  }

  (*list)->list[0] = tmp_name[0];
  
  for(i=N; i<num; i++){
    tmp_num = (int)rand() % N;
    tmp_list[tmp_num]->list[tmp_list[tmp_num]->num] = tmp_name[i];
    tmp_list[tmp_num]->num++;
  }

  (*list) = tmp_list[0];
  
  fprintf(stderr, "++Partition happened: ");
  for(i=0; i<N; i++){
    fprintf(stderr, "%d ", tmp_list[i]->num);
    k=0;
    l=0;
    for(j=0; j<NUM_USERS; j++){
      tmp_list[i]->leaving_list[j] = NULL;
      if(tmp_list[i]->list[k] == NULL){
        tmp_list[i]->leaving_list[l] = tmp_name[j];
        l++;
      }
      else if(strcmp(tmp_list[i]->list[k], tmp_name[j]) != 0){
        tmp_list[i]->leaving_list[l] = tmp_name[j];
        l++;
      }
      else{
        k++;
      }
    }
  }
  fprintf(stderr, "\n");
  
  tlist = (*list);

  while(tlist != NULL){
    for(i=0; i<tlist->num; i++){
      ret = str_cascade(&ctx[atoi(tlist->list[i])], GROUP_NAME,
                         tlist->leaving_list, NULL, &tmp);
      printf("\t::::str_cascade of %s returns %d with output %p\n",
             tlist->list[i],ret, tmp);
      if(ret <= 0) exit(ret);
      if(tmp != NULL){
        tlist->token_list = STR_add_token(tlist->token_list, tmp);
        tmp = NULL;
      }
      tmp=NULL;
    }
    for(i=0; i<NUM_USERS+1; i++){
      tlist->leaving_list[i] = NULL;
    }
    tlist = tlist->next;
  }

  return;
}

/* This function processes one token list... In Spread state diagram
   notation, this function is called in the NEW_TREE state */
int str_process_one_token_list(STR_LIST *list, STR_CONTEXT *ctx[])
{
  int i, k, ret;
  STR_TOKEN_LIST *curr_token=NULL, *tmp_input=NULL;
  CLQ_TOKEN *tmp=NULL, *output[NUM_USERS+1]={NULL};
  
  for(i=0; i<NUM_USERS+1; i++) {
    output[i] = NULL;
  }

  k=0;
  curr_token = list->token_list;
  tmp_input = (STR_TOKEN_LIST *) calloc(sizeof(STR_TOKEN_LIST), 1);

  do{
    list->status = 0;
    tmp_input->token = curr_token->token;
    tmp_input->next = NULL;

    for(i=0; i<list->num; i++){
      ret = str_cascade(&ctx[atoi(list->list[i])], GROUP_NAME,
                         NULL, tmp_input, &tmp);
      printf("\t::::str_cascade of %s returns %d with output %p\n",
             list->list[i],ret, tmp);
      if(ret <= 0) exit(1);
      if(((list->status > 1) && (ret == OK)) &&
         ((list->status == OK) && (ret > 1))){ 
        fprintf(stderr, "WHATTTTT????\n");
      }
      list->status = MAX(list->status, ret);
      if(tmp != NULL){
        if(output[k] != NULL){
          str_destroy_token(&output[k]);
        }
        output[k] = tmp;
        if(output[k] == NULL) {
          exit(1);
        }
        k++;
      }
      tmp=NULL;
    }
    if(list->status == 1) {
      list->token_list = STR_remove_all_token(list->token_list);
      break;
    }
    curr_token = curr_token->next;
  } while (curr_token != NULL);
    
  list->token_list = STR_remove_all_token(list->token_list);
    
  for(i=0; i<k; i++){
    list->token_list = STR_add_token(list->token_list, output[i]);
    output[i] = NULL;
  }

  if(list->status == OK){
    str_check_list_secret(ctx, list->list, list->num);
  }

  free(tmp_input);
  return list->status;
}

/* generate_partition */
int str_generate_partition(STR_LIST *list, STR_CONTEXT *ctx[])
{
  STR_LIST *tmp_list1=NULL, *tmp_list2=NULL;
  int i, num, ret, k=0;
  CLQ_NAME *tmp_name[NUM_USERS+1];
  CLQ_TOKEN *tmp=NULL;

  if(list->num < 2){
    fprintf(stderr, "  *\n");
    return DEFAULT;
  }

  if(list->token_list != NULL){
    list->token_list = STR_remove_all_token(list->token_list);
  }
  tmp_list1 = list;
  while(tmp_list1->next != NULL){
    tmp_list1 = tmp_list1->next;
  }

  tmp_list2 = (STR_LIST *) calloc(sizeof(STR_LIST), 1);
  tmp_list1->next = tmp_list2;

  for(i=0; i<NUM_USERS+1; i++){
    tmp_name[i] = list->list[i];
    list->list[i] = NULL;
  }
  
  num = list->num;
  list->num = 1;
  list->list[0] = tmp_name[0];
  tmp_list2->num = 1;
  tmp_list2->list[0] = tmp_name[1];
  
  for(i=2; i<num; i++){
    if((int)rand() %2){
      tmp_list2->list[tmp_list2->num] = tmp_name[i];
      tmp_list2->num++;
    }
    else{
      list->list[list->num] = tmp_name[i];
      list->num++;
    }
  }

  k=0;
  fprintf(stderr, "++Partition happened %d:%d\n", list->num, tmp_list2->num);
  for(i=0; i<list->num; i++){
    ret = str_cascade(&ctx[atoi(list->list[i])], GROUP_NAME,
                       tmp_list2->list, NULL, &tmp);
    printf("\t::::str_cascade of %s returns %d with output %p\n",
           list->list[i],ret, tmp); 
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      k++;
      list->token_list = STR_add_token(list->token_list, tmp);
      tmp = NULL;
    }
    tmp=NULL;
  }
  if(k>1){
    fprintf(stderr, "%d ", k);
    fprintf(stderr, "Strange!!!");
  }

  k=0;
  for(i=0; i<tmp_list2->num; i++){
    ret = str_cascade(&ctx[atoi(tmp_list2->list[i])], GROUP_NAME,
                       list->list, NULL, &tmp);
    printf("\t::::str_cascade of %s returns %d with output %p\n",
           tmp_list2->list[i],ret,tmp); 
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      k++;
      tmp_list2->token_list = STR_add_token(tmp_list2->token_list, tmp);
      tmp = NULL;
    }
  }
  if(k>1){
    fprintf(stderr, "Strange!!!");
  }

  return CPARTITION;
}


/* destroy_list */
void str_destroy_list(STR_LIST **list)
{
  STR_LIST *tmp_list=NULL;

  tmp_list = (*list)->next;
  while((*list) != NULL){
    if((*list)->token_list != NULL){
      (*list)->token_list = STR_remove_all_token((*list)->token_list);
    }
    free(*list);
    (*list) = tmp_list;
    if((*list) == NULL){
      break;
    }
    else{
      tmp_list = (*list)->next;
    }
  }

  return;
}

void str_check_list_secret (STR_CONTEXT *ctx[], CLQ_NAME *list[], int num) {
  int i;
  int same=TRUE;
  
  for (i=1; i < num; i++) {
    if (ctx[atoi(list[i])]->group_secret !=NULL) {
      if (BN_cmp(ctx[atoi(list[0])]->group_secret, ctx[atoi(list[i])]->group_secret)){ 
        same=FALSE;
      }
    }
    else {
      same = FALSE;
    }
  }
  
  if (same){
#ifdef DEBUG_ALL
    printf ("Group secret is the same in the entire group :)\n");
#endif
  }
  else{
    printf ("Group secret is NOT the same :(\n");
    exit(0);
  }
  
}


void STR_remove_add_list(STR_LIST *src, STR_LIST *dst, int index)
{
  int i=0;
  
  dst->list[dst->num] = src->list[index];
  dst->num++;

  for(i=index; i<src->num-1; i++){
    src->list[i] = src->list[i+1];
  }
  for(i=src->num-1; i>NUM_USERS+1; i++){
    src->list[i]=NULL;
  }
  src->num--;
}

