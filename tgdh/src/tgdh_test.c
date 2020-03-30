/*********************************************************************
 * tgdh_test.c                                                       * 
 * TGDH test source file.                                            * 
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
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <sys/resource.h>

#include "openssl/bn.h"
#include "tgdh_api.h"
#include "tgdh_api_misc.h"
#include "error.h"

#include "tgdh_test_misc.h"
#include "tgdh_test.h"

#ifdef TIMING
extern int print;
#endif

#define CMERGE 1
#define CPARTITION 2
#define C3MERGE 3
#define DEFAULT 10

int main(int argc, char **argv) {
  CLQ_NAME *user[NUM_USERS+1]={NULL};

  TGDH_LIST *list=NULL, *init_list=NULL, *tmp_list=NULL;
  
  TGDH_CONTEXT *ctx[NUM_USERS];
  CLQ_TOKEN *tmp=NULL;
  TOKEN_LIST *input=NULL;
  CLQ_TOKEN *output[NUM_USERS+1]={NULL};
  int num_users=NUM_USERS;
  int leaving_member=0;
  
  int ret=OK, Ret=CONTINUE;
  int i=0, j=0, k=0;
  int num_round=0;
  TOKEN_LIST *curr_token=NULL;
  TOKEN_LIST *tmp_input=NULL;

#ifdef BASIC
  int r=0, c=0;
  CLQ_NAME *users_leaving[NUM_USERS+1] = {NULL};
  CLQ_NAME *leaving_list[NUM_USERS+1]={NULL};
  CLQ_NAME *current_list[NUM_USERS+1]={NULL};
#endif
  
  if (!parse_args(argc,argv,&num_users,&num_round)) goto error;
  /*********************************/
  
  tmp_input = (TOKEN_LIST *)calloc(sizeof(TOKEN_LIST), 1);
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
  
  ret=tgdh_new_member(&ctx[0],user[0],GROUP_NAME);
  printf ("tgdh_new_member returns %d \n",ret);
  if (ret!=1) goto error;

  for(i=0; i<NUM_USERS+1; i++) {
    output[i] = NULL;
  }

  for(i=1; i<num_users; i++){
    ret=tgdh_new_member(&ctx[i],user[i],GROUP_NAME);
    printf ("\t:tgdh_new_member by %03d returns %d \n",i,ret);
    if (ret!=1) goto error;
    
    /* New member sends merge request */
    for(j=0; j<i; j++){
      ret=tgdh_merge_req(ctx[j], user[j], GROUP_NAME, NULL, &output[0]);
      printf ("\t::tgdh_merge_req by %03d returns %d with output %p\n",
              j,ret,output[0]);
      if (ret!=1) goto error;
      if(output[0] != NULL){
        input = add_token(input, output[0]);
      }
      output[0]=NULL;
    }
    if(input == NULL) {
      goto error;
    }
    
    /* Last member in the current group is the sponsor */
    ret=tgdh_merge_req(ctx[i], user[i], GROUP_NAME, NULL, &output[1]);
    printf ("\t::tgdh_merge_req by %03d returns %d with output %p\n",
            i,ret,output[1]);
    if (ret!=1) goto error;
    if(output[1] == NULL){
      fprintf(stderr, "something wrong!\n\n");
    }
    
    input = add_token(input, output[1]);
    if(input == NULL) {
      goto error;
    }
    output[1] = NULL;

    Ret=2;

    while(Ret != 1){
      k = 0;
      curr_token = input;
      
      Ret = 1;
      for(j=0; j<=i; j++){
        ret = tgdh_cascade(&ctx[j], GROUP_NAME, NULL,
                           curr_token, &tmp);
        printf("\t::::tgdh_cascade of %03d returns %d with output %p\n",
               j,ret, tmp); 
        if(ret <= 0) goto error;
        Ret = MAX(Ret, ret);
        if(tmp != NULL){
          if(output[k] != NULL){
            tgdh_destroy_token(&output[k]);
          }
          output[k] = tmp;
          if(output[k] == NULL) {
            goto error;
          }
          k++;
        }
        tmp=NULL;
      }
      input = remove_all_token(input);

      for(j=0; j<k; j++){
        input = add_token(input, output[j]);
        output[j] = NULL;
      }
    }
    input=remove_all_token(input);
    check_group_secret(ctx, i+1);
  }
  
  printf ("----------End of Join Event\n");
  check_group_secret(ctx, num_users);
  compare_key(ctx, num_users);

  list = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1);
  ret=tgdh_new_member(&ctx[num_users],user[num_users],GROUP_NAME);
  
  list->num = num_users;
  for(i=0; i<num_users; i++){
    list->list[i] = user[i];
  }

  for(i=0; i<num_round; i++){
    fprintf (stderr,"---------- Partition: fixed number Event %d\n", i);
    for(j=0; j<num_users-1; j++){
      list->token_list = remove_all_token(list->token_list);
      tmp_list = list;
      generate_i_partition(&tmp_list, ctx, num_users, j+1);
      while(tmp_list != NULL){
        Ret = 100;
        if(tmp_list->num != 1){
          while (Ret != 1){
            Ret = process_one_token_list(tmp_list, ctx);
          }
        }

        tmp_list->token_list = remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      
      fprintf (stderr, "----------Start of Make up Merge Event\n");

      tmp_list = list;
      while(tmp_list != NULL){
        tmp_list->token_list = remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      
      generate_all_merge_req(&list, ctx, num_users, user);
      Ret = 100;
      while (Ret != 1){
        Ret = process_one_token_list(list, ctx);
      }

      check_group_secret(ctx, num_users);
      fprintf (stderr, "----------Start of Join Event\n");

      tmp_list = list;
      while(tmp_list != NULL){
        tmp_list->token_list = remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      
      tmp_list = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1);
      tmp_list->num = 1;
      tmp_list->list[0] = user[num_users];
      for(k=1; k<NUM_USERS+1; k++){
        tmp_list->list[k] = NULL;
        tmp_list->leaving_list[k] = NULL;
      }
      tmp_list->next = NULL;

      list->next = tmp_list;

      generate_all_merge_req(&list, ctx, num_users+1, user);
    
      Ret = 100;
      while (Ret != 1){
        Ret = process_one_token_list(list, ctx);
      }
    
      fprintf (stderr,"----------Make-up Leave Event\n");
    
      tmp_list = list;
      while(tmp_list != NULL){
        tmp_list->token_list = remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      
      generate_leave(&list, ctx, num_users);
      
      Ret = 100;
      while (Ret != 1){
        Ret = process_one_token_list(list, ctx);
      }
      list->leaving_list[0]=NULL;

      fprintf (stderr, "----------Generate random Leave Event\n");
      tmp_list = list;
      while(tmp_list != NULL){
        tmp_list->token_list = remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      
      leaving_member = generate_r_leave(&list, ctx, num_users);
      
      Ret = 100;
      while (Ret != 1){
        Ret = process_one_token_list(list, ctx);
      }

      fprintf (stderr, "----------Make-up Join Event\n");

      tmp_list = list;
      while(tmp_list != NULL){
        tmp_list->token_list = remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      
      tmp_list = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1); 
      tmp_list->num = 1; 
      tmp_list->list[0] = user[leaving_member]; 
      for(k=1; k<NUM_USERS+1; k++){ 
        tmp_list->list[k] = NULL; 
        tmp_list->leaving_list[k] = NULL; 
      } 
      tmp_list->next = NULL; 
      
      list->next = tmp_list;
    
      generate_all_merge_req(&list, ctx, num_users, user);
      
      Ret = 100;
      while (Ret != 1){
        Ret = process_one_token_list(list, ctx);
      }
      
      tmp_list = list;
      while(tmp_list != NULL){
        tmp_list->token_list = remove_all_token(tmp_list->token_list);
        tmp_list = tmp_list->next;
      }
      
    }
    
  }
  
#ifdef CASCADE
  printf ("---------- Start of Cascaded Event\n");

  list = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1);
  
  list->num = num_users;
  for(i=0; i<num_users; i++){
    list->list[i] = user[i];
  }

  generate_partition(list, ctx);

  init_list = list;
  list = init_list;

  round = 0;
  getrusage(RUSAGE_SELF, &used);
  while(round<50){
    Ret = 0;
    l++;
    event = generate_random_event(&init_list, list, ctx, l+(int)used.ru_utime.tv_usec);

    if((event == 10) && (list->token_list != NULL)) {
/*        Ret = process_one_token_list(init_list, list, ctx); */
      Ret = process_one_token(list, ctx);
    }
    
    if(list->next != NULL){
      list = list->next;
    }
    else{
      list = init_list;
    }
    if(round % 100 == 0){
      fprintf(stderr, "round = %d\n", round);
    }
    if (Ret == OK) {
      round++;
    }
  }

#endif /* End of Basic */  
  free(tmp_input);
  
error:
  
  for (i=0; i < NUM_USERS; i++) {
    if (ctx[i] != NULL) tgdh_destroy_ctx(&(ctx[i]), 1);
    if (user[i] != NULL) free(user[i]);
  }
  if(init_list != NULL) destroy_list(&init_list);

  return 0;
}

/* This function processes one token list... In Spread state diagram
   notation, this function is called in the NEW_TREE state */
int process_one_token_list(TGDH_LIST *list, TGDH_CONTEXT *ctx[])
{
  int i, k, ret;
  TOKEN_LIST *curr_token=NULL, *tmp_input=NULL;
  CLQ_TOKEN *tmp=NULL, *output[NUM_USERS+1]={NULL};
  
  for(i=0; i<NUM_USERS+1; i++) {
    output[i] = NULL;
  }

  k=0;
  curr_token = list->token_list;
  tmp_input = (TOKEN_LIST *) calloc(sizeof(TOKEN_LIST), 1);

  do{
    list->status = 0;
    tmp_input->token = curr_token->token;
    tmp_input->next = NULL;

    for(i=0; i<list->num; i++){
      ret = tgdh_cascade(&ctx[atoi(list->list[i])], GROUP_NAME,
                         NULL, tmp_input, &tmp);
    
      printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
             atoi(list->list[i]),ret, tmp);
      if(ret <= 0) exit(1);
      if(((list->status > 1) && (ret == OK)) &&
         ((list->status == OK) && (ret > 1))){ 
        fprintf(stderr, "WHATTTTT????\n");
      }
      list->status = MAX(list->status, ret);
      if(tmp != NULL){
        if(output[k] != NULL){
          tgdh_destroy_token(&output[k]);
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
      list->token_list = remove_all_token(list->token_list);
      break;
    }
    curr_token = curr_token->next;
  } while (curr_token != NULL);
    
  list->token_list = remove_all_token(list->token_list);
    
  for(i=0; i<k; i++){
    list->token_list = add_token(list->token_list, output[i]);
    output[i] = NULL;
  }

  if(list->status == OK){
    check_list_secret(ctx, list->list, list->num);
  }

  free(tmp_input);
  return list->status;
}

/* This function processes single token... In Spread state diagram
   notation, this function is called in the NEW_TREE state */
int process_one_token(TGDH_LIST *list, TGDH_CONTEXT *ctx[])
{
  int i, k, ret;
  CLQ_TOKEN *tmp=NULL, *output[NUM_USERS+1]={NULL};
  TOKEN_LIST *tmp_input=NULL;
  
  for(i=0; i<NUM_USERS+1; i++) {
    output[i] = NULL;
  }

  k=0;
  list->status = 0;
  tmp_input = (TOKEN_LIST *) calloc(sizeof(TOKEN_LIST), 1);
  
  tmp_input->token = list->token_list->token;
  tmp_input->next = NULL;
  for(i=0; i<list->num; i++){
    ret = tgdh_cascade(&ctx[atoi(list->list[i])], GROUP_NAME,
                       NULL, tmp_input, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi(list->list[i]),ret, tmp);
    if(ret <= 0) exit(1);
    if(((list->status > 1) && (ret == OK)) &&
       ((list->status == OK) && (ret > 1))){ 
      fprintf(stderr, "WHATTTTT????\n");
    }
    list->status = MAX(list->status, ret);
    if(tmp != NULL){
      if(output[k] != NULL){
        tgdh_destroy_token(&output[k]);
      }
      output[k] = tmp;
      if(output[k] == NULL) {
        exit(1);
      }
      k++;
    }
    tmp=NULL;
  }
  list->token_list = remove_token(&(list->token_list));
    
  for(i=0; i<k; i++){
    list->token_list = add_token(list->token_list, output[i]);
    output[i] = NULL;
  }

  if(list->status == OK){
    check_list_secret(ctx, list->list, list->num);
    list->token_list = remove_all_token(list->token_list);
  }

  free(tmp_input);
  return list->status;
}

/* This function generates a random event for the current group */
int generate_random_event(TGDH_LIST **init_list, TGDH_LIST *list,
                          TGDH_CONTEXT *ctx[], int seed)
{
  int num_group=0, event=0;
  TGDH_LIST *tmp_list=NULL;
  

  tmp_list = (*init_list);
  while(tmp_list != NULL){
    tmp_list = tmp_list->next;
    num_group++;
  }

  srand(seed);
  event = (int) rand() % DEFAULT;

  if(event < CMERGE){
    if(num_group == 1){
      fprintf(stderr, "  *\n");
      return DEFAULT;
    }
    else{
      if(generate_merge(&(*init_list), list, ctx) == CMERGE){
        return CMERGE;
      }
      else{
        return DEFAULT;
      }
    }
  }
  else if(event < CPARTITION){
    if(list->num == 1){
      fprintf(stderr, "  *\n");
      return DEFAULT;
    }
    else{
      if(generate_partition(list, ctx) == CPARTITION){
        return CPARTITION;
      }
      else{
        return DEFAULT;
      }
    }
  }
  else if(event < C3MERGE){
    if(num_group <= 2){
      fprintf(stderr, "  *\n");
      return DEFAULT;
    }
    else{
      if(generate3merge(&(*init_list), list, ctx) == C3MERGE){
        return C3MERGE;
      }
      else{
        return DEFAULT;
      }
    }
  }
  else {
    fprintf(stderr, "  *\n");
  }

  return DEFAULT;
}

/* generate_r_leave */
int generate_r_leave(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users)
{
  int i, ret, N;
  CLQ_TOKEN *tmp=NULL;
  CLQ_NAME *tmp_name=NULL;

  if((*list)->token_list != NULL){
    (*list)->token_list = remove_all_token((*list)->token_list);
  }
  N = rand() % num_users;
  tmp_name = (*list)->list[N];
  (*list)->leaving_list[0] = tmp_name;
  for(i=N; i<num_users-1; i++){
    (*list)->list[i] = (*list)->list[i+1];
  }
  
  (*list)->list[num_users-1] = NULL;
  (*list)->num--;
  
  for(i=0; i<(*list)->num; i++){
    ret = tgdh_cascade(&ctx[atoi((*list)->list[i])], GROUP_NAME,
                       (*list)->leaving_list, NULL, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi((*list)->list[i]),ret, tmp);
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      (*list)->token_list = add_token((*list)->token_list, tmp);
      tmp = NULL;
    }
    tmp=NULL;
  }

  ret = tgdh_cascade(&ctx[N], GROUP_NAME, (*list)->list, NULL, &tmp);
  printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
         atoi(tmp_name),ret, tmp); 
  
  return N;
}

/* generate_leave */
void generate_leave(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users)
{
  int i, ret;
  CLQ_TOKEN *tmp=NULL;
  CLQ_NAME *tmp_name=NULL;

  if((*list)->token_list != NULL){
    (*list)->token_list = remove_all_token((*list)->token_list);
  }
  tmp_name = (*list)->list[num_users];
  (*list)->leaving_list[0] = (*list)->list[num_users];
  (*list)->list[num_users] = NULL;
  (*list)->num--;
  
  for(i=0; i<(*list)->num; i++){
    ret = tgdh_cascade(&ctx[atoi((*list)->list[i])], GROUP_NAME,
                       (*list)->leaving_list, NULL, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi((*list)->list[i]),ret, tmp);
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      (*list)->token_list = add_token((*list)->token_list, tmp);
      tmp = NULL;
    }
    tmp=NULL;
  }

  ret = tgdh_cascade(&ctx[num_users], GROUP_NAME, (*list)->list, NULL, &tmp);
  printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
         atoi(tmp_name),ret, tmp);
  
  return;
}

void remove_add_list(TGDH_LIST *src, TGDH_LIST *dst, int index)
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


/* generate_i_partition */
void generate_i_partition(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users, int num_leaves)
{
  int i, ret, leave_index=0, N, num, tmp_num, j, k;
  TGDH_LIST *tlist=NULL, *tlist1=NULL;
  TGDH_LIST *tmp_list[NUM_USERS+1]={NULL};
  CLQ_NAME *tmp_name[NUM_USERS+1], *tmp1_name[NUM_USERS+1];
  CLQ_TOKEN *tmp=NULL;
  struct rusage used;

  if((*list)->num < 2){
    fprintf(stderr, "  *\n");
    return;
  }

  if((*list)->token_list != NULL){
    (*list)->token_list = remove_all_token((*list)->token_list);
  }
  (*list)->next = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1);
  
  for(i=0; i<NUM_USERS; i++){
    tmp1_name[i]=(*list)->list[i];
  }

  getrusage(RUSAGE_SELF, &used);
  srand(used.ru_utime.tv_usec+36218368);

  for(i=0; i<num_leaves; i++){
    leave_index = rand() % ((*list)->num);
    remove_add_list((*list), (*list)->next, leave_index);
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
      tmp_list[i] = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1);
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
      ret = tgdh_cascade(&ctx[atoi(tlist->list[i])], GROUP_NAME,
                         tlist->leaving_list, NULL, &tmp);
      printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
             atoi(tlist->list[i]),ret, tmp);
      if(ret <= 0) exit(ret);
      if(tmp != NULL){
        tlist->token_list = add_token(tlist->token_list, tmp);
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

/* generate_n_partition */
void generate_n_partition(TGDH_LIST **list, TGDH_CONTEXT *ctx[], int num_users)
{
  TGDH_LIST *tmp_list[NUM_USERS+1]={NULL}, *tlist=NULL;
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
    (*list)->token_list = remove_all_token((*list)->token_list);
  }
  tlist=tmp_list[0] = (*list);

  getrusage(RUSAGE_SELF, &used);
  srand(used.ru_utime.tv_usec+36218368);
  N = (int)rand() % 3;
  N += 2;
  
  for(i=0; i<NUM_USERS+1; i++){
    tmp_name[i] = (*list)->list[i];
    (*list)->list[i] = NULL;
  }
  num = (*list)->num;
  (*list)->num = 1;
  
  for(i=1; i<N; i++){
    tmp_list[i] = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1);
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
      ret = tgdh_cascade(&ctx[atoi(tlist->list[i])], GROUP_NAME,
                         tlist->leaving_list, NULL, &tmp);
      
      printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
             atoi(tlist->list[i]),ret, tmp);
      if(ret <= 0) exit(ret);
      if(tmp != NULL){
        tlist->token_list = add_token(tlist->token_list, tmp);
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

/* generate_partition */
int generate_partition(TGDH_LIST *list, TGDH_CONTEXT *ctx[])
{
  TGDH_LIST *tmp_list1=NULL, *tmp_list2=NULL;
  int i, num, ret;
  CLQ_NAME *tmp_name[NUM_USERS+1];
  CLQ_TOKEN *tmp=NULL;

  if(list->num < 2){
    fprintf(stderr, "  *\n");
    return DEFAULT;
  }

  if(list->token_list != NULL){
    list->token_list = remove_all_token(list->token_list);
  }
  tmp_list1 = list;
  while(tmp_list1->next != NULL){
    tmp_list1 = tmp_list1->next;
  }

  tmp_list2 = (TGDH_LIST *) calloc(sizeof(TGDH_LIST), 1);
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

  fprintf(stderr, "++Partition happened %d:%d\n", list->num, tmp_list2->num);
  for(i=0; i<list->num; i++){
    ret = tgdh_cascade(&ctx[atoi(list->list[i])], GROUP_NAME,
                       tmp_list2->list, NULL, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi(list->list[i]),ret, tmp); 
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      list->token_list = add_token(list->token_list, tmp);
      tmp = NULL;
    }
    tmp=NULL;
  }
  
  for(i=0; i<tmp_list2->num; i++){
    ret = tgdh_cascade(&ctx[atoi(tmp_list2->list[i])], GROUP_NAME,
                       list->list, NULL, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi(tmp_list2->list[i]),ret,tmp); 
    if(ret <= 0) exit(ret);
    if(tmp != NULL){
      tmp_list2->token_list = add_token(tmp_list2->token_list, tmp);
      tmp = NULL;
    }
  }

  return CPARTITION;
}

/* generate_all_merge_req */
void generate_all_merge_req(TGDH_LIST **list, TGDH_CONTEXT *ctx[],
                            int num_users, CLQ_NAME *user[])
{
  TGDH_LIST *tmp_list[NUM_USERS+1]={NULL}, *tlist = NULL;
  int i=0, num=0, ret=0;
  CLQ_TOKEN *tmp=NULL;
  TOKEN_LIST *tmp_token_list=NULL;

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
  destroy_list(&tmp_list[0]);
  (*list)->next = NULL;
  
  for(i=0; i<(*list)->num; i++){
    ret=tgdh_merge_req(ctx[atoi((*list)->list[i])], (*list)->list[i],
                       GROUP_NAME, NULL, &tmp); 
    printf ("\t::tgdh_merge_req by %03d returns %d with output %p\n",
            atoi((*list)->list[i]),ret,tmp);
    if (ret!=1) {
      exit(0);
    }
    if(tmp != NULL){
      (*list)->token_list = add_token((*list)->token_list, tmp);
    }
    tmp=NULL;
  }
  for(i=0; i<(*list)->num; i++){
    ret = tgdh_cascade(&ctx[atoi((*list)->list[i])], GROUP_NAME, NULL,
                       (*list)->token_list, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi((*list)->list[i]),ret, tmp);
    if(ret <= 0){
      exit(0);
    }
    if(tmp != NULL){
      tmp_token_list = add_token(tmp_token_list, tmp);
    }
    tmp=NULL;
  }
  (*list)->token_list = remove_all_token((*list)->token_list);

  (*list)->token_list = tmp_token_list;

  return;
}

/* generate_merge */
int generate_merge(TGDH_LIST **init_list, TGDH_LIST *list,
                   TGDH_CONTEXT *ctx[]) 
{
  TGDH_LIST *tmp_list1=NULL, *tmp_list2=NULL;
  int i=0, num=0, ret=0;
  int num_group=0;
  CLQ_TOKEN *tmp=NULL;
  TOKEN_LIST *tmp_token_list=NULL;

  if((*init_list) == list){
    fprintf(stderr, "  *\n");
    return DEFAULT;
  }

  tmp_list1 = (*init_list);
  while(tmp_list1 != NULL){
    num_group++;
    tmp_list1 = tmp_list1->next;
  }

  num = (int)(rand()) % num_group;

  tmp_list1 = (*init_list);

  for(i=0; i<num; i++){
    tmp_list1 = tmp_list1->next;
  }
  if(tmp_list1 == list){
    fprintf(stderr, "  *\n");
    return DEFAULT;
  }
  
  tmp_list1 = (*init_list);

  if(num == 0){
    tmp_list2 = (*init_list);
    (*init_list) = (*init_list)->next;
  }
  else{
    for(i=0; i<num-1; i++){
      tmp_list1 = tmp_list1->next;
    }
    tmp_list2 = tmp_list1->next;
    if(tmp_list2->next != NULL){
      tmp_list1->next = tmp_list2->next;
    }
    else{
      tmp_list1->next = NULL;
    }
  }
  
  for(i=0; i<tmp_list2->num; i++){
    list->list[i+list->num] = tmp_list2->list[i];
  }
  list->num += tmp_list2->num;
  tmp_list2->next = NULL;

  fprintf(stderr, "++Merge happened %d\n", list->num);

  destroy_list(&tmp_list2);
  list->token_list = remove_all_token(list->token_list); 

  for(i=0; i<list->num; i++){
    ret=tgdh_merge_req(ctx[atoi(list->list[i])], list->list[i],
                       GROUP_NAME, NULL, &tmp); 
    printf ("\t::tgdh_merge_req by %03d returns %d with output %p\n",
            atoi(list->list[i]),ret,tmp);
    if (ret!=1) {
      exit(0);
    }
    if(tmp != NULL){
      list->token_list = add_token(list->token_list, tmp);
    }
    tmp=NULL;
  }
  if(list->token_list == NULL) {
    exit(0);
  }

  for(i=0; i<list->num; i++){
    ret = tgdh_cascade(&ctx[atoi(list->list[i])], GROUP_NAME, NULL,
                       list->token_list, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi(list->list[i]),ret, tmp); 
    if(ret <= 0){
      exit(0);
    }
    if(tmp != NULL){
      tmp_token_list = add_token(tmp_token_list, tmp);
    }
    tmp=NULL;
  }
  list->token_list = remove_all_token(list->token_list);

  list->token_list = tmp_token_list;

  return CMERGE;
}

/* generate3merge */
int generate3merge(TGDH_LIST **init_list, TGDH_LIST *list,
                   TGDH_CONTEXT *ctx[]) 
{
  TGDH_LIST *tmp_list1=NULL, *tmp_list2=NULL, *tmp_list3=NULL;
  int i=0, num=0, ret=0, num1=0, listnum=0;
  int num_group=0;
  CLQ_TOKEN *tmp=NULL;
  TOKEN_LIST *tmp_token_list=NULL;

  if((*init_list) == list){
    fprintf(stderr, "  *\n");
    return DEFAULT;
  }

  tmp_list1 = (*init_list);
  while(tmp_list1 != NULL){
    num_group++;
    tmp_list1 = tmp_list1->next;
  }
  tmp_list1 = (*init_list);
  for(listnum = 0; tmp_list1 != list; listnum++){
    tmp_list1 = tmp_list1->next;
  }

  num = (int)(rand()) % num_group;
  num1 = (int)(rand()) % (num_group-1);
  
  tmp_list1 = (*init_list);

  for(i=0; i<num; i++){
    tmp_list1 = tmp_list1->next;
  }
  if((tmp_list1 == list) || (num_group <= 2)){
    fprintf(stderr, "  *\n");
    return DEFAULT;
  }

  tmp_list2 = (*init_list);
  for(i=0; i<num1; i++){
    tmp_list2 = tmp_list2->next;
  }
  if((tmp_list2 == list) || (tmp_list2 == tmp_list1)){
    fprintf(stderr, "  *\n");
    return DEFAULT;
  }
  
  tmp_list1 = (*init_list);

  if(num == 0){
    tmp_list2 = (*init_list);
    (*init_list) = (*init_list)->next;
  }
  else{
    for(i=0; i<num-1; i++){
      tmp_list1 = tmp_list1->next;
    }
    tmp_list2 = tmp_list1->next;
    if(tmp_list2->next != NULL){
      tmp_list1->next = tmp_list2->next;
    }
    else{
      tmp_list1->next = NULL;
    }
  }

  for(i=0; i<tmp_list2->num; i++){
    list->list[i+list->num] = tmp_list2->list[i];
  }
  list->num += tmp_list2->num;
  tmp_list2->next = NULL;
  destroy_list(&tmp_list2);

  tmp_list1 = (*init_list);
  if((num1 == 0) || (num1 == 1)){
    /*  if((num1 == 0) || ((num == 0) && (num1 == 1))){ */
    tmp_list3 = (*init_list);
    (*init_list) = (*init_list)->next;
  }
  else{
    for(i=0; i<num1-2; i++){
      tmp_list1 = tmp_list1->next;
    }
    if(num > num1){
      tmp_list1 = tmp_list1->next;
    }
    
    tmp_list3 = tmp_list1->next;
    if(tmp_list3->next != NULL){
      tmp_list1->next = tmp_list3->next;
    }
    else{
      tmp_list1->next = NULL;
    }
  }
  
  for(i=0; i<tmp_list3->num; i++){
    list->list[i+list->num] = tmp_list3->list[i];
  }
  list->num += tmp_list3->num;
  tmp_list3->next = NULL;

  fprintf(stderr, "++3Merge happened %d: %d, %d\n", list->num, num, num1);

  destroy_list(&tmp_list3);
  
  list->token_list = remove_all_token(list->token_list); 

  for(i=0; i<list->num; i++){
    ret=tgdh_merge_req(ctx[atoi(list->list[i])], list->list[i],
                       GROUP_NAME, NULL, &tmp); 
    printf ("\t::tgdh_merge_req by %03d returns %d with output %p\n",
            atoi(list->list[i]),ret,tmp);
    if (ret!=1) {
      exit(0);
    }
    if(tmp != NULL){
      list->token_list = add_token(list->token_list, tmp);
    }
    tmp=NULL;
  }
  if(list->token_list == NULL) {
    exit(0);
  }

  for(i=0; i<list->num; i++){
    ret = tgdh_cascade(&ctx[atoi(list->list[i])], GROUP_NAME, NULL,
                       list->token_list, &tmp);
    printf("\t::::tgdh_cascade by %03d returns %d with output %p\n",
           atoi(list->list[i]),ret, tmp); 
    if(ret <= 0){
      exit(0);
    }
    if(tmp != NULL){
      tmp_token_list = add_token(tmp_token_list, tmp);
    }
    tmp=NULL;
  }
  list->token_list = remove_all_token(list->token_list);

  list->token_list = tmp_token_list;

  return C3MERGE;
}


/* destroy_list */
void destroy_list(TGDH_LIST **list)
{
  TGDH_LIST *tmp_list=NULL;

  tmp_list = (*list)->next;
  while((*list) != NULL){
    if((*list)->token_list != NULL){
      (*list)->token_list = remove_all_token((*list)->token_list);
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

void check_list_secret (TGDH_CONTEXT *ctx[], CLQ_NAME *list[], int num) {
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

