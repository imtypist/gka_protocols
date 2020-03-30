/*********************************************************************
 * tgdh_api.c                                                        * 
 * TGDH main source file                                             * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *                                                                   *
 * Date      Tue March 24, 2020  9:48 PM                             *
 * Maintained by:                                                    *
 * Junqin Huang                                                      *
 *                                                                   *
 * Shanghai Jiao Tong University                                     *
 *********************************************************************/

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <math.h>

#include <netinet/in.h> /* Needed by htonl and ntohl */

/* SSL include files */
#include "openssl/bn.h"
#include "openssl/bio.h"
#include "openssl/md5.h"
#include "openssl/err.h"
#include "openssl/dsa.h"

/* TGDH_API include files */
#include "tgdh_api.h"
#include "error.h"
#include "common.h" /* clq_get_cert is here */

#include "tgdh_sig.h"
#include "tgdh_test_misc.h" /* tgdh_get_time is defined here */

#include "tgdh_api_misc.h" /* tgdh_get_time is defined here */


/* dmalloc CNR.  */
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/* tgdh_new_member is called by the new member in order to create its
 *   own context. Main functionality of this function is to generate
 *   session random for the member
 */
int tgdh_new_member(TGDH_CONTEXT **ctx, CLQ_NAME *member_name,
                    CLQ_NAME *group_name)
{
  int ret=OK;

  if(member_name == NULL) return INVALID_MEMBER_NAME;
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  
  if ((ret=tgdh_create_ctx(ctx)) != OK) {goto error;}
  
  (*ctx)->member_name=(CLQ_NAME *) calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
  if (((*ctx)->member_name) == NULL) { ret=MALLOC_ERROR; goto error; }
  strncpy((*ctx)->member_name,member_name,MAX_LGT_NAME);
  (*ctx)->group_name=(CLQ_NAME *) calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
  if (((*ctx)->group_name) == NULL) { ret=MALLOC_ERROR; goto error; }
  strncpy((*ctx)->group_name,group_name,MAX_LGT_NAME);
  /* Get DSA parameters */
  (*ctx)->params=clq_read_dsa(NULL,CLQ_PARAMS);
  if ((*ctx)->params == (DSA *)NULL) { ret=INVALID_DSA_PARAMS; goto error; }
  /* Get user private and public keys */
  (*ctx)->pkey=clq_get_pkey(member_name);
  if (((*ctx)->pkey) == (EVP_PKEY*) NULL) { ret=INVALID_PRIV_KEY; goto error; }
  
  (*ctx)->root->tgdh_nv=(TGDH_NV *) calloc(sizeof(TGDH_NV),1);
  (*ctx)->root->tgdh_nv->member = (TGDH_GM *) calloc(sizeof(TGDH_GM),1);
  (*ctx)->root->tgdh_nv->member->member_name=(CLQ_NAME *)
    calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1); 
  strncpy ((*ctx)->root->tgdh_nv->member->member_name,
           (*ctx)->member_name,MAX_LGT_NAME);
  (*ctx)->root->tgdh_nv->member->cert = NULL;
  
  (*ctx)->root->tgdh_nv->index=1;
  (*ctx)->root->tgdh_nv->num_node=1;
  (*ctx)->root->tgdh_nv->height=0;
  (*ctx)->root->tgdh_nv->potential=-1;
  (*ctx)->root->tgdh_nv->joinQ=FALSE;
  
  /* I'm only member in my group... So key is same as my session random */
  (*ctx)->root->tgdh_nv->key=tgdh_rand((*ctx)->params);
  if (BN_is_zero((*ctx)->root->tgdh_nv->key) ||
      (*ctx)->root->tgdh_nv->key==NULL){
    ret=MALLOC_ERROR;
    goto error;
  }
  /* group_secret is same as key */
  if((*ctx)->group_secret == NULL){
    (*ctx)->group_secret=BN_dup((*ctx)->root->tgdh_nv->key);
    if ((*ctx)->group_secret == (BIGNUM *) NULL) {
      ret=MALLOC_ERROR;
      goto error;
    }
  }
  else{
    BN_copy((*ctx)->group_secret,(*ctx)->root->tgdh_nv->key);
  }
  
  ret=tgdh_compute_secret_hash ((*ctx));
  if (ret!=OK) goto error;
  (*ctx)->root->tgdh_nv->member->cert=NULL;
  
  /* Compute blinded Key */
  (*ctx)->root->tgdh_nv->bkey=
    tgdh_compute_bkey((*ctx)->root->tgdh_nv->key, (*ctx)->params);
  if((*ctx)->root->tgdh_nv->bkey== NULL){
    ret=MALLOC_ERROR;
    goto error;
  }
  (*ctx)->tmp_key = (*ctx)->tmp_bkey = NULL;
  (*ctx)->status = OK;

error:
  /* OK... Let's free the memory */
  if (ret!=OK) tgdh_destroy_ctx(&(*ctx),1);
  
  return ret;
}

/* tgdh_merge_req is called by every members in both groups and only
 * the sponsors will return a output token
 *   o When any addtive event happens this function will be called.
 *   o In other words, if merge and leave happen, we need to call this
 *     function also.
 *   o If only addtive event happens, users_leaving should be NULL.
 *   ctx: context of the caller
 *   member_name: name of the caller
 *   users_leaving: name of the leaving members
 *   group_name: target group name
 *   output: output token(input token of tgdh_merge)
 */
int tgdh_merge_req (TGDH_CONTEXT *ctx, CLQ_NAME *member_name, 
                    CLQ_NAME *group_name, CLQ_NAME *users_leaving[],
                    CLQ_TOKEN **output)
{
  int ret=OK;
  TGDH_TOKEN_INFO *info=NULL;
  KEY_TREE *tmp_tree=NULL, *tmp1_tree=NULL;

  KEY_TREE *the_sponsor=NULL;
  int sponsor = 0;
  BN_CTX *bn_ctx=BN_CTX_new();
  
  if (ctx == NULL) return CTX_ERROR;
  if (member_name == NULL) return INVALID_MEMBER_NAME;
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;

  /* If we want change key and if I am not the root node */
  tmp_tree = tgdh_search_member(ctx->root, 4, ctx->member_name);
  
  if((the_sponsor == NULL) && (tmp_tree != ctx->root) ){
    the_sponsor = tgdh_search_member(ctx->root, 6, NULL);
    if(the_sponsor == NULL){
      fprintf(stderr, "The sponsor is NULL!\n");
      ret = STRUCTURE_ERROR;
      goto error;
    }
    else{
#ifdef DEBUG_YD
      fprintf(stderr, "The sponsor is %s\n",
              the_sponsor->tgdh_nv->member->member_name);
#endif
    }
  }

  if (the_sponsor == NULL){
    /*
     * This means that I am the only member in my tree. So we don't
     * need to change key... We just need to broadcast, since I am the
     * sponsor
     */
    sponsor = 1;
    ret = OK;
    goto error;
  }

  /* Remove keys and bkeys related with the sponsor */
  tmp_tree = the_sponsor;
  while(tmp_tree != NULL){
    if(tmp_tree->tgdh_nv->bkey != NULL){
      BN_clear_free(tmp_tree->tgdh_nv->bkey);
      tmp_tree->tgdh_nv->bkey = NULL;
    }
    if(tmp_tree->tgdh_nv->key != NULL){
      BN_clear_free(tmp_tree->tgdh_nv->key);
      tmp_tree->tgdh_nv->key = NULL;
    }
    tmp_tree = tmp_tree->parent;
  }

  /* If I am not the sponsor, quietly go out */
  if(strcmp(the_sponsor->tgdh_nv->member->member_name,
            ctx->member_name)!=0){ 
    ret = OK;
    goto error;
  }

  /* Now, I am the sponsor */

  /* Generate new key and bkeys for the sponsor */
  the_sponsor->tgdh_nv->key=tgdh_rand(ctx->params);
  the_sponsor->tgdh_nv->bkey=
    tgdh_compute_bkey(the_sponsor->tgdh_nv->key, ctx->params);
  sponsor = 1;
  
  /* Now compute every key and bkey */
  tmp_tree = the_sponsor;

  if(tmp_tree->parent->tgdh_nv->key != NULL){
    fprintf(stderr, "Parent key is not null 1!\n");
    ret = STRUCTURE_ERROR;
    goto error;
  }
  if(tmp_tree->tgdh_nv->index % 2){
    tmp1_tree = tmp_tree->parent->left;
  }
  else{
    tmp1_tree = tmp_tree->parent->right;
  }
  while(tmp1_tree->tgdh_nv->bkey != NULL){
    /* Compute intermediate keys until I can */
    if(tmp_tree->parent->tgdh_nv->key != NULL){
      fprintf(stderr, "Parent key is not null 2!\n");
      ret=STRUCTURE_ERROR;
      goto error;
    }
    tmp_tree->parent->tgdh_nv->key = BN_new();
    sponsor = 1;
    if(tmp_tree->parent->left->tgdh_nv->key != NULL){
      ret = BN_mod(tmp_tree->parent->left->tgdh_nv->key,
                   tmp_tree->parent->left->tgdh_nv->key,
                   DSA_get0_q(ctx->params), bn_ctx);
      if(ret != OK) goto error;
      
      ret=BN_mod_exp(tmp_tree->parent->tgdh_nv->key, 
                     tmp_tree->parent->right->tgdh_nv->bkey,
                     tmp_tree->parent->left->tgdh_nv->key,
                     DSA_get0_p(ctx->params),bn_ctx);
    }
    else{
      ret = BN_mod(tmp_tree->parent->right->tgdh_nv->key,
                   tmp_tree->parent->right->tgdh_nv->key,
                   DSA_get0_q(ctx->params), bn_ctx);
      if(ret != OK) goto error;
      ret=BN_mod_exp(tmp_tree->parent->tgdh_nv->key,
                     tmp_tree->parent->left->tgdh_nv->bkey,
                     tmp_tree->parent->right->tgdh_nv->key,
                     DSA_get0_p(ctx->params),bn_ctx);
    }
    if(ret != OK) {
      fprintf(stderr, "mod exp problem\n");
      goto error;
    }
    
    /* Compute bkeys */
    if(tmp_tree->parent->tgdh_nv->bkey != NULL){
      BN_clear_free(tmp_tree->parent->tgdh_nv->bkey);
      tmp_tree->parent->tgdh_nv->bkey=NULL;
    }
    tmp_tree->parent->tgdh_nv->bkey
      =tgdh_compute_bkey(tmp_tree->parent->tgdh_nv->key, ctx->params);
    
    if(tmp_tree->parent->parent == NULL) {
      break;
    }
    else{
      tmp_tree = tmp_tree->parent;
    }
    if(tmp_tree->tgdh_nv->index % 2){
      tmp1_tree = tmp_tree->parent->left;
    }
    else{
      tmp1_tree = tmp_tree->parent->right;
    }
  }
  

error:
  if(sponsor==1){
    /* Creating token info */
    ret=tgdh_create_token_info(&info,ctx->group_name,TGDH_KEY_MERGE_UPDATE, 
                               time(0),ctx->member_name); 
    /* Encoding */
    if(ret == 1){
      ret=tgdh_encode(ctx,output,info);
    }
    /* sign_message */
    if(ret == 1){
      ret=tgdh_sign_message (ctx, *output);
    }
  }
  
  /* OK... Let's free the memory */
  if (ret!=OK) tgdh_destroy_ctx(&ctx, 1);
  if (info != (TGDH_TOKEN_INFO*)NULL) tgdh_destroy_token_info(&info);
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);
  
  return ret;
}

/* tgdh_cascade is called by every member several times until every
 * member can compute the new group key when any network events occur.
 * o this function handles every membership event, e.g. join, leave,
 *   merge, and partition.
 * o this function handles any cascaded events.
 * o this funciton is tgdh-stabilizing.
 * o sponsors are decided uniquely for every membership event, and
 *   only the sponsors return an output
 *   - ctx: context of the caller
 *   - member_name: name of the caller
 *   - users_leaving: list of the leaving members, used only for
 *       subtractive events
 *   - input: Input token(previous output token of
 *       tgdh_cascade or join or merge request) 
 *   - output: output token(will be used as next input token of
 *       tgdh_cascade) 
 */
int tgdh_cascade(TGDH_CONTEXT **ctx, CLQ_NAME *group_name,
                 CLQ_NAME *users_leaving[], 
                 TOKEN_LIST *list, CLQ_TOKEN **output){
  TGDH_TOKEN_INFO *info=NULL;
  int i=0;
  TGDH_SIGN *sign=NULL;
  int ret=CONTINUE;
  KEY_TREE *tmp_node=NULL, *tmp1_node=NULL;
  int num_sponsor=0;
  
  int new_information=0;
  int result=OK;
  int new_status=0;
  int new_key_comp=0;
  BN_CTX *bn_ctx=BN_CTX_new();
  KEY_TREE *sponsor_list[NUM_USERS+1]={NULL};
  int sponsor=0, sender=0;
  int leaveormerge=0;
  int message_type=-1;
  TOKEN_LIST *tmp_list=NULL;
  TREE_LIST *new_tree_list=NULL, *tmp_tree_list=NULL;
  TGDH_CONTEXT *new_ctx=NULL;
  int epoch=0;

  for(i=0; i<NUM_USERS+1; i++){
    sponsor_list[i]=NULL;
  }
  
  /* Doing some error checkings */
  if ((*ctx) == NULL) return CTX_ERROR;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;

  /*    tgdh_print_simple("Initial", (*ctx)->root); */
  if(users_leaving != NULL){
    leaveormerge = 1;

    result = remove_member(*ctx, users_leaving, sponsor_list);
    if(result == 4){
      result = (*ctx)->status;
      goto error;
    }
    
    else{
      if(result < 0){
        goto error;
      }
    }

    i=0;
    if(sponsor_list[0] == NULL){
      fprintf(stderr, "No sponsor? Strange!!!\n");
      goto error;
    }
    
    while(sponsor_list[i] != NULL){
      if(strcmp(sponsor_list[i]->tgdh_nv->member->member_name,
              (*ctx)->member_name)== 0){
        new_information = 1;
        new_key_comp = 1;
        if(sponsor_list[i]->tgdh_nv->key == NULL){
          sponsor_list[i]->tgdh_nv->key=tgdh_rand((*ctx)->params);
          sponsor_list[i]->tgdh_nv->bkey
            =tgdh_compute_bkey(sponsor_list[i]->tgdh_nv->key,
                               (*ctx)->params);
        }
        sponsor = 1;
        /* why not break here? */
      }
      i++;
    }
  }
  else{ /* This is not leave */
    if(list == NULL) {
      result = INVALID_INPUT_TOKEN;
      printf("This is weird 2\n\n");
        
      goto error;
    }

    tmp_list = list;
    while (tmp_list != NULL){
      result=tgdh_remove_sign(tmp_list->token,&sign);
      if (result != OK) goto error;
        
      /* Decoding the token & creating new_ctx */
      result=tgdh_decode(&new_ctx, tmp_list->token, &info);
      if(strcmp(info->sender_name, (*ctx)->member_name) == 0){
        sender = 1;
      }
      epoch=MAX(new_ctx->epoch, epoch);
      if (result!=OK){
        goto error;
      }
      new_status = new_ctx->status;
      if (strcmp(info->group_name,group_name)){
        result=GROUP_NAME_MISMATCH;
        goto error;
      }
      /* Before merging the tree, we need to verify signature */
      result=tgdh_vrfy_sign ((*ctx), new_ctx, tmp_list->token,
                             info->sender_name, sign);
      if(result!=OK) goto error;
        
      if(tmp_list->token != NULL){
        result=tgdh_restore_sign(tmp_list->token,&sign);
      }

      tmp_node = tgdh_search_member(new_ctx->root, 4, (*ctx)->member_name);
      if(tmp_node != NULL){  
        if(tgdh_check_useful(new_ctx->root, (*ctx)->root)==1){
          /* Copy new information(if any) to my context;           */
          /* Tree should be same to process the following function */
          tgdh_swap_bkey(new_ctx->root, (*ctx)->root);
        }
        tgdh_free_tree(&(new_ctx->root));
        new_ctx->root = (*ctx)->root;
      }
      
      /* Add new_ctx, info to new_tree_list */
      new_tree_list = add_tree_list(new_tree_list, new_ctx->root);
      tmp_list = tmp_list->next;
      message_type = info->message_type;
      
      tgdh_destroy_ctx(&new_ctx, 0);
      tgdh_destroy_token_info(&info);
    }
    
    switch (message_type) { /* There is no leave or join event */

      /*****************/
      /*               */
      /* JOIN or MERGE */
      /*               */
      /*****************/
      case TGDH_KEY_MERGE_UPDATE:
      {

        (*ctx)->status = CONTINUE;
        leaveormerge = 1;

        (*ctx)->root = new_tree_list->tree;
        tmp_tree_list = new_tree_list->next;
        (*ctx)->epoch = MAX(epoch, (*ctx)->epoch);
        while(tmp_tree_list != NULL){
          (*ctx)->root = tgdh_merge((*ctx)->root, tmp_tree_list->tree);
          tmp_tree_list = tmp_tree_list->next;
        }
        
        break;
      }
      /********************/
      /*                  */
      /* MEMBERSHIP EVENT */
      /*                  */
      /********************/
      case PROCESS_EVENT:
      {
        if(epoch != (*ctx)->epoch){
          fprintf(stderr, "\nReceived: %d, Mine: %d\n", epoch,
                  (*ctx)->epoch); 
          result = UNSYNC_EPOCH;
          goto error;
        }
    
        /* This includes second call of partition, update_ctx of */
        /* join and merge operation                              */
        if(((*ctx)->status == KEY_COMPUTED) && sender &&
           (new_status == KEY_COMPUTED)){  
          (*ctx)->status = OK;
          ret = OK;
          goto error;
        }
        
        if(new_status == KEY_COMPUTED){ 
          (*ctx)->status = OK; 
          ret = OK;
          new_information = 1;
        }
    
        tgdh_init_bfs((*ctx)->root);
        num_sponsor = find_sponsors((*ctx)->root, sponsor_list);
        tgdh_init_bfs((*ctx)->root);
        i=0;
        if(sponsor_list[0] == NULL){
          fprintf(stderr, "No sponsor? Strange!!!\n");
          goto error;
        }
        
        while(sponsor_list[i] != NULL){
          if(strcmp(sponsor_list[i]->tgdh_nv->member->member_name,
                    (*ctx)->member_name)== 0){
            new_information = 1;
            new_key_comp = 1;
            sponsor = 1;
          }
          i++;
        }

        if(new_information == 0){
          goto error;
        }
        break;
      }

      /* No more cases */
      default:
      {
        result=INVALID_MESSAGE_TYPE;
        goto error;
      }
    }
  }
  
  tmp1_node = tgdh_search_member((*ctx)->root, 4, (*ctx)->member_name);
  if(tmp1_node == NULL){
    fprintf(stderr, "I cannot find me 222\n");
    result = STRUCTURE_ERROR;
    goto error;
  }

  tgdh_init_bfs((*ctx)->root);
  num_sponsor = find_sponsors((*ctx)->root, sponsor_list);
  tgdh_init_bfs((*ctx)->root);
  i=0;
  if(sponsor_list[0] == NULL){
    fprintf(stderr, "No sponsor? Strange!!!\n");
    goto error;
  }
  
  while(sponsor_list[i] != NULL){
    if(strcmp(sponsor_list[i]->tgdh_nv->member->member_name,
              (*ctx)->member_name)== 0){
      new_information = 1;
      new_key_comp = 1;
      sponsor = 1;
    }
    i++;
  }

  /* tgdh_print_simple("Bef comput", (*ctx)->root); */
  /* If not needed, only sponsor computes the key... */
  if(new_information || new_status == KEY_COMPUTED){
    tmp1_node = tgdh_search_member((*ctx)->root, 4, (*ctx)->member_name);
    if(tmp1_node == NULL){
      fprintf(stderr, "I cannot find me 3\n");
      result = STRUCTURE_ERROR;
      goto error;
    }
    if(tmp1_node != (*ctx)->root){
      while(tmp1_node->parent != NULL){
        if(tmp1_node->parent->tgdh_nv->key == NULL){
          break;
        }
        tmp1_node = tmp1_node->parent;
      }
    }

    if(tmp1_node != (*ctx)->root){
      if(tmp1_node->parent->tgdh_nv->key != NULL){
        fprintf(stderr, "PArent not null 2\n");
        result = STRUCTURE_ERROR;
        goto error;
      }
      if(tmp1_node->tgdh_nv->index % 2){
        tmp_node = tmp1_node->parent->left;
      }
      else{
        tmp_node = tmp1_node->parent->right;
      }
      while(tmp_node->tgdh_nv->bkey != NULL){
        /* Compute intermediate keys until I can */
        if(tmp1_node->parent->tgdh_nv->key != NULL){
          fprintf(stderr, "PArent not null 2\n");
          result=STRUCTURE_ERROR;
          goto error;
        }
        tmp1_node->parent->tgdh_nv->key = BN_new();
        new_key_comp = 1;
        if(tmp1_node->parent->left->tgdh_nv->key != NULL){
           result = BN_mod(tmp1_node->parent->left->tgdh_nv->key, 
                           tmp1_node->parent->left->tgdh_nv->key, 
                           DSA_get0_q((*ctx)->params), bn_ctx); 
          if(result != OK) goto error;
          result=BN_mod_exp(tmp1_node->parent->tgdh_nv->key, 
                            tmp1_node->parent->right->tgdh_nv->bkey,
                            tmp1_node->parent->left->tgdh_nv->key,
                            DSA_get0_p((*ctx)->params),bn_ctx);
        }
        else{
          result = BN_mod(tmp1_node->parent->right->tgdh_nv->key,
                          tmp1_node->parent->right->tgdh_nv->key,
                          DSA_get0_q((*ctx)->params), bn_ctx);
          if(result != OK) goto error;
          result=BN_mod_exp(tmp1_node->parent->tgdh_nv->key,
                            tmp1_node->parent->left->tgdh_nv->bkey,
                            tmp1_node->parent->right->tgdh_nv->key,
                            DSA_get0_p((*ctx)->params),bn_ctx);
        }
        if(result != OK) goto error;
        
        /* Compute bkeys */
        if(tmp1_node->parent->tgdh_nv->bkey != NULL){
          BN_clear_free(tmp1_node->parent->tgdh_nv->bkey);
          tmp1_node->parent->tgdh_nv->bkey=NULL;
        }
        tmp1_node->parent->tgdh_nv->bkey
          =tgdh_compute_bkey(tmp1_node->parent->tgdh_nv->key, (*ctx)->params);
        
        if(tmp1_node->parent->parent == NULL) {
          break;
        }
        else{
          tmp1_node = tmp1_node->parent;
        }
        if(tmp1_node->tgdh_nv->index % 2){
          tmp_node = tmp1_node->parent->left;
        }
        else{
          tmp_node = tmp1_node->parent->right;
        }
      }
    }
  }
  /* tgdh_print_simple("Aft comput", (*ctx)->root); */
  
  
  
  if((*ctx)->root->tgdh_nv->key != NULL){
    if((*ctx)->status == CONTINUE){
      ret = KEY_COMPUTED;
      (*ctx)->status = KEY_COMPUTED;
    }
    if((*ctx)->root->tgdh_nv->member != NULL){
      if(strcmp((*ctx)->root->tgdh_nv->member->member_name,
                (*ctx)->member_name)==0){
        ret = OK;
        (*ctx)->status = OK;
      }
    }
  }

  if((new_information == 1) && (new_key_comp == 1) && ((*ctx)->status != OK)){
    /* Creating token info */
    result=tgdh_create_token_info(&info, (*ctx)->group_name,
                                  PROCESS_EVENT, time(0),
                                  (*ctx)->member_name);  
    if (result!=OK) goto error;
    
    result=tgdh_encode((*ctx),output,info);
    if (result!=OK) goto error;

    /* Sign output token; */
    result=tgdh_sign_message ((*ctx), *output);
  }

error:
  if(new_tree_list != NULL){
    remove_tree_list(&new_tree_list);
  }

  if(ret == OK){
    if((*ctx)->root->tgdh_nv->key == NULL){
      fprintf(stderr, "Key is NULL, but return is OK\n\n");
    }
    BN_copy((*ctx)->group_secret,(*ctx)->root->tgdh_nv->key);
    result=tgdh_compute_secret_hash ((*ctx));
    (*ctx)->epoch++; /* Used inside tgdh_encode */
  }
        
  if (result <= 0){
    ret = result;
    if (ctx != NULL) tgdh_destroy_ctx(ctx,1);
  }
  if (info != NULL) tgdh_destroy_token_info(&info);
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);
  

  return ret;
}

/* tgdh_create_ctx creates the tgdh context.
 * Preconditions: *ctx has to be NULL.
 */
int tgdh_create_ctx(TGDH_CONTEXT **ctx) 
{
  int ret=CTX_ERROR;

  if (*ctx != (TGDH_CONTEXT *)NULL) return CTX_ERROR;
  /* Creating ctx */
  (*ctx) = (TGDH_CONTEXT *) calloc(sizeof(TGDH_CONTEXT), 1);
  if ((*ctx) == NULL) goto error;
  (*ctx)->member_name=NULL;
  (*ctx)->group_name=NULL;
  (*ctx)->root=(KEY_TREE *) calloc(sizeof(KEY_TREE),1);
  if ((*ctx)->root == (KEY_TREE *) NULL) goto error;
  (*ctx)->group_secret_hash=(clq_uchar*) calloc (MD5_DIGEST_LENGTH,1);
  if ((*ctx)->group_secret_hash==NULL){
    goto error;
  }
  
  (*ctx)->root->parent=(*ctx)->root->left=(*ctx)->root->right=NULL;
  (*ctx)->root->prev=(*ctx)->root->next=(*ctx)->root->bfs=NULL;
  (*ctx)->params=NULL; 
  (*ctx)->pkey=NULL;
  (*ctx)->epoch=0;
  
  ret=OK;
error:
  if (ret!=OK) tgdh_destroy_ctx (ctx,1);
  
  return ret;
}

/* tgdh_compute_bkey: Computes and returns bkey */
BIGNUM *tgdh_compute_bkey (BIGNUM *key, DSA *params)
{
  int ret=OK;
  BIGNUM *new_bkey = BN_new();
  BN_CTX *bn_ctx=BN_CTX_new();  
  
  if (bn_ctx == (BN_CTX *) NULL) {ret=MALLOC_ERROR; goto error;}
  if (new_bkey == NULL) {ret=MALLOC_ERROR; goto error;}
  if (key == NULL) {ret=STRUCTURE_ERROR; goto error;}
  
  ret = BN_mod(key,key,DSA_get0_q(params),bn_ctx);
  if(ret != OK) goto error;
  ret=BN_mod_exp(new_bkey,DSA_get0_g(params),key,DSA_get0_p(params),bn_ctx); 
  
error:
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);
  if (ret!=OK) 
    if (new_bkey != NULL) {
      BN_clear_free(new_bkey);
      new_bkey=NULL;
    }
  
  return new_bkey;
}

/* tgdh_rand: Generates a new random number of "params->q" bits, using
 *   the default parameters.
 * Returns: A pointer to a dsa structure where the random value
 *          resides. 
 *          NULL if an error occurs.
 */
BIGNUM *tgdh_rand (DSA *params) 
{
  /* DSA *Random=NULL; */
  int ret=OK;
  BIGNUM *random=NULL;
  int i=0;
  
  random=BN_new();
  if (random == NULL) { ret=MALLOC_ERROR; goto error;}
  
  /* The following idea was obtained from dsa_key.c (openssl) */
  i=BN_num_bits(DSA_get0_q(params));
  for (;;) {
    ret = BN_rand(random,i,1,0);
    if (BN_cmp(random,DSA_get0_q(params)) >= 0)
      BN_sub(random,random,DSA_get0_q(params));
    if (!BN_is_zero(random)) break;
  }
  
error:
  
  if (ret!=OK) 
    if (random != NULL) {
      BN_clear_free(random);
      random=NULL;
    }

  return random;
}

/* tgdh_compute_secret_hash: It computes the hash of the group_secret.
 * Preconditions: ctx->group_secret has to be valid.
 */
int tgdh_compute_secret_hash (TGDH_CONTEXT *ctx) 
{
  char *tmp_str=NULL;
  
  tmp_str=BN_bn2hex(ctx->group_secret);
  if (tmp_str==NULL) return CTX_ERROR;
  
  MD5((clq_uchar *)tmp_str, (unsigned long)strlen(tmp_str), 
      ctx->group_secret_hash);
  
  OPENSSL_free(tmp_str); // free(tmp_str);
  
  if (ctx->group_secret_hash == (clq_uchar *) NULL) return CTX_ERROR; 
  
  return OK;
}

/* tgdh_destroy_ctx frees the space occupied by the current context.
 * Including the group_members_list.
 *   if flag == 1, delete all context
 *   if flag == 0, delete all except the tree(used for merge)
 */

void tgdh_destroy_ctx (TGDH_CONTEXT **ctx, int flag) 
{
  
  if ((*ctx) == NULL) return;
  if (((*ctx)->member_name) != NULL) { 
    free((*ctx)->member_name);
    (*ctx)->member_name=NULL;
  }
  if (((*ctx)->group_name) != NULL) { 
    free((*ctx)->group_name);
    (*ctx)->group_name=NULL;
  }
  if (((*ctx)->group_secret) != NULL) {
    BN_clear_free((*ctx)->group_secret);
    (*ctx)->group_secret=NULL;
  }
  if (((*ctx)->tmp_key) != NULL) {
    BN_clear_free((*ctx)->tmp_key);
    (*ctx)->tmp_key=NULL;
  }
  if (((*ctx)->tmp_bkey) != NULL) {
    BN_clear_free((*ctx)->tmp_bkey);
    (*ctx)->tmp_bkey=NULL;
  }
  if (((*ctx)->group_secret_hash) != NULL) {
    free((*ctx)->group_secret_hash);
    (*ctx)->group_secret_hash=NULL;
  }

  if(flag == 1){
    tgdh_free_tree(&((*ctx)->root));
    (*ctx)->root=NULL;
  }
  
  if (((*ctx)->params) != NULL) {
    DSA_free((*ctx)->params);
    (*ctx)->params=NULL;
  }
  if (((*ctx)->pkey) != NULL) {
    EVP_PKEY_free((*ctx)->pkey);
    (*ctx)->pkey=NULL;
  }
  if (((*ctx)->epoch) != (int)NULL) {
    (*ctx)->epoch = (int)NULL;
  }
  free((*ctx));
  (*ctx)=NULL;
  
  return;
}

/***********************/
/*TREE private functions*/
/***********************/

/* tgdh_encode using information from the current context and from
 * token info generates the output token.
 * include_last_partial: If TRUE includes all last_partial_keys,
 * otherwise it includes the partial key of the (controller) first
 * user in ckd. Hence it should be TRUE if called within cliques and
 * FALSE if called from ckd_gnrt_gml.
 *
 * Note: output is created here.
 * Preconditions: *output should be empty (otherwise it will be
 * freed).  
 */
int tgdh_encode(TGDH_CONTEXT *ctx, CLQ_TOKEN **output,
		TGDH_TOKEN_INFO *info) 
{ 
  uint pos=0;
  clq_uchar *data;
  
  /* Freeing the output token if necessary */
  if((*output) != NULL) tgdh_destroy_token(output);
  
  /* Do some error checkings HERE !! */
  if (ctx == (TGDH_CONTEXT *) NULL) return CTX_ERROR;
  /* The token has to match the current group name */
  if (strcmp(info->group_name,ctx->group_name)) return GROUP_NAME_MISMATCH;
  /* Done with error checkings */
  
  data=(clq_uchar *) calloc (sizeof(clq_uchar)*MSG_SIZE,1);
  if (data==(clq_uchar *) NULL) return MALLOC_ERROR;
  
  string_encode(data,&pos,info->group_name);
  int_encode(data,&pos,info->message_type);
  int_encode(data,&pos,info->time_stamp);
  /* Note: info->sender_name is not used here. The name is retreived
   * from ctx.
   */
  string_encode(data,&pos,ctx->member_name);
  int_encode(data,&pos,ctx->epoch);
  int_encode(data,&pos,ctx->status);
  
  tgdh_map_encode(data, &pos, ctx->root);
  
  *output=(CLQ_TOKEN *) calloc(sizeof(CLQ_TOKEN),1);
  if (*output == (CLQ_TOKEN *) NULL) return MALLOC_ERROR;
  (*output)->length=pos;
  (*output)->t_data=data;
  
  return OK;
}

/* Converts tree structure to unsigned character string */
void tgdh_map_encode(clq_uchar *stream, uint *pos, KEY_TREE *root)
{
  KEY_TREE *head, *tail;
  int map = 0;        /* If map is 3, index, bkey, member_name
                       * If map is 2, index, member_name
                       * If map is 1, index, bkey
                       * If map is 0, only index
                       */

  tgdh_init_bfs(root);
  
  int_encode(stream, pos, (uint)root->tgdh_nv->height);
  int_encode(stream, pos, root->tgdh_nv->num_node);
  head = tail = root;
  
  while(head != NULL){
    if(head->tgdh_nv->member == NULL){
      if(head->tgdh_nv->bkey == NULL){
        map = 0;
      }
      else map = 1;
    }
    else{
      if(head->tgdh_nv->bkey == NULL){
        map = 2;
      }
      else map = 3;
    }
    
    /* Real encoding */
    int_encode(stream, pos, map);
    int_encode(stream, pos, head->tgdh_nv->index);
    int_encode(stream, pos, (uint)head->tgdh_nv->potential);
    int_encode(stream, pos, head->tgdh_nv->joinQ);
    if(head->tgdh_nv->bkey != NULL) 
      bn_encode(stream, pos, head->tgdh_nv->bkey);
    if(head->tgdh_nv->member != NULL) 
      string_encode(stream, pos, head->tgdh_nv->member->member_name);
    
    /* Queue handling */
    if(head->left){
      tail->bfs = head->left;
      tail = tail->bfs;
    }
    if(head->right){
      tail->bfs = head->right;
      tail = tail->bfs;
    }
    head = head->bfs;
  }
  
  tgdh_init_bfs(root);
}

/* tgdh_decode using information from the input token, it creates
 * ctx. info is also created here. It contains data recovered from
 * input such as message_type, sender, etc. (See structure for more
 * details) in readable format. 
 * Preconditions: *ctx has to be NULL.
 * Postconditions: ctx is created. The only valid data in it is
 * group_members_list (first & last), and epoch. All the other
 * variables are NULL. (tgdh_create_ctx behavior)
 */
int tgdh_decode(TGDH_CONTEXT **ctx, CLQ_TOKEN *input,
                TGDH_TOKEN_INFO **info)
{
  uint pos=0;
  int ret=CTX_ERROR;
  
  if (input == NULL){
        printf("This is weird 3\n\n");
        
    return INVALID_INPUT_TOKEN;
  }
  if (input->t_data == NULL){
        printf("This is weird 4\n\n");
        
    return INVALID_INPUT_TOKEN;
  }
  if (input->length <= 0){
        printf("This is weird 5\n\n");
        
    return INVALID_INPUT_TOKEN;
  }
  
  /* Creating token info */
  ret=tgdh_create_token_info(info,"",TGDH_INVALID,0L,"");
  if (ret!=OK) goto error;
  
  if (ret!=tgdh_create_ctx(ctx)) goto error;
  
  ret=INVALID_INPUT_TOKEN;
  if (!string_decode(input,&pos,(*info)->group_name)) 
    goto error;
  if (!int_decode(input,&pos,(uint*)&(*info)->message_type)) 
    goto error;
  if (!int_decode(input,&pos,(uint *)&(*info)->time_stamp)) 
    goto error;
  if (!string_decode(input,&pos,(*info)->sender_name)) 
    goto error;
  /*  (*ctx)->member_name = (CLQ_NAME *)malloc(sizeof(CLQ_NAME)*MAX_LGT_NAME);
  strncpy((*ctx)->member_name, (*info)->sender_name, MAX_LGT_NAME);
  */
  if (!int_decode(input,&pos,&(*ctx)->epoch)) 
    goto error;
  if (!int_decode(input,&pos,&(*ctx)->status)) 
    goto error;
  
  if ((ret=tgdh_map_decode(input,&pos,ctx)) != OK)
    goto error; 
  
  /* Checking after decoding */
  if ((((*info)->sender_name) == NULL) ||
      (((*info)->group_name) == NULL) ||
      ((*ctx)->epoch < 0)){
        printf("This is weird 6\n\n");
        
    ret=INVALID_INPUT_TOKEN;
  }
  
  else
    ret=OK;
  
error:
  
  if (ret != OK) {
        printf("This is weird 7\n\n");
        
    if (info != NULL) tgdh_destroy_token_info(info);
    if (ctx != NULL) tgdh_destroy_ctx(ctx,1);
  }
  
  return ret;
}

/* tgdh_map_decode decode input token to generate tree for the new
 *   tree
 * *tree should be pointer to the root node
 */
int tgdh_map_decode(const CLQ_TOKEN *input, uint *pos, 
                    TGDH_CONTEXT **ctx)
{
  int i;
  uint map=0;
  uint tmp_index;
  KEY_TREE *tmp_tree=NULL, *tmp1_tree=NULL;
  int ret=OK;
  
  (*ctx)->root->tgdh_nv = (TGDH_NV *)calloc(sizeof(TGDH_NV),1);
  if ((*ctx)->root->tgdh_nv == NULL) 
  {ret=MALLOC_ERROR; goto error;}
  if(!int_decode(input, pos, (uint *)&((*ctx)->root->tgdh_nv->height))) 
    return 0;
  if(!int_decode(input, pos, (uint *)&((*ctx)->root->tgdh_nv->num_node))) 
    return 0;
  
  (*ctx)->root->parent = NULL;
  (*ctx)->root->tgdh_nv->member = NULL;
  
  if(!int_decode(input, pos, &map)) return 0;
  if(!int_decode(input, pos, &tmp_index)) return 0;
  
  (*ctx)->root->tgdh_nv->index = tmp_index;
  if(!int_decode(input, pos, (uint *)&((*ctx)->root->tgdh_nv->potential))) 
    return 0;
  if(!int_decode(input, pos, &((*ctx)->root->tgdh_nv->joinQ))) 
    return 0;
  
  (*ctx)->root->tgdh_nv->key = (*ctx)->root->tgdh_nv->bkey = NULL;
  if(map & 0x1){      /* If map is 3, index, bkey, member_name
                       * If map is 2, index, member_name
                       * If map is 1, index, bkey
                       * If map is 0, only index
                       */
    (*ctx)->root->tgdh_nv->bkey = BN_new();
    if(!bn_decode(input, pos, (*ctx)->root->tgdh_nv->bkey)) return 0;
  }
  if((map >> 1) & 0x1){
    (*ctx)->root->tgdh_nv->member 
      = (TGDH_GM *)calloc(sizeof(TGDH_GM),1);
    if((*ctx)->root->tgdh_nv->member == NULL)
    {ret=MALLOC_ERROR; goto error;}
    
    (*ctx)->root->tgdh_nv->member->cert = NULL;
    (*ctx)->root->tgdh_nv->member->member_name = 
      (CLQ_NAME *)calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
    if((*ctx)->root->tgdh_nv->member->member_name == NULL)
    {ret=MALLOC_ERROR; goto error;}
    if(!string_decode(input, pos,
                      (*ctx)->root->tgdh_nv->member->member_name))
      return 0; 
  }
  
  for(i=0; i<(*ctx)->root->tgdh_nv->num_node-1; i++){
    if(!int_decode(input, pos, &map)) return 0;
    if(!int_decode(input, pos, &tmp_index)) return 0;
    tmp_tree=tgdh_search_index((*ctx)->root, tmp_index);
    if(tmp_tree == NULL) return 0;
    tmp_tree->tgdh_nv->member = NULL;
    tmp1_tree = (KEY_TREE *)calloc(sizeof(KEY_TREE),1);
    
    tmp1_tree->parent = tmp_tree;
    if(tmp_index % 2)
      tmp_tree->right = tmp1_tree;
    else tmp_tree->left = tmp1_tree;
    tmp1_tree->tgdh_nv = (TGDH_NV *)calloc(sizeof(TGDH_NV),1);
    tmp1_tree->tgdh_nv->member = NULL;
    tmp1_tree->tgdh_nv->key = tmp1_tree->tgdh_nv->bkey = NULL;
    tmp1_tree->tgdh_nv->index = tmp_index;
    tmp1_tree->tgdh_nv->height = tmp1_tree->tgdh_nv->num_node=-1;
    tmp1_tree->left=tmp1_tree->right=NULL;
    tmp1_tree->prev=tmp1_tree->next=tmp1_tree->bfs=NULL;
    if(!int_decode(input, pos, (uint *)&(tmp1_tree->tgdh_nv->potential))) 
      return 0;
    if(!int_decode(input, pos, &(tmp1_tree->tgdh_nv->joinQ))) 
      return 0;
    if(map & 0x1){
      tmp1_tree->tgdh_nv->bkey = BN_new();
      if(!bn_decode(input, pos, tmp1_tree->tgdh_nv->bkey)) return 0;
    }
    if((map >> 1) & 0x1){
      tmp1_tree->tgdh_nv->member=(TGDH_GM *)calloc(sizeof(TGDH_GM),1);
      tmp1_tree->tgdh_nv->member->member_name = 
        (CLQ_NAME *)calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1); 
      tmp1_tree->tgdh_nv->member->cert=NULL;
      
      if(!string_decode(input, pos, tmp1_tree->tgdh_nv->member->member_name))
        return 0; 
      tmp_tree = tgdh_search_member(tmp1_tree, 0, NULL);
      tmp1_tree->prev = tmp_tree;
      if(tmp_tree != NULL) tmp_tree->next = tmp1_tree;
      tmp_tree = tgdh_search_member(tmp1_tree, 1, NULL);
      tmp1_tree->next = tmp_tree;
      if(tmp_tree != NULL) tmp_tree->prev = tmp1_tree;
      tmp1_tree->bfs = NULL;
    }
  }
  
  error:
  if(ret != OK){
    if((*ctx)->root->tgdh_nv->member != NULL){
      if((*ctx)->root->tgdh_nv->member->member_name != NULL) 
        free((*ctx)->root->tgdh_nv->member->member_name);
      free((*ctx)->root->tgdh_nv->member);
    }
    if((*ctx)->root->tgdh_nv != NULL) free((*ctx)->root->tgdh_nv);
  }
  
  return ret;
}

/* tgdh_create_token_info: It creates the info token. */
int tgdh_create_token_info (TGDH_TOKEN_INFO **info, CLQ_NAME *group, 
                            enum TGDH_MSG_TYPE msg_type, time_t time,
                            CLQ_NAME *sender/*, uint epoch*/) 
{ 
  int ret=MALLOC_ERROR;
  
  /* Creating token information */
  (*info)=(TGDH_TOKEN_INFO *) calloc (sizeof(TGDH_TOKEN_INFO),1);
  if ((*info) == NULL) goto error;
  if (group != NULL) {
    (*info)->group_name
      =(CLQ_NAME *) calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
    if (((*info)->group_name) == NULL) goto error;
    strncpy ((*info)->group_name,group,MAX_LGT_NAME);
  } else (*info)->group_name=NULL;
  (*info)->message_type=msg_type;
  (*info)->time_stamp=time;
  if (sender != NULL) {
    (*info)->sender_name=(CLQ_NAME *)
      calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
    if (((*info)->sender_name) == NULL) goto error;
    strncpy ((*info)->sender_name,sender,MAX_LGT_NAME);
  }
  else (*info)->sender_name=NULL;
  /*  (*info)->epoch=epoch; */
  
  ret=OK;
error:
  if (ret != OK) tgdh_destroy_token_info(info);

  return ret;
}

/* tgdh_destroy_token: It frees the memory of the token. */
void tgdh_destroy_token (CLQ_TOKEN **token) {
  if (*token !=(CLQ_TOKEN *) NULL) {
    if ((*token)->t_data != NULL) {
      free ((*token)->t_data);
      (*token)->t_data=NULL;
    }
    free(*token);
    *token=NULL;
  }
}

/* tgdh_destroy_token_info: It frees the memory of the token. */
void tgdh_destroy_token_info (TGDH_TOKEN_INFO **info) 
{
  
  if (info == NULL) return;
  if ((*info) == NULL) return;
  if ((*info)->group_name != NULL) {
    free ((*info)->group_name);
    (*info)->group_name =NULL;
  }
  if ((*info)->sender_name != NULL) {
    free ((*info)->sender_name);
    (*info)->sender_name=NULL;
  }
  free ((*info));
  *info = NULL;
  
}

/* tgdh_merge_tree returns root of a new tree which is the result of
 *   merge of two trees
 */
KEY_TREE *tgdh_merge_tree(KEY_TREE *joiner, KEY_TREE *joinee)
{
  KEY_TREE *tmp_tree=NULL, *tmp_root=NULL;
  KEY_TREE *last=NULL, *last1=NULL, *first=NULL;
  int height=-1;
  
  if(joiner->parent != NULL) return NULL;
  
  tmp_tree = (KEY_TREE *)calloc(sizeof(KEY_TREE),1);
  if(tmp_tree == NULL) return NULL;
  
  /* setting up pointers for the new node */
  tmp_tree->parent = joinee->parent;
  tmp_tree->left = joinee;
  tmp_tree->right = joiner;
  tmp_tree->prev=tmp_tree->next=tmp_tree->bfs=NULL;
  
  /* setting up pointer for the parent of the joinee */
  if(joinee->parent != NULL){
    if(joinee->tgdh_nv->index % 2)
      joinee->parent->right = tmp_tree;
    else joinee->parent->left = tmp_tree;
  }
  
  /* setting up pointers for the joinee and joiner */
  joiner->parent = tmp_tree;
  joinee->parent = tmp_tree;
  
  /* setting up the pointers for the leaf nodes */
  last = tgdh_search_member(joinee, 3, NULL);
  first = tgdh_search_member(joiner, 2, NULL);
  last1 = tgdh_search_member(joiner, 3, NULL);
  if(last->next != NULL){
    last1->next = last->next;
    last->next->prev = last1;
  }
  last->next = first;
  first->prev = last;
  
  /* Now, real values for the tmp_tree */
  tmp_tree->tgdh_nv=(TGDH_NV *)calloc(sizeof(TGDH_NV),1);
  tmp_tree->tgdh_nv->index = tmp_tree->left->tgdh_nv->index;
  tmp_tree->tgdh_nv->key = tmp_tree->tgdh_nv->bkey = NULL; 
  
  /* I decide to change everything -_-''
   * It looks simple, but inefficient...
   * But correct in every cases
   */
  /* Firstly, I'm just updating index... And then I'll update
   * potential using brute-force way
   */
  tgdh_update_index(tmp_tree->right, 1, tmp_tree->tgdh_nv->index);  
  tgdh_update_index(tmp_tree->left, 0, tmp_tree->tgdh_nv->index);

  tmp_tree->tgdh_nv->member = NULL;

  /* Potential will be updated here */
  tmp_root = tmp_tree;
  while(tmp_root->parent != NULL)
    tmp_root = tmp_root->parent;
  
  first = tgdh_search_member(tmp_root, 2, NULL);
  while(first != NULL){
    height = MAX(height, clq_log2(first->tgdh_nv->index));
    first = first->next;
  }
  
  tmp_root->tgdh_nv->height = height; /* update height */
  first = tgdh_search_member(tmp_root, 2, NULL);
  while(first != NULL){ /* Update potential for leaf users */
    first->tgdh_nv->potential
      = height - clq_log2(first->tgdh_nv->index) - 1;
    if(first->tgdh_nv->potential == -1)
      first->tgdh_nv->joinQ = FALSE;
    else first->tgdh_nv->joinQ = TRUE;
    first = first ->next;
  }
  tgdh_update_potential(tmp_root);
  
  /* Now update some values upto the root */
  tgdh_update_key_path(&tmp_root);

  last=last1=first=NULL;
  
  return tmp_root;
}


/* tgdh_search_member: returns the pointer of the previous or the next
 *   member or the first or the last member
 *   if option is 0, this will return the pointer to the previous member
 *   if option is 1, this will return the pointer to the next member
 *     in the above two cases, tree is the starting leaf node in this
 *     searching 
 *   if option is 2, this will return the pointer to the left-most
 *      leaf member 
 *   if option is 3, this will return the pointer to the right-most
 *      leaf member 
 *   if option is 4 and member_name is not null, this will return the
 *     pointer to the node with that name
 *   if option is 5, this will return the pointer to the root
 *   if option is 6, this will return the shallowest leaf node
 */
KEY_TREE *tgdh_search_member(KEY_TREE *tree, int option, 
                             CLQ_NAME *member_name )
{
  KEY_TREE *tmp_tree, *tmp_tree1=NULL, *the_tree=NULL;
  int min_node=100000;
  
  tmp_tree = tree;
  
  if(member_name == NULL){
    switch (option) {
      case 0: 
        if(tree->tgdh_nv->member == NULL) return NULL;
        if(tree->tgdh_nv->member->member_name == NULL) return NULL;
        if(tmp_tree->parent == NULL) return NULL;
        if(tmp_tree->parent->left == NULL) return NULL;
        while(tmp_tree->parent->left == tmp_tree){
          tmp_tree = tmp_tree->parent;
          if(tmp_tree->parent == NULL) return NULL;
        }
        /* find the previous member */
        tmp_tree = tmp_tree->parent->left;
        while(tmp_tree->tgdh_nv->member == NULL){
          if(tmp_tree->right == NULL) return NULL;
          tmp_tree = tmp_tree->right; 
        }
        if(tmp_tree->tgdh_nv->member->member_name == NULL) return NULL;
        return tmp_tree;
      case 1:
        if(tree->tgdh_nv->member == NULL) return NULL;
        if(tree->tgdh_nv->member->member_name == NULL) return NULL;
        if(tmp_tree->parent == NULL) return NULL;
        if(tmp_tree->parent->right == NULL) return NULL;
        while(tmp_tree->parent->right == tmp_tree){
          tmp_tree = tmp_tree->parent;
          if(tmp_tree->parent == NULL) return NULL;
        }
        /* find the next member */
        tmp_tree = tmp_tree->parent->right;
        while(tmp_tree->tgdh_nv->member == NULL){
          if(tmp_tree->left == NULL) return NULL;
          tmp_tree = tmp_tree->left;
        }
        if(tmp_tree->tgdh_nv->member->member_name == NULL) return NULL;
        return tmp_tree;
      case 2:
        if(tmp_tree->left == NULL) return tmp_tree;
        while(tmp_tree->left != NULL) tmp_tree=tmp_tree->left;
        return tmp_tree;
      case 3:
        if(tmp_tree->right == NULL) return tmp_tree;
        while(tmp_tree->right != NULL) tmp_tree=tmp_tree->right;
        return tmp_tree;
      case 5:
        if(tmp_tree->parent == NULL) return tmp_tree;
        while(tmp_tree->parent != NULL) tmp_tree=tmp_tree->parent;
        return tmp_tree;
      case 6:
        tmp_tree1 = tgdh_search_member(tmp_tree, 3, NULL);
        tmp_tree = tgdh_search_member(tmp_tree, 2, NULL);
        while(tmp_tree != NULL){
          /* the minimum index is the shallowest node */
          if(tmp_tree->tgdh_nv->index < min_node){
            min_node = tmp_tree->tgdh_nv->index;
            the_tree = tmp_tree;
          }
          if(tmp_tree == tmp_tree1){
            break;
          }
          tmp_tree = tmp_tree->next;
        }
        return the_tree;
      default:
        return NULL;
    }
  }
  else{
    if(option==4){
      tmp_tree = tgdh_search_member(tree, 2, NULL);
      if(tmp_tree == NULL) return NULL;
      
      while(strcmp(tmp_tree->tgdh_nv->member->member_name,
                   member_name)!=0 ){
        if(tmp_tree->next == NULL) return NULL;
        tmp_tree = tmp_tree->next;
      }
      return tmp_tree;
    }
  }
  return NULL;
}

/* tgdh_search_node: Returns the first fit or worst fit node
 *   if option is 0, search policy is the first fit
 *   if option is 1, search policy is the best fit
 * height of the joiner should be always smaller or equal to that of
 *   the joinee
 */
KEY_TREE *tgdh_search_node(KEY_TREE *joiner, KEY_TREE *joinee,
			   int option)
{
  KEY_TREE *tmp_tree;
  
  if(joiner->tgdh_nv->height > joinee->tgdh_nv->potential) return joinee;
  
  tmp_tree = joinee;
  
  if(option==0){
    while(tmp_tree->tgdh_nv->joinQ == FALSE){
      if(tmp_tree->right->tgdh_nv->potential >= 
         tmp_tree->left->tgdh_nv->potential){
        tmp_tree = tmp_tree->right;
      }
      else tmp_tree = tmp_tree->left;
    }
    return tmp_tree;
  }
  return NULL;
}

/* tgdh_search_index: Returns the node having the index as a child 
 *   index should be greater than 1
 */
KEY_TREE *tgdh_search_index(KEY_TREE *tree, int index)
{
  int height=0;
  int i;
  KEY_TREE *tmp_tree;
  
  height = clq_log2(index);
  
  tmp_tree = tree;
  
  if(index==1) return NULL;
  
  for(i=1; i<height; i++){
    if((index >> (height-i)) & 0x1){
      if(tmp_tree->right == NULL) return NULL;
      else tmp_tree = tmp_tree->right;
    }
    else{
      if(tmp_tree->left == NULL) return NULL;
      else tmp_tree = tmp_tree->left;
    }
  }
  
  return tmp_tree;
}

/* tgdh_update_index: update index of the input tree by 1
 * index 0 is for the left node
 * index 1 is for the right node
 * if option is -1, potential and joinQ need not be recomputed
 * if option is >=0, potential and joinQ should be recomputed
 * if option is > 0, the value means potential for the left sibling
 * height is only meaningful, when right tree need to be modified
 */
void tgdh_update_index(KEY_TREE *tree, int index, int root_index) 
{
  if(tree == NULL) return;
  
  tree->tgdh_nv->index = root_index * 2 + index;

  tgdh_update_index(tree->left, 0, tree->tgdh_nv->index);
  tgdh_update_index(tree->right, 1, tree->tgdh_nv->index);
}

/* Updates potential and joinQ except the leaf node */
void tgdh_update_potential(KEY_TREE *tree)
{
  if(tree == NULL) return;
  
  tgdh_update_potential(tree->left);
  tgdh_update_potential(tree->right);
  
  if(tree->left != NULL){
    if((tree->left->tgdh_nv->joinQ == TRUE) && 
       (tree->right->tgdh_nv->joinQ == TRUE)){
      tree->tgdh_nv->potential = 
        tree->left->tgdh_nv->potential + 1;
      tree->tgdh_nv->joinQ = TRUE;
    }
    else{
      tree->tgdh_nv->potential = 
        MAX(tree->left->tgdh_nv->potential,
            tree->right->tgdh_nv->potential);
      tree->tgdh_nv->joinQ = FALSE;
    }
  }
}

/* tgdh_update_key_path: update joinQ, potential of key_path
 */
void tgdh_update_key_path(KEY_TREE **tree)
{
  if((*tree) != NULL){
    while((*tree)->parent != NULL){
      (*tree) = (*tree)->parent;
      if(((*tree)->left->tgdh_nv->joinQ == 0) ||
         ((*tree)->right->tgdh_nv->joinQ == 0))
        (*tree)->tgdh_nv->joinQ = FALSE;
      else (*tree)->tgdh_nv->joinQ = TRUE;
      (*tree)->tgdh_nv->potential = 
        MAX((*tree)->left->tgdh_nv->potential,
            (*tree)->right->tgdh_nv->potential);
      if(((*tree)->left->tgdh_nv->potential >= 0) && 
         ((*tree)->right->tgdh_nv->potential >= 0) &&
         ((*tree)->left->tgdh_nv->joinQ ==TRUE) &&
         ((*tree)->right->tgdh_nv->joinQ ==TRUE))
        (*tree)->tgdh_nv->potential++;
      if((*tree)->tgdh_nv->member != NULL)
        (*tree)->tgdh_nv->member = NULL;
    }
  }
}

/* leaderQ: true if I am the node(first or worst fit)
   false otherwise
   */
int leaderQ(KEY_TREE *tree, CLQ_NAME *my_name)
{
  KEY_TREE *tmp_tree;
  
  tmp_tree = tree;
  
  while(tmp_tree->right != NULL) tmp_tree = tmp_tree->right;
  if(strcmp(tmp_tree->tgdh_nv->member->member_name, my_name) == 0)
    return TRUE;
  else return FALSE;
}

/* Frees a TGDH_TREE structure */
void tgdh_free_tree(KEY_TREE **tree) {
  
  if(tree == NULL) return;
  if((*tree) == NULL) return;

  if((*tree)->left != NULL)
    tgdh_free_tree(&((*tree)->left));
  if((*tree)->right != NULL)
    tgdh_free_tree(&((*tree)->right));
  
  tgdh_free_node(&(*tree));
}

/* Frees a NODE structure */
void tgdh_free_node(KEY_TREE **tree) {

  if(tree == NULL) return;
  if((*tree) == NULL) return;
  
  if((*tree)->tgdh_nv != NULL){
    tgdh_free_nv(&((*tree)->tgdh_nv));
    (*tree)->tgdh_nv = NULL;
  }
  
  free((*tree));
  
  (*tree)=NULL;
}

/* Frees a TGDH_NV structure */
void tgdh_free_nv(TGDH_NV **nv) {
  if (nv == NULL) return;
  if ((*nv) == NULL) return;
  if((*nv)->member != NULL){
    tgdh_free_gm(&((*nv)->member));
    (*nv)->member=NULL;
  }
  
  if ((*nv)->key != NULL){
    BN_clear_free((*nv)->key);
  }
  
  if ((*nv)->bkey != NULL){
    BN_clear_free((*nv)->bkey);
  }
  
  free((*nv));
  (*nv)=NULL;
}

/* Frees a TGDH_GM structure */
void tgdh_free_gm(TGDH_GM **gm) {
  if((*gm) == NULL) return;
  if (((*gm)->member_name) != NULL) {
    free ((*gm)->member_name);
    (*gm)->member_name=NULL;
  }
  if (((*gm)->cert) != NULL) {
    X509_free ((*gm)->cert);
    (*gm)->cert=NULL;
  }
  free((*gm));
  (*gm)=NULL;
}

/* tgdh_copy tree structure, but to finish the real copy, we need to
   call tgdh_dup_tree, which finishes prev and next pointer */  
KEY_TREE *tgdh_copy_tree(KEY_TREE *src)
{
  KEY_TREE *dst=NULL;
  
  if(src != NULL){
    dst = (KEY_TREE *) calloc(sizeof(KEY_TREE), 1);
    if(src->tgdh_nv != NULL){
      dst->tgdh_nv = (TGDH_NV *) calloc(sizeof(TGDH_NV), 1);
      dst->tgdh_nv->index = src->tgdh_nv->index;
      dst->tgdh_nv->joinQ=src->tgdh_nv->joinQ;
      dst->tgdh_nv->potential=src->tgdh_nv->potential;
      dst->tgdh_nv->height=src->tgdh_nv->height;
      dst->tgdh_nv->num_node=src->tgdh_nv->num_node;
      if(src->tgdh_nv->key != NULL){
        dst->tgdh_nv->key = BN_dup(src->tgdh_nv->key);
      }
      if(src->tgdh_nv->bkey != NULL){
        dst->tgdh_nv->bkey = BN_dup(src->tgdh_nv->bkey);
      }
      if(src->tgdh_nv->member != NULL){
        dst->tgdh_nv->member = (TGDH_GM *) calloc(sizeof(TGDH_GM),1);
        if(src->tgdh_nv->member->member_name != NULL){
          dst->tgdh_nv->member->member_name=(CLQ_NAME *)
            calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
          strncpy (dst->tgdh_nv->member->member_name,
                   src->tgdh_nv->member->member_name,MAX_LGT_NAME);
        }
        if(src->tgdh_nv->member->cert != NULL){
          dst->tgdh_nv->member->cert = X509_dup(src->tgdh_nv->member->cert);
        }
      }
    }
    dst->left = tgdh_copy_tree(src->left);
    dst->right = tgdh_copy_tree(src->right);
    if(dst->left) {
      dst->left->parent = dst;
    }
    if(dst->right) {
      dst->right->parent = dst;
    }
  }

  return dst;
}

/* tgdh_dup_tree finishes the copy process of one tree to
   another... Mainly, it just handles prev and next pointer */
KEY_TREE *tgdh_dup_tree(KEY_TREE *src)
{
  KEY_TREE *dst=NULL;
  KEY_TREE *tmp1_src=NULL, *tmp1_dst=NULL;
  KEY_TREE *tmp2_src=NULL, *tmp2_dst=NULL;

  dst = tgdh_copy_tree(src);
  if(src != NULL){
    tmp1_src = tgdh_search_member(src, 2, NULL);
    tmp2_src = tmp1_src->next;
    tmp1_dst = tgdh_search_member(dst, 4,
                                  tmp1_src->tgdh_nv->member->member_name);
    while(tmp2_src != NULL){
      tmp2_dst = tgdh_search_member(tmp1_dst, 1, NULL);
      tmp1_dst->next = tmp2_dst;
      tmp2_dst->prev = tmp1_dst;
      tmp2_src = tmp2_src->next;
      tmp1_src = tmp1_src->next;
      tmp1_dst = tmp2_dst;
    }
  }

  return dst;
}


/* tgdh_copy_node copies or changes tgdh_nv values of src node to dst
   node */  
void tgdh_copy_node(KEY_TREE *src, KEY_TREE *dst)
{
  if(src->tgdh_nv != NULL){
    dst->tgdh_nv->index = src->tgdh_nv->index;
    dst->tgdh_nv->joinQ=src->tgdh_nv->joinQ;
    dst->tgdh_nv->potential=src->tgdh_nv->potential;
    dst->tgdh_nv->height=src->tgdh_nv->height;
    dst->tgdh_nv->num_node=src->tgdh_nv->num_node;
    if(src->tgdh_nv->key != NULL){
      clq_swap((void *)&(src->tgdh_nv->key),(void *)&(dst->tgdh_nv->key));
    }
    if(src->tgdh_nv->bkey != NULL){
      clq_swap((void *)&(src->tgdh_nv->bkey),(void *)&(dst->tgdh_nv->bkey));
    }
    if(src->tgdh_nv->member != NULL){
      clq_swap((void *)&(src->tgdh_nv->member), (void *)&(dst->tgdh_nv->member));
    }
  }
}

/* tgdh_swap_bkey swap my null bkey with meaningful bkey from new token */
void tgdh_swap_bkey(KEY_TREE *src, KEY_TREE *dst) 
{
  if(src->left != NULL){
    tgdh_swap_bkey(src->left, dst->left);
    tgdh_swap_bkey(src->right, dst->right);
  }
  if(src != NULL){
    if((src->tgdh_nv->bkey != NULL) && (dst->tgdh_nv->bkey == NULL)){
      clq_swap((void *)&(src->tgdh_nv->bkey),(void *)&(dst->tgdh_nv->bkey));
    }
  }
}

/* tgdh_copy_bkey copies meaningful bkey from new token to my null
   token, used for cache update */
void tgdh_copy_bkey(KEY_TREE *src, KEY_TREE *dst) 
{
  if(src->left != NULL){
    tgdh_copy_bkey(src->left, dst->left);
    tgdh_copy_bkey(src->right, dst->right);
  }
  if(src != NULL){
    if(src->tgdh_nv->bkey != NULL){
      if(dst->tgdh_nv->bkey == NULL){
        dst->tgdh_nv->bkey = BN_dup(src->tgdh_nv->bkey);
      }
    }
  }
}

/* tgdh_check_useful checks whether new_ctx has useful information
 * If it has, return 1,
 * else, return 0
 */
int tgdh_check_useful(KEY_TREE *newtree, KEY_TREE *mytree) 
{
  KEY_TREE *head_new=NULL, *tail_new=NULL;
  KEY_TREE *head_my=NULL, *tail_my=NULL;

  head_new=tail_new=newtree;
  head_my=tail_my=mytree;

  tgdh_init_bfs(newtree);
  tgdh_init_bfs(mytree); 
  
  while(head_new != NULL){
    if(head_new->tgdh_nv->bkey!=NULL){
      if(head_my->tgdh_nv->bkey==NULL){
        return 1;
      }
      else{
        if(BN_cmp(head_new->tgdh_nv->bkey, head_my->tgdh_nv->bkey) != 0){
          return 1;
        }
      }
    }
    /* Queue handling */
    if(head_new->left){
      tail_new->bfs = head_new->left;
      tail_new = tail_new->bfs;
      tail_my->bfs = head_my->left;
      tail_my = tail_my->bfs;
    }
    if(head_new->right){
      tail_new->bfs = head_new->right;
      tail_new = tail_new->bfs;
      tail_my->bfs = head_my->right;
      tail_my = tail_my->bfs;
    }
    head_new = head_new->bfs;
    head_my = head_my->bfs;
    
  }
  tgdh_init_bfs(newtree);
  tgdh_init_bfs(mytree); 

  return 0;
}

/* tgdh_init_bfs initializes(nullfies) bfs pointers for each node */
void tgdh_init_bfs(KEY_TREE *tree)
{
  if(tree != NULL){
    if(tree->left){
      tgdh_init_bfs(tree->left);
      tgdh_init_bfs(tree->right);
    }
    if(tree != NULL){
      tree->bfs = NULL;
    }
  }
}

/* remove_sponsor: remove the sponsor from the sponsor list */
int remove_sponsor(CLQ_NAME *sponsor_list[], CLQ_NAME *sponsor)
{
  int i=0, j=0;

  if(sponsor_list[0] == NULL) {
    return -1;
  }
  
  for(i=0; i<NUM_USERS+1; i++){
    if(sponsor_list[i] != NULL){
      if(strcmp(sponsor_list[i], sponsor)==0){
        break;
      }
    }
  }
  for(j=i; j<NUM_USERS-1; j++){
    if(sponsor_list[j] != NULL){
      sponsor_list[j] = sponsor_list[j+1];
    }
  }
  
  return 1;
}

/* remove_member removes leaving members from the current tree.
 * o Reason for this function: It was leave part of tgdh_cascade
 *    function, but I decided to make a function since we need to add
 *    this functionality to tgdh_merge_req too...
 * o What is it doing?
 *   - This function will only remove the leaving members...
 *   - No key update happens...
 */
int remove_member(TGDH_CONTEXT *ctx, CLQ_NAME *users_leaving[],
                  KEY_TREE *sponsor_list[])
{
  KEY_TREE *the_sponsor=NULL;
  int i=0;
  KEY_TREE *leave_node=NULL, *first=NULL;
  KEY_TREE *tmp_node=NULL, *tmp1_node=NULL;
  int min_index=100000;
  int height=0;
  int num_sponsor=0;
  
  while(users_leaving[i] != NULL){
    /* If I have cache and if I receive another membership, remove
       cache */
    ctx->status = CONTINUE;
    
    /* If my name is in the users_leaving list, then I just exit
     * partition with OK... I will call again to partition out other
     * members
     */
    if(strcmp(users_leaving[i], ctx->member_name)==0){
      return 4;
    }
    
    /* Delete every bkey and key which is related with the leaving
     * members;
     */ 
    tmp1_node=leave_node=tgdh_search_member(ctx->root, 4,
                                            users_leaving[i]);
    if(tmp1_node == NULL) {
      return MEMBER_NOT_IN_GROUP;
    }
    while(tmp1_node != NULL){
      if(tmp1_node->tgdh_nv->bkey != NULL){
        BN_clear_free(tmp1_node->tgdh_nv->bkey);
        tmp1_node->tgdh_nv->bkey = NULL;
      }
      if(tmp1_node->tgdh_nv->key != NULL){
        BN_clear_free(tmp1_node->tgdh_nv->key);
        tmp1_node->tgdh_nv->key = NULL;
      }
      tmp1_node = tmp1_node->parent;
    }
    
    /* Delete the leaving members from the current tree;
     * Pointer handling
     */
    if(leave_node->parent->parent == NULL){ /* If my index is 2 or 3 */
      if(leave_node->tgdh_nv->index % 2 == 0){ /* If my index is 2 */
        if(leave_node->parent != ctx->root){
          fprintf(stderr, "Parent of leave node is not root 1\n");
          return STRUCTURE_ERROR;
        }
        tgdh_copy_node(leave_node->parent, leave_node->parent->right);
        tmp_node=ctx->root = leave_node->parent->right;
        leave_node->parent->right->parent = NULL;
      }
      else{ /* If my index is 3 */
        if(leave_node->parent != ctx->root){
          fprintf(stderr, "Parent of leave node is not root 1\n");
          return STRUCTURE_ERROR;
        }
        tgdh_copy_node(leave_node->parent, leave_node->parent->left);
        tmp_node=ctx->root = leave_node->parent->left;
        leave_node->parent->left->parent = NULL;
      }
    }
    else{
      if(leave_node->parent->tgdh_nv->index % 2 == 0){ /* If my parent is a left intermediate node */
        if(leave_node->tgdh_nv->index % 2 == 0){ /* If I am a left leave node */
          tgdh_copy_node(leave_node->parent, leave_node->parent->right);
          leave_node->parent->parent->left = leave_node->parent->right;
          leave_node->parent->right->parent = leave_node->parent->parent;
          tmp_node = leave_node->parent->right;
        }
        else{
          tgdh_copy_node(leave_node->parent, leave_node->parent->left);
          leave_node->parent->parent->left = leave_node->parent->left;
          leave_node->parent->left->parent = leave_node->parent->parent;
          tmp_node = leave_node->parent->left;
        }
      }
      else{
        if(leave_node->tgdh_nv->index % 2 == 0){
          tgdh_copy_node(leave_node->parent, leave_node->parent->right);
          leave_node->parent->parent->right = leave_node->parent->right;
          leave_node->parent->right->parent = leave_node->parent->parent;
          tmp_node = leave_node->parent->right;
        }
        else{
          tgdh_copy_node(leave_node->parent, leave_node->parent->left);
          leave_node->parent->parent->right = leave_node->parent->left;
          leave_node->parent->left->parent = leave_node->parent->parent;
          tmp_node = leave_node->parent->left;
        }
      }
    }
    if(tmp_node->left){ /* why not update the index of the tmp_node? */
      tgdh_update_index(tmp_node->right, 1, 
                        tmp_node->tgdh_nv->index);
      tgdh_update_index(tmp_node->left, 0,
                        tmp_node->tgdh_nv->index);
    }
    
    if(leave_node->prev != NULL) 
      leave_node->prev->next = leave_node->next;
    if(leave_node->next != NULL) 
      leave_node->next->prev = leave_node->prev;
    tgdh_free_node(&leave_node->parent);
    tgdh_free_node(&leave_node);
    
    ctx->root->tgdh_nv->num_node -= 2; /* one leave node and one intermediate node */
    first = tgdh_search_member(ctx->root, 2, NULL);
    if(first == NULL) {
      return STRUCTURE_ERROR;
    }
    height=0;
    while(first != NULL){
      height = MAX(clq_log2(first->tgdh_nv->index), height);
      first = first->next;
    }
    
    ctx->root->tgdh_nv->height = height;
    first = tgdh_search_member(ctx->root, 2, NULL);
    if(first == NULL) {
      return STRUCTURE_ERROR;
    }
    while(first != NULL){
      first->tgdh_nv->potential =
        height - clq_log2(first->tgdh_nv->index) -1;
      if(first->tgdh_nv->potential > -1) first->tgdh_nv->joinQ = TRUE;
      else first->tgdh_nv->joinQ = FALSE;
      first = first->next;
    }
    
    tgdh_update_potential(ctx->root);
    
    i++;
  }

  tgdh_init_bfs(ctx->root);
  num_sponsor = find_sponsors(ctx->root, sponsor_list);
  tgdh_init_bfs(ctx->root);
  
  /* tgdh_print_simple("Bef spo ch", ctx->root); */
  if(sponsor_list[0] != NULL){
    for(i=0; i<num_sponsor; i++){
      tmp1_node = tgdh_search_member(ctx->root, 4,
                                     sponsor_list[i]->tgdh_nv->member->member_name);  
      if(tmp1_node->tgdh_nv->index < min_index){
        the_sponsor = tmp1_node;
        min_index = tmp1_node->tgdh_nv->index;
      }
    }
    
    tmp1_node = the_sponsor;
    if(tmp1_node->tgdh_nv->bkey != NULL){
      BN_clear_free(tmp1_node->tgdh_nv->bkey);
      tmp1_node->tgdh_nv->bkey = NULL;
    }
    if(tmp1_node->tgdh_nv->key != NULL){
      BN_clear_free(tmp1_node->tgdh_nv->key);
      tmp1_node->tgdh_nv->key = NULL;
    }
    tmp1_node = tmp1_node->parent;
    while(tmp1_node != NULL){
      if(tmp1_node->tgdh_nv->bkey != NULL){
        BN_clear_free(tmp1_node->tgdh_nv->bkey);
        tmp1_node->tgdh_nv->bkey = NULL;
      }
      if(tmp1_node->tgdh_nv->key != NULL){
        BN_clear_free(tmp1_node->tgdh_nv->key);
        tmp1_node->tgdh_nv->key = NULL;
      }
      tmp1_node = tmp1_node->parent;
    }
  }

  return 1;
}

/* Make a tree list for merge */
TREE_LIST *add_tree_list(TREE_LIST *list, KEY_TREE *tree) 
{
  TREE_LIST *tmp_list=NULL, *tmp1_list=NULL, *tmp2_list=NULL;
  TREE_LIST *head=NULL; 
  KEY_TREE *tmp_tree=NULL, *tmp1_tree=NULL;

  head = list;
  tmp_tree = tgdh_search_member(tree, 3, NULL);

  if(tree == NULL) return NULL;
  
  if(list == NULL){
    list = (TREE_LIST *) calloc(sizeof(TREE_LIST), 1);
    if(list == NULL){
      return NULL;
    }
    list->tree = tree;
    list->end = list;
    list->next = NULL;
    return list;
  }
  else{
    if(list->end != list){
      if(list->next == NULL){
        return NULL;
      }
    }
    else{
      if(list->end->next != NULL){
        return NULL;
      }
    }
    tmp_list = (TREE_LIST *) calloc(sizeof(TREE_LIST), 1);
    tmp_list->tree = tree;

    tmp1_list = head;
    while(tmp1_list != NULL){
      tmp1_tree = tgdh_search_member(tmp1_list->tree, 3, NULL);
      if(tmp1_list->tree->tgdh_nv->height <
         tmp_list->tree->tgdh_nv->height){
        break;
      }
      else if((tmp1_list->tree->tgdh_nv->height ==
               tmp_list->tree->tgdh_nv->height) &&
              (strcmp(tmp1_tree->tgdh_nv->member->member_name,
                      tmp_tree->tgdh_nv->member->member_name) < 0)){
        break;
      }
      else{
        tmp2_list = tmp1_list;
        tmp1_list = tmp1_list->next;
      }
    }

    if(tmp2_list == NULL){
      tmp_list->next = tmp1_list;
      tmp_list->end = tmp1_list->end;
      tmp1_list->end = NULL;
      return tmp_list;
    }
    
    if(tmp1_list == NULL){
      tmp2_list->next = tmp_list;
      head->end = tmp_list;
      if(tmp2_list != head){
        tmp2_list->end = NULL;
      }
      return head;
    }

    tmp2_list->next = tmp_list;
    tmp_list->next = tmp1_list;
    
  }

  return head;
}

/* -> unclear of the function of bfs and holes */
int find_sponsors(KEY_TREE *root, KEY_TREE *sponsor_list[])
{
  KEY_TREE *head=NULL, *tail=NULL, *holes[NUM_USERS]={NULL};
  int num_holes=0, i=0;
  
  for(i=0; i<NUM_USERS; i++){
    holes[i] = NULL;
  }

  
  head = tgdh_search_member(root, 5, NULL);
  head = tgdh_search_member(head, 2, NULL);
  tgdh_init_bfs(head);

  head = tail = root;
  
  while(head != NULL){
    if(head->left == NULL){
      holes[num_holes] = head;
      num_holes++;
    }
    else {
      if((head->left->tgdh_nv->bkey != NULL) && (head->right->tgdh_nv->bkey != NULL)){
        holes[num_holes] = head;
        num_holes++;
      }
      else{
        if(head->right->tgdh_nv->bkey == NULL){
          tail->bfs = head->right;
          tail = tail->bfs;
        }
        if(head->left->tgdh_nv->bkey == NULL){
          tail->bfs = head->left;
          tail = tail->bfs;
        }
      }
    }
    head = head->bfs;
  }
  
  head = tgdh_search_member(root, 5, NULL);
  head = tgdh_search_member(head, 2, NULL);
  tgdh_init_bfs(head);
  
  tail = head = NULL;

  for(i=0; i<num_holes; i++){
    sponsor_list[i] = tgdh_search_member(holes[i], 6, NULL);
  }
  
  return num_holes;
}

/* tgdh_merge merges two tree using tgdh_merge_tree */
KEY_TREE *tgdh_merge(KEY_TREE *big_tree, KEY_TREE *small_tree)
{
  KEY_TREE *tmp1_node=NULL, *tmp_node=NULL;
  KEY_TREE *joiner=NULL, *joinee=NULL;
  int tmp_height=0, tmp_num=0;
  
  /* Now, we can merge two trees to generate a new tree   */
  if(big_tree->tgdh_nv->height == small_tree->tgdh_nv->height){
    tmp1_node = tgdh_search_member(big_tree, 2, NULL);
    tmp_node = tgdh_search_member(small_tree, 2, NULL);
    if(strcmp(tmp1_node->tgdh_nv->member->member_name,
              tmp_node->tgdh_nv->member->member_name)>0){  
      joiner = small_tree;
      joinee = big_tree;
    }
    else if(strcmp(tmp1_node->tgdh_nv->member->member_name,
                   tmp_node->tgdh_nv->member->member_name)<0){  
      joiner = big_tree;
      joinee = small_tree;
    }
    else{
      fprintf(stderr,"strange... two of them are same???\n");
      return NULL;
    }
  }
  else if(big_tree->tgdh_nv->height > small_tree->tgdh_nv->height){ 
    joiner = small_tree;
    joinee = big_tree;
  }
  else{
    joiner = big_tree;
    joinee = small_tree;
  }
  
  if(joiner->tgdh_nv->height <= joinee->tgdh_nv->potential){
    tmp_height = joinee->tgdh_nv->height;
  }
  else{
    tmp_height = joinee->tgdh_nv->height+1;
  }
  tmp_num=joiner->tgdh_nv->num_node+joinee->tgdh_nv->num_node+1;
  tmp1_node = tmp_node = tgdh_search_node(joiner, joinee, 0);
  tmp_node = tgdh_merge_tree(joiner, tmp_node);
  if(tmp_node == NULL) {
    return NULL;
  }
  if(tmp_node->parent != NULL){
    return NULL;
  }
  
  tmp1_node = joiner->parent;
  while(tmp1_node != NULL){
    if(tmp1_node->tgdh_nv->key != NULL){
      BN_clear_free(tmp1_node->tgdh_nv->key);
      tmp1_node->tgdh_nv->key = NULL;
    }
    if(tmp1_node->tgdh_nv->bkey != NULL){
      BN_clear_free(tmp1_node->tgdh_nv->bkey);
      tmp1_node->tgdh_nv->bkey = NULL;
    }
    tmp1_node = tmp1_node->parent;
  }
  
  big_tree = tmp_node;
  
  big_tree->tgdh_nv->height = tmp_height;
  big_tree->tgdh_nv->num_node = tmp_num;
  if(joinee != tmp_node){
    joinee->tgdh_nv->height=joinee->tgdh_nv->num_node=-1;
  }
  if(joiner != tmp_node){
    joiner->tgdh_nv->height=joiner->tgdh_nv->num_node=-1;
  }

  return big_tree;
}

/* Remove all tree list */
void remove_tree_list(TREE_LIST **list)
{
  TREE_LIST *tmp_list=NULL;

  tmp_list = (*list)->next;
  while((*list) != NULL){
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

  
