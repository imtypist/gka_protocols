/*********************************************************************
 * str_api.c                                                         * 
 * STR API main source file                                          * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
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

/* STR_API include files */
#include "str_api.h"
#include "error.h"
#include "common.h" /* clq_get_cert is here */

#include "str_sig.h"
#include "str_test_misc.h" 

#include "str_api_misc.h" /* str_get_time is defined here */

#ifdef TIMING
#include "str_test.h"
#endif

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/* str_new_member is called by the new member in order to create its
 *   own context. Main functionality of this function is to generate
 *   session random for the member
 */
int str_new_member(STR_CONTEXT **ctx, CLQ_NAME *member_name,
                    CLQ_NAME *group_name)
{
  int ret=OK;

  if (member_name == NULL) return INVALID_MEMBER_NAME;
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  
  if ((ret=str_create_ctx(ctx)) != OK) {goto error;}
  
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
  if (((*ctx)->pkey) == (EVP_PKEY*) NULL){
    ret=INVALID_PRIV_KEY;
    goto error;
  }
  
  (*ctx)->root->str_nv=(STR_NV *) calloc(sizeof(STR_NV),1);
  (*ctx)->root->str_nv->member = (STR_GM *) calloc(sizeof(STR_GM),1);
  (*ctx)->root->str_nv->member->member_name=(CLQ_NAME *)
    calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1); 
  strncpy ((*ctx)->root->str_nv->member->member_name,
           (*ctx)->member_name,MAX_LGT_NAME);
  (*ctx)->root->str_nv->member->cert = NULL;
  
  (*ctx)->root->str_nv->index=1;
  (*ctx)->root->str_nv->num_user=1;
  
  /* I'm only member in my group... So key is same as my session random */
  (*ctx)->root->str_nv->key=str_rand((*ctx)->params);
  
  if (BN_is_zero((*ctx)->root->str_nv->key) ||
      (*ctx)->root->str_nv->key==NULL){
    ret=MALLOC_ERROR;
    goto error;
  }
  /* group_secret is same as key */
  if((*ctx)->group_secret == NULL){
    (*ctx)->group_secret=BN_dup((*ctx)->root->str_nv->key);
    if ((*ctx)->group_secret == (BIGNUM *) NULL) {
      ret=MALLOC_ERROR;
      goto error;
    }
  }
  else{
    BN_copy((*ctx)->group_secret,(*ctx)->root->str_nv->key);
  }
  
  ret=str_compute_secret_hash ((*ctx));
  if (ret!=OK) goto error;
  (*ctx)->root->str_nv->member->cert=NULL;
  
  /* Compute blinded Key */
  (*ctx)->root->str_nv->bkey=
    str_compute_bkey((*ctx)->root->str_nv->key, (*ctx)->params);
  if((*ctx)->root->str_nv->bkey== NULL){
    ret=MALLOC_ERROR;
    goto error;
  }
  (*ctx)->status = OK;
  
error:
  /* OK... Let's free the memory */
  if (ret!=OK) str_destroy_ctx(&(*ctx),1);
  
  return ret;
}

/* str_merge_req is called by sponsors in both groups 
 *   ctx: context of the caller
 *   member_name: name of the caller
 *   group_name: target group name
 *   output: output token(input token of str_merge)
 */
int str_merge_req (STR_CONTEXT *ctx, CLQ_NAME *member_name, 
                    CLQ_NAME *group_name, CLQ_TOKEN **output)
{
  int ret=OK;
  STR_TOKEN_INFO *info=NULL;
  STR_KEY_TREE *tmp_tree=NULL;
  
  if (ctx == NULL) return CTX_ERROR;
  if (member_name == NULL) return INVALID_MEMBER_NAME;
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;

  /* Sponsor is the rightmost member */
  tmp_tree = str_search_member(ctx->root, 3, NULL);
  if(strcmp(ctx->member_name, tmp_tree->str_nv->member->member_name)){
    ret = OK;
    goto error;
  }
  
  /* Creating token info */
  ret=str_create_token_info(&info,ctx->group_name,STR_KEY_MERGE_UPDATE, 
                             time(0),ctx->member_name); 
  if (ret!=OK) goto error;
  
  /* Encoding */
  ret=str_encode(ctx,output,info);
  if (ret!=OK) goto error;
  
  /* sign_message */
  ret=str_sign_message (ctx, *output);
  
error:
  /* OK... Let's free the memory */
  if (ret!=OK) str_destroy_ctx(&ctx, 1);
  if (info != (STR_TOKEN_INFO*)NULL) str_destroy_token_info(&info);
  
  return ret;
}

/* str_cascade is called by every member several times until every
 * member can compute the new group key when any network events occur.
 * o this function handles every membership event, e.g. join, leave,
 *   merge, and partition.
 * o this function handles any cascaded events.
 * o this funciton is str-stabilizing.
 * o sponsors are decided uniquely for every membership event, and
 *   only the sponsors return an output
 *   - ctx: context of the caller
 *   - member_name: name of the caller
 *   - users_leaving: list of the leaving members, used only for
 *       subtractive events
 *   - input: Input token(previous output token of
 *       str_cascade or join or merge request) 
 *   - output: output token(will be used as next input token of
 *       str_cascade) 
 */
int str_cascade(STR_CONTEXT **ctx, CLQ_NAME *group_name,
                 CLQ_NAME *users_leaving[],
                 STR_TOKEN_LIST *list, CLQ_TOKEN **output){
  STR_TOKEN_INFO *info=NULL;
  STR_SIGN *sign=NULL;
  STR_CONTEXT *new_ctx=NULL;
  int ret=CONTINUE;
  STR_KEY_TREE *leave_node=NULL, *first=NULL;
  STR_KEY_TREE *tmp_node=NULL, *tmp1_node=NULL, *tmp2_node=NULL;
  STR_TOKEN_LIST *tmp_list = NULL;
  STR_TREE_LIST *new_tree_list=NULL, *tmp_tree_list=NULL;

  int message_type=-1, sender = 0;
  int i=0;
  int result=OK;
  int leaveormerge=0;
  BN_CTX *bn_ctx=BN_CTX_new();
  int new_status=0;
  STR_KEY_TREE *the_sponsor=NULL;
  int new_information=0;
  int new_key_comp=0;
  int epoch=0;
  
  /* Doing some error checkings */
  if ((*ctx) == NULL) return CTX_ERROR;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;

  i=0;
  if(users_leaving != NULL){
    while(users_leaving[i] != NULL){
      leaveormerge=1;
      /* this is the first call or cascaded leave happens
         Currently, STR does not provide leave + merge
      */
      if(list != NULL) {
        result = INVALID_INPUT_TOKEN;
        printf("This is weird 1\n\n");
        
        goto error;
      }
      /* If my name is in the users_leaving list, then I just exit
       * partition with OK... I will call again to partition out other
       * members
       */
      if(strcmp(users_leaving[i], (*ctx)->member_name)==0){
        goto error;
      }
      (*ctx)->status = CONTINUE;
  
      /* Delete every bkey and key which is related with the leaving
       * members;
       */ 
      tmp1_node=leave_node=str_search_member((*ctx)->root, 4,
                                              users_leaving[i]);
      if(tmp1_node == NULL) {
        result=MEMBER_NOT_IN_GROUP;
        goto error;
      }
      
      while(tmp1_node != NULL){
        if(tmp1_node->str_nv->bkey != NULL){
          BN_clear_free(tmp1_node->str_nv->bkey);
          tmp1_node->str_nv->bkey = NULL;
        }
        if(tmp1_node->str_nv->key != NULL){
          BN_clear_free(tmp1_node->str_nv->key);
          tmp1_node->str_nv->key = NULL;
        }
        tmp1_node = tmp1_node->parent;
      }
      
      /* Delete the leaving members from the current tree;
       * Pointer handling
       */
      if(leave_node->parent->parent == NULL){ /* If my index is 2 or 3 */
        if(leave_node->str_nv->index % 2 == 0){ /* If my index is 2 */
          if(leave_node->parent != (*ctx)->root){
            result=STRUCTURE_ERROR;
            goto error;
          }
          str_copy_node(leave_node->parent, leave_node->parent->right);
          tmp_node=(*ctx)->root = leave_node->parent->right;
          leave_node->parent->right->parent = NULL;
        }
        else{ /* If my index is 3 */
          if(leave_node->parent != (*ctx)->root){
            result=STRUCTURE_ERROR;
            goto error;
          }
          str_copy_node(leave_node->parent, leave_node->parent->left);
          tmp_node=(*ctx)->root = leave_node->parent->left;
          leave_node->parent->left->parent = NULL;
        }
      }
      else{
        if(leave_node->str_nv->index % 2 == 0){ /* left most leaf node */
          str_copy_node(leave_node->parent, leave_node->parent->right);
          leave_node->parent->parent->left = leave_node->parent->right;
          leave_node->parent->right->parent = leave_node->parent->parent;
          tmp_node = leave_node->parent->right;
        }
        else{
          str_copy_node(leave_node->parent, leave_node->parent->left);
          leave_node->parent->parent->left = leave_node->parent->left;
          leave_node->parent->left->parent = leave_node->parent->parent;
          tmp_node = leave_node->parent->left;
        }
      }
      if(tmp_node->left){
        str_update_index(tmp_node->right, 1, tmp_node->str_nv->index);
        str_update_index(tmp_node->left,  0, tmp_node->str_nv->index);
      }
      
      if(leave_node->prev != NULL) 
        leave_node->prev->next = leave_node->next;
      if(leave_node->next != NULL) 
        leave_node->next->prev = leave_node->prev;
      str_free_node(&leave_node->parent);
      str_free_node(&leave_node);

      (*ctx)->root->str_nv->num_user--;
      first = str_search_member((*ctx)->root, 2, NULL);
      if(first == NULL) {
        result=STRUCTURE_ERROR;
        goto error;
      }
      first = str_search_member((*ctx)->root, 2, NULL);
      if(first == NULL) {
        result=STRUCTURE_ERROR;
        goto error;
      }
      i++;
    }
    if((*ctx)->root->str_nv->bkey != NULL){
      BN_clear_free((*ctx)->root->str_nv->bkey);
      (*ctx)->root->str_nv->bkey = NULL;
    }
    if((*ctx)->root->str_nv->key != NULL){
      BN_clear_free((*ctx)->root->str_nv->key);
      (*ctx)->root->str_nv->key = NULL;
    }
  }
  

  if(list != NULL){ /* This is not the first call */
    /*****************/
    /*               */
    /* JOIN or MERGE */
    /*               */
    /*****************/

    tmp_list = list;
    while (tmp_list != NULL){
      result=str_remove_sign(tmp_list->token,&sign);
      if (result != OK) goto error;
        
      /* Decoding the token & creating new_ctx */
      result=str_decode(&new_ctx, tmp_list->token, &info);
      if (result!=OK){
        goto error;
      }
      
      new_status = new_ctx->status;
      epoch = MAX(epoch, new_ctx->epoch);
      if (strcmp(info->group_name,group_name)){
        result=GROUP_NAME_MISMATCH;
        goto error;
      }
      if(strcmp(info->sender_name, (*ctx)->member_name)){
        /* Verify signature; */
        result=str_vrfy_sign ((*ctx), new_ctx, tmp_list->token,
                              info->sender_name, sign);  
        if(result!=OK) goto error;
      }
      else{
        sender = 1;
      }
      
      if(tmp_list->token != NULL){
        result = str_restore_sign(tmp_list->token, &sign);
      }

      tmp_node = str_search_member(new_ctx->root, 4, (*ctx)->member_name);
      if(tmp_node != NULL){
        if(str_check_useful(new_ctx->root, (*ctx)->root)==1){
          /* Copy new information(if any) to my context;           */
          /* Tree should be same to process the following function */
          str_swap_bkey(new_ctx->root, (*ctx)->root);
        }
        str_free_tree(&(new_ctx->root));
        new_ctx->root = (*ctx)->root;
      }
      
      /* Add new_ctx, info to new_tree_list */
      new_tree_list = str_add_tree_list(new_tree_list, new_ctx->root);
      tmp_list = tmp_list->next;
      message_type = info->message_type;
      
      str_destroy_ctx(&new_ctx, 0);
      str_destroy_token_info(&info);
    }

    switch (message_type) { /* There is no leave or join event */
      /********************/
      /*                  */
      /* MEMBERSHIP EVENT */
      /*                  */
      /********************/
      case STR_PROCESS_EVENT:
      {
        if(epoch != (*ctx)->epoch){
          fprintf(stderr, "\nReceived: %d, Mine: %d\n", epoch,
                  (*ctx)->epoch); 
          result = UNSYNC_EPOCH;
          goto error;
        }
        /* This includes second call of partition, update_ctx of */
        /* join and merge operation                              */
        if(new_status == KEY_COMPUTED){ 
          (*ctx)->status = OK; 
          ret = OK; 
          if(sender){
            (*ctx)->status = OK;
            goto error;
          }
        } 
        break;
      }
    
      /*****************/
      /*               */
      /* JOIN or MERGE */
      /*               */
      /*****************/
      case STR_KEY_MERGE_UPDATE:
      {
        (*ctx)->status = CONTINUE;
        leaveormerge = 1;
        (*ctx)->epoch = MAX(epoch, (*ctx)->epoch);

        (*ctx)->root = new_tree_list->tree;
        tmp_tree_list = new_tree_list->next;
        while(tmp_tree_list != NULL){
          (*ctx)->root = str_merge((*ctx)->root, tmp_tree_list->tree);
          tmp_tree_list = tmp_tree_list->next;
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

  if(leaveormerge == 1){
    if((*ctx)->root->str_nv->num_user == 1){
      the_sponsor = (*ctx)->root;
    }
    else if((*ctx)->root->str_nv->num_user == 2){
      the_sponsor = (*ctx)->root->right;
    }
    else{
      the_sponsor = str_search_member((*ctx)->root, 2, NULL);
      if(the_sponsor->parent != NULL){
        the_sponsor = the_sponsor->parent;
        if(the_sponsor != NULL){
          while((the_sponsor->str_nv->bkey != NULL) && (the_sponsor->parent != NULL)){
            the_sponsor = the_sponsor->parent;
          }
        }
      }
      the_sponsor = the_sponsor->right;
    }
    if(strcmp(the_sponsor->str_nv->member->member_name,
              (*ctx)->member_name) == 0){
      new_information = 1;
    }
  
    tmp_node = str_search_member((*ctx)->root, 4,
                                 the_sponsor->str_nv->member->member_name);  
    if(tmp_node != NULL){
      if(tmp_node->str_nv->key != NULL){
        BN_clear_free(tmp_node->str_nv->key);
        tmp_node->str_nv->key = NULL;
      }
      if(tmp_node->str_nv->bkey != NULL){
        BN_clear_free(tmp_node->str_nv->bkey);
        tmp_node->str_nv->bkey = NULL;
      }
    }
      
    if(new_information){
      tmp_node = str_search_member((*ctx)->root, 4, (*ctx)->member_name);
      if(tmp_node != NULL){
        if(tmp_node->str_nv->key == NULL){
          tmp_node->str_nv->key=str_rand((*ctx)->params);
        }
        if(tmp_node->str_nv->bkey == NULL){
          tmp_node->str_nv->bkey =
            str_compute_bkey(tmp_node->str_nv->key, (*ctx)->params);  
        }
      }
    }
  }
    
  tmp1_node = str_search_member((*ctx)->root, 4, (*ctx)->member_name);
  if(tmp1_node->parent != NULL){
    while((tmp1_node->parent->str_nv->key != NULL) && (tmp1_node->parent != NULL)){
      tmp1_node = tmp1_node->parent;
    }
  }
  
  if((new_information == 1) || (new_status == KEY_COMPUTED)){
    if(tmp1_node != (*ctx)->root){
      if(tmp1_node->parent->str_nv->key != NULL){
        result = STRUCTURE_ERROR;
        goto error;
      }
      if(tmp1_node->str_nv->index % 2){
        tmp_node = tmp1_node->parent->left;
      }
      else{
        tmp_node = tmp1_node->parent->right;
      }
      while(tmp_node->str_nv->bkey != NULL){
        /* Compute intermediate keys until I can */
        if(tmp1_node->parent->str_nv->key != NULL){
          result=STRUCTURE_ERROR;
          goto error;
        }
        tmp1_node->parent->str_nv->key = BN_new();
        if(tmp1_node->parent->left->str_nv->key != NULL){
          if(tmp1_node->parent->right->str_nv->bkey != NULL){
            new_key_comp = 1;
            result = BN_mod(tmp1_node->parent->left->str_nv->key,
                            tmp1_node->parent->left->str_nv->key,   
                            DSA_get0_q((*ctx)->params), bn_ctx);
            if(result != OK) goto error;
            result=BN_mod_exp(tmp1_node->parent->str_nv->key,
                              tmp1_node->parent->right->str_nv->bkey,
                              tmp1_node->parent->left->str_nv->key,
                              DSA_get0_p((*ctx)->params),bn_ctx);
          }
          else{
          }
        }
        else{
          if(tmp1_node->parent->left->str_nv->bkey != NULL){
            new_key_comp = 1;
            result = BN_mod(tmp1_node->parent->right->str_nv->key,
                            tmp1_node->parent->right->str_nv->key,   
                            DSA_get0_q((*ctx)->params), bn_ctx);
            if(result != OK) goto error;
            result=BN_mod_exp(tmp1_node->parent->str_nv->key,
                              tmp1_node->parent->left->str_nv->bkey,
                              tmp1_node->parent->right->str_nv->key,
                              DSA_get0_p((*ctx)->params),bn_ctx);
          }
        }
        if(result != OK) goto error;
        
        /* Compute bkeys */
        if(tmp1_node->parent->str_nv->bkey != NULL){
          BN_clear_free(tmp1_node->parent->str_nv->bkey);
          tmp1_node->parent->str_nv->bkey=NULL;
        }
        tmp1_node->parent->str_nv->bkey
          =str_compute_bkey(tmp1_node->parent->str_nv->key, (*ctx)->params);
        
        
        if(tmp1_node->parent->parent == NULL) {
          break;
        }
      else{
        tmp1_node = tmp1_node->parent;
      }
        if(tmp1_node->str_nv->index % 2){
          tmp_node = tmp1_node->parent->left;
        }
        else{
          tmp_node = tmp1_node->parent->right;
        }
      }
      if(the_sponsor != NULL){
        tmp2_node = str_search_member((*ctx)->root, 2, NULL);
        while(tmp2_node->next != NULL){
          if(tmp2_node->str_nv->bkey == NULL){
            break;
          }
          tmp2_node = tmp2_node->next;
        }
      }
    }
  }
  
  
  if((*ctx)->root->str_nv->key != NULL){
    if((*ctx)->status == CONTINUE){
      ret = KEY_COMPUTED;
      (*ctx)->status = KEY_COMPUTED;
    }
    if((*ctx)->root->str_nv->member != NULL){
      if(strcmp((*ctx)->root->str_nv->member->member_name,
                (*ctx)->member_name)==0){
        ret = OK;
        (*ctx)->status = OK;
      }
    }
  }

  if((new_information == 1) && (new_key_comp == 1) && ((*ctx)->status != OK)){
    /* If I have any new information, encode my information to output; */
    if (info != NULL) str_destroy_token_info(&info);
    /* Creating token info */
    result=str_create_token_info(&info, (*ctx)->group_name,
                                 STR_PROCESS_EVENT, time(0),
                                 (*ctx)->member_name);  
    if (result!=OK) goto error;
    result=str_encode((*ctx),output,info);
    if (result!=OK) goto error;
    
    /* Sign output token; */
    result=str_sign_message ((*ctx), *output);
  }
  
error:
  if(new_tree_list != NULL){
    STR_remove_tree_list(&new_tree_list);
  }

  if(ret == OK){
    if((*ctx)->root->str_nv->key == NULL){
      fprintf(stderr, "Key is NULL, but return is OK\n\n");
    }
    
    BN_copy((*ctx)->group_secret,(*ctx)->root->str_nv->key);
    result=str_compute_secret_hash ((*ctx));
    (*ctx)->epoch++; 
  }
        
  if (result <= 0){
    ret = result;
    if (ctx != NULL) str_destroy_ctx(ctx,1);
  }
  if (info != NULL) str_destroy_token_info(&info);
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);

  return ret;
}

/* str_merge merges two tree using str_merge_tree */
STR_KEY_TREE *str_merge(STR_KEY_TREE *big_tree, STR_KEY_TREE *small_tree)
{
  int tmp_num=0;
  STR_KEY_TREE *root=NULL, *tmp1_node=NULL, *tmp_node=NULL;
    
  tmp_num=small_tree->str_nv->num_user+big_tree->str_nv->num_user;
  if(big_tree->str_nv->num_user > 1){
    tmp1_node = big_tree;
  }
  tmp_node = str_merge_tree(small_tree, big_tree);

  while(tmp1_node != NULL){
    if(tmp1_node->str_nv->key != NULL){
      BN_clear_free(tmp1_node->str_nv->key);
      tmp1_node->str_nv->key = NULL;
    }
    if(tmp1_node->str_nv->bkey != NULL){
      BN_clear_free(tmp1_node->str_nv->bkey);
      tmp1_node->str_nv->bkey = NULL;
    }
    tmp1_node = tmp1_node->parent;
  }
  
  root = str_search_member(big_tree, 5, NULL);
  
  root->str_nv->num_user = tmp_num;
  if(big_tree != root){
    big_tree->str_nv->num_user=0;
  }
  if((small_tree->right != root) && (small_tree->right != NULL)){
    small_tree->right->str_nv->num_user=0;
  }

  return root;
}

          
/* str_create_ctx creates the str context.
 * Preconditions: *ctx has to be NULL.
 */
int str_create_ctx(STR_CONTEXT **ctx) 
{
  int ret=CTX_ERROR;

  if (*ctx != (STR_CONTEXT *)NULL) return CTX_ERROR;
  /* Creating ctx */
  (*ctx) = (STR_CONTEXT *) calloc(sizeof(STR_CONTEXT), 1);
  if ((*ctx) == NULL) goto error;
  (*ctx)->member_name=NULL;
  (*ctx)->group_name=NULL;
  (*ctx)->root=(STR_KEY_TREE *) calloc(sizeof(STR_KEY_TREE),1);
  if ((*ctx)->root == (STR_KEY_TREE *) NULL) goto error;
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
  if (ret!=OK) str_destroy_ctx (ctx,1);
  
  return ret;
}

/* str_compute_bkey: Computes and returns bkey */
BIGNUM *str_compute_bkey (BIGNUM *key, DSA *params)
{
  int ret=OK;
  BIGNUM *new_bkey = BN_new();
  BN_CTX *bn_ctx=BN_CTX_new();
  
  if (bn_ctx == (BN_CTX *) NULL) {ret=MALLOC_ERROR; goto error;}
  if (new_bkey == NULL) {ret=MALLOC_ERROR; goto error;}
  if (key == NULL) {
    ret=STRUCTURE_ERROR;
    goto error;
  }
  
  ret=BN_mod(key,key,DSA_get0_q(params), bn_ctx);
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

/* str_rand: Generates a new random number of "params->q" bits, using
 *   the default parameters.
 * Returns: A pointer to a dsa structure where the random value
 *          resides. 
 *          NULL if an error occurs.
 */
BIGNUM *str_rand (DSA *params) 
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

/* str_compute_secret_hash: It computes the hash of the group_secret.
 * Preconditions: ctx->group_secret has to be valid.
 */
int str_compute_secret_hash (STR_CONTEXT *ctx) 
{
  char *tmp_str=NULL;
  
  tmp_str=BN_bn2hex(ctx->group_secret);
  if (tmp_str==NULL) return CTX_ERROR;
  
  MD5((clq_uchar *)tmp_str, (unsigned long)strlen(tmp_str), 
      ctx->group_secret_hash);
  
  free(tmp_str);
  
  if (ctx->group_secret_hash == (clq_uchar *) NULL) return CTX_ERROR; 
  
  return OK;
}

/* str_destroy_ctx frees the space occupied by the current context.
 * Including the group_members_list.
 *   if flag == 1, delete all context
 *   if flag == 0, delete all except the tree(used for merge)
 */

void str_destroy_ctx (STR_CONTEXT **ctx, int flag) 
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
  if (((*ctx)->group_secret_hash) != NULL) {
    free((*ctx)->group_secret_hash);
    (*ctx)->group_secret_hash=NULL;
  }

  if(flag == 1){
    str_free_tree(&((*ctx)->root));
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

/* str_encode using information from the current context and from
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
int str_encode(STR_CONTEXT *ctx, CLQ_TOKEN **output,
		STR_TOKEN_INFO *info) 
{ 
  uint pos=0;
  clq_uchar *data;
  
  /* Freeing the output token if necessary */
  if((*output) != NULL) str_destroy_token(output);
  
  /* Do some error checkings HERE !! */
  if (ctx == (STR_CONTEXT *) NULL) return CTX_ERROR;
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
  
  str_map_encode(data, &pos, ctx->root);
  
  *output=(CLQ_TOKEN *) calloc(sizeof(CLQ_TOKEN),1);
  if (*output == (CLQ_TOKEN *) NULL) return MALLOC_ERROR;
  (*output)->length=pos;
  (*output)->t_data=data;
  
  return OK;
}

/* Converts tree structure to unsigned character string */
void str_map_encode(clq_uchar *stream, uint *pos, STR_KEY_TREE *root)
{
  STR_KEY_TREE *head, *tail;
  int map = 0;        /* If map is 3, index, bkey, member_name
                       * If map is 2, index, member_name
                       * If map is 1, index, bkey
                       * If map is 0, only index
                       */

  head = str_search_member(root, 2, NULL);
  
  while(head != NULL){ 
    if(head->bfs != NULL) head->bfs = NULL;
    head = head->next; 
  } 

  int_encode(stream, pos, root->str_nv->num_user);
  head = tail = root;
  
  while(head != NULL){
    if(head->str_nv->member == NULL){
      if(head->str_nv->bkey == NULL){
        map = 0;
      }
      else map = 1;
    }
    else{
      if(head->str_nv->bkey == NULL){
        map = 2;
      }
      else map = 3;
    }
    
    /* Real encoding */
    int_encode(stream, pos, map);
    int_encode(stream, pos, head->str_nv->index);
    if(head->str_nv->bkey != NULL) 
      bn_encode(stream, pos, head->str_nv->bkey);
    if(head->str_nv->member != NULL) 
      string_encode(stream, pos, head->str_nv->member->member_name);
    
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
  
  tail = head = NULL;
}

/* str_decode using information from the input token, it creates
 * ctx. info is also created here. It contains data recovered from
 * input such as message_type, sender, etc. (See structure for more
 * details) in readable format. 
 * Preconditions: *ctx has to be NULL.
 * Postconditions: ctx is created. The only valid data in it is
 * group_members_list (first & last), and epoch. All the other
 * variables are NULL. (str_create_ctx behavior)
 */
int str_decode(STR_CONTEXT **ctx, CLQ_TOKEN *input,
                STR_TOKEN_INFO **info)
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
  ret=str_create_token_info(info,"",STR_INVALID,0L,"");
  if (ret!=OK) goto error;
  
  if (ret!=str_create_ctx(ctx)) goto error;
  
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
  if ((ret=str_map_decode(input,&pos,ctx)) != OK)
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
        
    if (info != NULL) str_destroy_token_info(info);
    if (ctx != NULL) str_destroy_ctx(ctx,1);
  }
  
  return ret;
}

/* str_map_decode decode input token to generate tree for the new
 *   tree
 * *tree should be pointer to the root node
 */
int str_map_decode(const CLQ_TOKEN *input, uint *pos, 
                    STR_CONTEXT **ctx)
{
  int i;
  uint map=0;
  uint tmp_index;
  STR_KEY_TREE *tmp_tree=NULL, *tmp1_tree=NULL;
  int ret=OK;
  
  (*ctx)->root->str_nv = (STR_NV *)calloc(sizeof(STR_NV),1);
  if ((*ctx)->root->str_nv == NULL) 
  {ret=MALLOC_ERROR; goto error;}
  if(!int_decode(input, pos, (uint *)&((*ctx)->root->str_nv->num_user))) 
    return 0;
  
  (*ctx)->root->parent = NULL;
  (*ctx)->root->str_nv->member = NULL;
  
  if(!int_decode(input, pos, &map)) return 0;
  if(!int_decode(input, pos, &tmp_index)) return 0;
  
  (*ctx)->root->str_nv->index = tmp_index;
  (*ctx)->root->str_nv->key = (*ctx)->root->str_nv->bkey = NULL;
  if(map & 0x1){
    (*ctx)->root->str_nv->bkey = BN_new();
#ifdef MEMCHECK
  add_alloc(BKEY);
#endif
    if(!bn_decode(input, pos, (*ctx)->root->str_nv->bkey)) return 0;
  }
  if((map >> 1) & 0x1){
    (*ctx)->root->str_nv->member 
      = (STR_GM *)calloc(sizeof(STR_GM),1);
    if((*ctx)->root->str_nv->member == NULL)
    {ret=MALLOC_ERROR; goto error;}
    
    (*ctx)->root->str_nv->member->cert = NULL;
    (*ctx)->root->str_nv->member->member_name = 
      (CLQ_NAME *)calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
    if((*ctx)->root->str_nv->member->member_name == NULL)
    {ret=MALLOC_ERROR; goto error;}
    if(!string_decode(input, pos,
                      (*ctx)->root->str_nv->member->member_name))
      return 0; 
  }
  
  for(i=0; i<2 * (*ctx)->root->str_nv->num_user-2; i++){
    if(!int_decode(input, pos, &map)) return 0;
    if(!int_decode(input, pos, &tmp_index)) return 0;
    tmp_tree=str_search_index((*ctx)->root, tmp_index);
    if(tmp_tree == NULL) return 0;
    tmp_tree->str_nv->member = NULL;
    tmp1_tree = (STR_KEY_TREE *)calloc(sizeof(STR_KEY_TREE),1);
    
    tmp1_tree->parent = tmp_tree;
    if(tmp_index % 2)
      tmp_tree->right = tmp1_tree;
    else tmp_tree->left = tmp1_tree;
    tmp1_tree->str_nv = (STR_NV *)calloc(sizeof(STR_NV),1);
    tmp1_tree->str_nv->member = NULL;
    tmp1_tree->str_nv->key = tmp1_tree->str_nv->bkey = NULL;
    tmp1_tree->str_nv->index = tmp_index;
    tmp1_tree->left=tmp1_tree->right=NULL;
    tmp1_tree->prev=tmp1_tree->next=tmp1_tree->bfs=NULL;
    if(map & 0x1){
      tmp1_tree->str_nv->bkey = BN_new();
#ifdef MEMCHECK
  add_alloc(BKEY);
#endif
      if(!bn_decode(input, pos, tmp1_tree->str_nv->bkey)) return 0;
    }
    if((map >> 1) & 0x1){
      tmp1_tree->str_nv->member=(STR_GM *)calloc(sizeof(STR_GM),1);
      tmp1_tree->str_nv->member->member_name = 
        (CLQ_NAME *)calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1); 
      tmp1_tree->str_nv->member->cert=NULL;
      
      if(!string_decode(input, pos, tmp1_tree->str_nv->member->member_name))
        return 0; 
      tmp_tree = str_search_member(tmp1_tree, 0, NULL);
      tmp1_tree->prev = tmp_tree;
      if(tmp_tree != NULL) tmp_tree->next = tmp1_tree;
      tmp_tree = str_search_member(tmp1_tree, 1, NULL);
      tmp1_tree->next = tmp_tree;
      if(tmp_tree != NULL) tmp_tree->prev = tmp1_tree;
      tmp1_tree->bfs = NULL;
    }
  }
  
  error:
  if(ret != OK){
    if((*ctx)->root->str_nv->member != NULL){
      if((*ctx)->root->str_nv->member->member_name != NULL) 
        free((*ctx)->root->str_nv->member->member_name);
      free((*ctx)->root->str_nv->member);
    }
    if((*ctx)->root->str_nv != NULL) free((*ctx)->root->str_nv);
  }
  
  return ret;
}

/* str_create_token_info: It creates the info token. */
int str_create_token_info (STR_TOKEN_INFO **info, CLQ_NAME *group, 
                            enum STR_MSG_TYPE msg_type, time_t time,
                            CLQ_NAME *sender/*, uint epoch*/) 
{ 
  int ret=MALLOC_ERROR;
  
  /* Creating token information */
  (*info)=(STR_TOKEN_INFO *) calloc (sizeof(STR_TOKEN_INFO),1);
  if ((*info) == NULL) goto error;
  if (group != NULL) {
    (*info)->group_name
      =(CLQ_NAME *) calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
#ifdef MEMCHECK
    add_alloc(GN);
#endif
    if (((*info)->group_name) == NULL) goto error;
    strncpy ((*info)->group_name,group,MAX_LGT_NAME);
  } else (*info)->group_name=NULL;
  (*info)->message_type=msg_type;
  (*info)->time_stamp=time;
  if (sender != NULL) {
    (*info)->sender_name=(CLQ_NAME *)
      calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
#ifdef MEMCHECK
    add_alloc(SN);
#endif
    if (((*info)->sender_name) == NULL) goto error;
    strncpy ((*info)->sender_name,sender,MAX_LGT_NAME);
  }
  else (*info)->sender_name=NULL;

  /*  (*info)->epoch=epoch; */
  
  ret=OK;
error:
  if (ret != OK) str_destroy_token_info(info);

  return ret;
}

/* str_destroy_token: It frees the memory of the token. */
void str_destroy_token (CLQ_TOKEN **token) {
  if (*token !=(CLQ_TOKEN *) NULL) {
    if ((*token)->t_data != NULL) {
      free ((*token)->t_data);
      (*token)->t_data=NULL;
    }
    free(*token);
    *token=NULL;
  }
}

/* str_destroy_token_info: It frees the memory of the token. */
void str_destroy_token_info (STR_TOKEN_INFO **info) 
{
  
  if (info == NULL) return;
  if ((*info) == NULL) return;
  if ((*info)->group_name != NULL) {
    free ((*info)->group_name);
#ifdef MEMCHECK
    add_free(GN);
#endif
    (*info)->group_name =NULL;
  }
  if ((*info)->sender_name != NULL) {
    free ((*info)->sender_name);
#ifdef MEMCHECK
    add_free(SN);
#endif
    (*info)->sender_name=NULL;
  }
  free ((*info));
  *info = NULL;
  
}

/* str_merge_tree returns root of a new tree which is the result of
 *   merge of two trees
 */
STR_KEY_TREE *str_merge_tree(STR_KEY_TREE *joiner, STR_KEY_TREE *joinee)
{
  STR_KEY_TREE *tmp_tree=NULL, *tmp_tree1=NULL;
  
  if((joiner->parent != NULL) && (joinee->parent != NULL)) return NULL;
  
  tmp_tree = (STR_KEY_TREE *)calloc(sizeof(STR_KEY_TREE),1);
  if(tmp_tree == NULL) return NULL;
  
  /* setting up pointers for the new node */
  tmp_tree1        = str_search_member(joiner, 2, NULL);
  tmp_tree->parent = tmp_tree1;
  tmp_tree->left   = NULL;
  tmp_tree->right  = NULL;
  if(joinee->right){
    tmp_tree->prev   = joinee->right;
  }
  else{
    tmp_tree->prev = joinee;
  }
  if(tmp_tree1->parent != NULL){
    tmp_tree->next   = tmp_tree1->parent->right;
  }
  else{
    tmp_tree->next = NULL;
  }
  tmp_tree->bfs = NULL;
  joinee->parent      = tmp_tree1;
  if(joinee->right){
    joinee->right->next = tmp_tree;
  }
  else{
    joinee->next = tmp_tree;
  }
  tmp_tree1->left     = joinee;
  tmp_tree1->right    = tmp_tree;
  if(tmp_tree1->parent){
    tmp_tree1->parent->right->prev = tmp_tree;
  }
  
  /* Now, real values for the tmp_tree */
  tmp_tree->str_nv=(STR_NV *)calloc(sizeof(STR_NV),1);
  str_copy_node(tmp_tree1, tmp_tree);
  tmp_tree->str_nv->index = tmp_tree->str_nv->index + 3;

  if(tmp_tree1->left){
    str_update_index(tmp_tree1->left, 0, tmp_tree1->str_nv->index);  
    str_update_index(tmp_tree1->right, 1, tmp_tree1->str_nv->index);
  }

  return joiner;
}


/* str_search_member: returns the pointer of the previous or the next
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
STR_KEY_TREE *str_search_member(STR_KEY_TREE *tree, int option, 
				CLQ_NAME *member_name )
{
  STR_KEY_TREE *tmp_tree;
  int min_node=100000;
  CLQ_NAME *the_name=NULL;
  
  tmp_tree = tree;
  
  if(member_name == NULL){
    switch (option) {
      case 0: 
        if(tree->str_nv->member == NULL) return NULL;
        if(tree->str_nv->member->member_name == NULL) return NULL;
        if(tmp_tree->parent == NULL) return NULL;
        if(tmp_tree->parent->left == NULL) return NULL;
        while(tmp_tree->parent->left == tmp_tree){
          tmp_tree = tmp_tree->parent;
          if(tmp_tree->parent == NULL) return NULL;
        }
        tmp_tree = tmp_tree->parent->left;
        while(tmp_tree->str_nv->member == NULL){
          if(tmp_tree->right == NULL) return NULL;
          tmp_tree = tmp_tree->right; 
        }
        if(tmp_tree->str_nv->member->member_name == NULL) return NULL;
        return tmp_tree;
      case 1:
        if(tree->str_nv->member == NULL) return NULL;
        if(tree->str_nv->member->member_name == NULL) return NULL;
        if(tmp_tree->parent == NULL) return NULL;
        if(tmp_tree->parent->right == NULL) return NULL;
        while(tmp_tree->parent->right == tmp_tree){
          tmp_tree = tmp_tree->parent;
          if(tmp_tree->parent == NULL) return NULL;
        }
        tmp_tree = tmp_tree->parent->right;
        while(tmp_tree->str_nv->member == NULL){
          if(tmp_tree->left == NULL) return NULL;
          tmp_tree = tmp_tree->left;
        }
        if(tmp_tree->str_nv->member->member_name == NULL) return NULL;
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
        tmp_tree = str_search_member(tmp_tree, 2, NULL);
        while(tmp_tree->next != NULL){
          if(tmp_tree->str_nv->index < min_node){
            min_node = tmp_tree->str_nv->index;
            the_name = tmp_tree->str_nv->member->member_name;
          }
          tmp_tree = tmp_tree->next;
        }
        tmp_tree = str_search_member(tmp_tree, 5, NULL);
        tmp_tree = str_search_member(tmp_tree, 4, the_name);
        if(tmp_tree == NULL){
          fprintf(stderr, "What happened???????\n");
        }
        return tmp_tree;
      default:
        return NULL;
    }
  }
  else{
    if(option==4){
      if(tmp_tree->left == NULL){
        if(strcmp(tmp_tree->str_nv->member->member_name,member_name)==0){
          return tmp_tree;
        }
      }
      tmp_tree = str_search_member(tree, 2, NULL);
      if(tmp_tree == NULL) return NULL;
      
      while(strcmp(tmp_tree->str_nv->member->member_name,
                   member_name)!=0 ){
        if(tmp_tree->next == NULL) return NULL;
        tmp_tree = tmp_tree->next;
      }
      return tmp_tree;
    }
  }
  return NULL;
}

/* str_search_index: Returns the node having the index as a child 
 *   index should be greater than 1
 */
STR_KEY_TREE *str_search_index(STR_KEY_TREE *tree, int index)
{
  int height=0;
  int i;
  STR_KEY_TREE *tmp_tree;
  
  height = index/2;
  
  tmp_tree = tree;
  
  if(index==1) return NULL;
  
  for(i=1; i<height; i++){
     tmp_tree = tmp_tree->left;
  }
  
  return tmp_tree;
}

/* str_update_index: update index of the input tree by 1
 * index 0 is for the left node
 * index 1 is for the right node
 */
void str_update_index(STR_KEY_TREE *tree, int index, int root_index) 
{
  if(tree == NULL) return;

  if(root_index == 1){
    tree->str_nv->index = root_index * 2 + index;
  }
  else{
    tree->str_nv->index = root_index + 2 + index;
  }

  str_update_index(tree->left, 0, tree->str_nv->index);
  str_update_index(tree->right, 1, tree->str_nv->index);
}

/* Frees a STR_TREE structure */
void str_free_tree(STR_KEY_TREE **tree) {
  
  if(tree == NULL) return;
  if((*tree) == NULL) return;

  if((*tree)->left != NULL)
    str_free_tree(&((*tree)->left));
  if((*tree)->right != NULL)
    str_free_tree(&((*tree)->right));
  
  str_free_node(&(*tree));
}

/* Frees a NODE structure */
void str_free_node(STR_KEY_TREE **tree) {

  if(tree == NULL) return;
  if((*tree) == NULL) return;
  
  if((*tree)->str_nv != NULL){
    str_free_nv(&((*tree)->str_nv));
    (*tree)->str_nv = NULL;
  }
  
  free((*tree));
  
  (*tree)=NULL;
}

/* Frees a STR_NV structure */
void str_free_nv(STR_NV **nv) {
  if (nv == NULL) return;
  if ((*nv) == NULL) return;
  if((*nv)->member != NULL){
    str_free_gm(&((*nv)->member));
    (*nv)->member=NULL;
  }
  
  if ((*nv)->key != NULL){
    BN_clear_free((*nv)->key);
#ifdef MEMCHECK
    add_free(KEY);
#endif
  }
  
  if ((*nv)->bkey != NULL){
    BN_clear_free((*nv)->bkey);
#ifdef MEMCHECK
    add_free(BKEY);
#endif
  }
  
  free((*nv));
  (*nv)=NULL;
}

/* Frees a STR_GM structure */
void str_free_gm(STR_GM **gm) {
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


/* str_copy tree structure, but to finish the real copy, we need to
   call str_dup_tree, which finishes prev and next pointer */  
STR_KEY_TREE *str_copy_tree(STR_KEY_TREE *src)
{
  STR_KEY_TREE *dst=NULL;
  
  if(src != NULL){
    dst = (STR_KEY_TREE *) calloc(sizeof(STR_KEY_TREE), 1);
    if(src->str_nv != NULL){
      dst->str_nv = (STR_NV *) calloc(sizeof(STR_NV), 1);
      dst->str_nv->index = src->str_nv->index;
      dst->str_nv->num_user=src->str_nv->num_user;
      if(src->str_nv->key != NULL){
        dst->str_nv->key = BN_dup(src->str_nv->key);
      }
      if(src->str_nv->bkey != NULL){
        dst->str_nv->bkey = BN_dup(src->str_nv->bkey);
      }
      if(src->str_nv->member != NULL){
        dst->str_nv->member = (STR_GM *) calloc(sizeof(STR_GM),1);
        if(src->str_nv->member->member_name != NULL){
          dst->str_nv->member->member_name=(CLQ_NAME *)
            calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
          strncpy (dst->str_nv->member->member_name,
                   src->str_nv->member->member_name,MAX_LGT_NAME);
        }
        if(src->str_nv->member->cert != NULL){
          dst->str_nv->member->cert = X509_dup(src->str_nv->member->cert);
        }
      }
    }
    dst->left = str_copy_tree(src->left);
    dst->right = str_copy_tree(src->right);
    if(dst->left) {
      dst->left->parent = dst;
    }
    if(dst->right) {
      dst->right->parent = dst;
    }
  }

  return dst;
}

/* str_dup_tree finishes the copy process of one tree to
   another... Mainly, it just handles prev and next pointer */
STR_KEY_TREE *str_dup_tree(STR_KEY_TREE *src)
{
  STR_KEY_TREE *dst=NULL;
  STR_KEY_TREE *tmp1_src=NULL, *tmp1_dst=NULL;
  STR_KEY_TREE *tmp2_src=NULL, *tmp2_dst=NULL;

  dst = str_copy_tree(src);
  if(src != NULL){
    tmp1_src = str_search_member(src, 2, NULL);
    tmp2_src = tmp1_src->next;
    tmp1_dst = str_search_member(dst, 4,
                                  tmp1_src->str_nv->member->member_name);
    while(tmp2_src != NULL){
      tmp2_dst = str_search_member(tmp1_dst, 1, NULL);
      tmp1_dst->next = tmp2_dst;
      tmp2_dst->prev = tmp1_dst;
      tmp2_src = tmp2_src->next;
      tmp1_src = tmp1_src->next;
      tmp1_dst = tmp2_dst;
    }
  }

  return dst;
}

/* str_copy_node copies or changes str_nv values of src node to dst
   node */  
void str_copy_node(STR_KEY_TREE *src, STR_KEY_TREE *dst)
{
  if(src->str_nv != NULL){
    dst->str_nv->index = src->str_nv->index;
    dst->str_nv->num_user=src->str_nv->num_user;
    if(src->str_nv->key != NULL){
      clq_swap((void *)&(src->str_nv->key),(void *)&(dst->str_nv->key));
    }
    if(src->str_nv->bkey != NULL){
      clq_swap((void *)&(src->str_nv->bkey),(void *)&(dst->str_nv->bkey));
    }
    if(src->str_nv->member != NULL){
      clq_swap((void *)&(src->str_nv->member), (void *)&(dst->str_nv->member));
    }
  }
}

/* str_swap_bkey swap my null bkey with meaningful bkey from new token */
void str_swap_bkey(STR_KEY_TREE *src, STR_KEY_TREE *dst) 
{
  if(src->left != NULL){
    str_swap_bkey(src->left, dst->left);
    str_swap_bkey(src->right, dst->right);
  }
  if(src != NULL){
    if(src->str_nv->bkey != NULL){
      if(dst->str_nv->bkey == NULL){
        clq_swap((void *)&(src->str_nv->bkey),(void *)&(dst->str_nv->bkey));
      }
    }
  }
}

/* str_copy_bkey copies meaningful bkey from new token to my null
   token, used for cache update */
void str_copy_bkey(STR_KEY_TREE *src, STR_KEY_TREE *dst) 
{
  if(src->left != NULL){
    str_copy_bkey(src->left, dst->left);
    str_copy_bkey(src->right, dst->right);
  }
  if(src != NULL){
    if(src->str_nv->bkey != NULL){
      if(dst->str_nv->bkey == NULL){
        dst->str_nv->bkey = BN_dup(src->str_nv->bkey);
      }
    }
  }
}

/* str_check_useful checks whether new_ctx has useful information
 * If it has, return 1,
 * else, return 0
 */
int str_check_useful(STR_KEY_TREE *newtree, STR_KEY_TREE *mytree) 
{
  STR_KEY_TREE *head_new=NULL, *tail_new=NULL;
  STR_KEY_TREE *head_my=NULL, *tail_my=NULL;

  head_new=tail_new=newtree;
  head_my=tail_my=mytree;

  str_init_bfs(newtree);
  str_init_bfs(mytree); 
  
  while(head_new != NULL){
    if((head_new->str_nv->bkey!=NULL)&&(head_my->str_nv->bkey==NULL)){
      return 1;
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
  str_init_bfs(newtree);
  str_init_bfs(mytree); 

  return 0;
}

/* str_init_bfs initializes(nullfies) bfs pointers for each node */
void str_init_bfs(STR_KEY_TREE *tree)
{
  if(tree != NULL){
    if(tree->left){
      str_init_bfs(tree->left);
      str_init_bfs(tree->right);
    }
    if(tree != NULL){
      tree->bfs = NULL;
    }
  }
}

/* remove_sponsor: remove the sponsor from the sponsor list */
int str_remove_sponsor(CLQ_NAME *sponsor_list[], CLQ_NAME *sponsor)
{
  int i=0, j=0;
  int find = 0;

  if(sponsor_list[0] == NULL) {
    return -1;
  }
  
  for(i=0; i<NUM_USERS+1; i++){
    if(sponsor_list[i] != NULL){
      if(strcmp(sponsor_list[i], sponsor)==0){
        find = 1;
        break;
      }
    }
  }
  for(j=i; j<NUM_USERS-1; j++){
    if(sponsor_list[j] != NULL){
      sponsor_list[j] = sponsor_list[j+1];
    }
  }

  if(find){
    return 1;
  }
  else{
    return -1;
  }
}

/* Make a tree list for merge */
STR_TREE_LIST *str_add_tree_list(STR_TREE_LIST *list, STR_KEY_TREE *tree) 
{
  STR_TREE_LIST *tmp_list=NULL, *tmp1_list=NULL, *tmp2_list=NULL;
  STR_TREE_LIST *head=NULL; 
  STR_KEY_TREE *tmp_tree=NULL, *tmp1_tree=NULL;

  head = list;
  tmp_tree = str_search_member(tree, 3, NULL);

  if(tree == NULL) return NULL;
  
  if(list == NULL){
    list = (STR_TREE_LIST *) calloc(sizeof(STR_TREE_LIST), 1);
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
    tmp_list = (STR_TREE_LIST *) calloc(sizeof(STR_TREE_LIST), 1);
    tmp_list->tree = tree;

    tmp1_list = head;
    while(tmp1_list != NULL){
      tmp1_tree = str_search_member(tmp1_list->tree, 3, NULL);
      if(tmp1_list->tree->str_nv->num_user <
         tmp_list->tree->str_nv->num_user){
        break;
      }
      else if((tmp1_list->tree->str_nv->num_user ==
               tmp_list->tree->str_nv->num_user) &&
              (strcmp(tmp1_tree->str_nv->member->member_name,
                      tmp_tree->str_nv->member->member_name) < 0)){
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

/* Remove all tree list */
void STR_remove_tree_list(STR_TREE_LIST **list)
{
  STR_TREE_LIST *tmp_list=NULL;

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
