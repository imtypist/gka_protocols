/*********************************************************************
 * clq_merge.c                                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <malloc.h>
#include <memory.h>

/* SSL include files */
#include "openssl/bn.h"

/* CLQ_API include files */
#include "clq_api.h"
#include "clq_merge.h"
#include "error.h"
#include "common.h"
#include "ckd_api.h" /* Needed it because of ckd_compute_user_key */

#include "clq_sig.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/* clq_update_key is called by every new user (who are part of the
 * merge operation) and the group controller. If the group controller
 * is the one calling this function then member_list will be
 * valid. Otherwise, for every other user input token will be valid (and
 * member_list will be NULL.
 * The last new member calling this function will not add his/her
 * key_share.
 * member_list has to be NULL terminated. Moreover, if a user already
 * exist in the group then he/she will not be added to the
 * group_member_list.
 * last_partial_keys of old members in the group remain in the context
 * of the current controller, but they will not be encoded in the
 * token.
 */
int clq_update_key (CLQ_CONTEXT *ctx, CLQ_NAME *member_list[], 
                    CLQ_TOKEN *input, CLQ_TOKEN **output) 
{
  int ret;
  int i;
  BN_CTX *bn_ctx= BN_CTX_new();
  CLQ_CONTEXT *new_ctx=NULL;
  CLQ_TOKEN_INFO *info=NULL;
  CLQ_GML *gml=NULL;
  int last_new_user=FALSE;
  CLQ_SIGN *sign=NULL;

  /* Doing some error checkings */
  if (ctx == (CLQ_CONTEXT *) NULL) return CTX_ERROR;
  if (bn_ctx == (BN_CTX*)NULL) {ret=MALLOC_ERROR; goto error;}
  /* Only one of input token or member_list can be valid. The other
   * has to be invalid.
   */
  if (((input == (CLQ_TOKEN*) NULL) && (member_list == NULL)) ||
      ((input != (CLQ_TOKEN*) NULL) && (member_list != NULL)))
    { ret= INVALID_PARAM; goto error; }

  /* The following is need it for old group members in case they call
   * this function.
   */
  if (ctx->me != NULL)
    if (ctx->me != ctx->last) return NOT_CONTROLLER;
  /* Error checkings done */

  /* If I am the current controller then add new users to the
   * group_members_list.
   */
  if ((ctx->me == ctx->last) && (ctx->me != (CLQ_GML*)NULL)){
    /* I am the current controller */
    if (member_list == NULL) { ret=LIST_EMPTY; goto error; }
    if (ctx->key_share == (BIGNUM *) NULL) { ret=CTX_ERROR;  goto error;}
    if (ctx->last != ctx->me) { ret=NOT_CONTROLLER; goto error;}

    /* Adding new users to the group_members_list */
    i=0;
    gml=ctx->last;
    if (gml == (CLQ_GML *)NULL) {ret=CTX_ERROR; goto error;}
    while ((member_list[i]!=NULL) && (i < MAX_LIST)) {
      if (strlen(member_list[i])>MAX_LGT_NAME)
      {ret=INVALID_LGT_NAME; goto error; }
      /* The new user shouldn't be in the group */
      if (clq_search_gml(ctx->first,member_list[i])==NULL) {
        gml->next=(CLQ_GML *) malloc(sizeof(CLQ_GML));
        if (gml->next == (CLQ_GML *)NULL) {ret=MALLOC_ERROR; goto error;}
        gml->next->prev=gml;
        gml=gml->next;
        gml->next=NULL;
        gml->member=(CLQ_GM *) malloc(sizeof(CLQ_GM));
        if (gml->member == (CLQ_GM *) NULL) {ret=MALLOC_ERROR; goto error;}
        /* Using BN_new doesn't work because the size is 0  */
        gml->member->last_partial_key=BN_dup(BN_value_one()); /* One
                                                                 by
                                                                 default */
        gml->member->cert=NULL;
        gml->member->member_name=(CLQ_NAME *)
          malloc(sizeof(CLQ_NAME)*MAX_LGT_NAME);
        if (gml->member->member_name==NULL) {ret=MALLOC_ERROR; goto error;}
        strcpy (gml->member->member_name,member_list[i]);
      }
      i++;
    }
    ctx->last=gml;
    BN_clear_free (ctx->key_share);
    ctx->key_share=NULL;
    /* Generating token */
    ret= clq_create_token_info (&info, ctx->group_name, MASS_JOIN, 
                                time(0), ctx->member_name); 
    if (ret != OK) goto error;
  }
  /* Every other user who is not the current controller */
  else {
    ret=clq_remove_sign(input,&sign);
    if (ret != OK) goto error;
    
    if (input == (CLQ_TOKEN*) NULL) { ret= INVALID_INPUT_TOKEN; goto error;}
    if ((ret=clq_decode(&new_ctx, input, &info))!=OK) goto error;
    if (strcmp (info->group_name,ctx->group_name)) 
    { ret=GROUP_NAME_MISMATCH; goto error; }
    if (info->message_type != MASS_JOIN) 
    { ret=INVALID_MESSAGE_TYPE; goto error; }
    /* Setting me, last and first */
    gml=clq_search_gml(new_ctx->group_members_list,ctx->member_name);
    if (gml==(CLQ_GML*)NULL) {ret=MEMBER_NOT_IN_GROUP; goto error; }
    ctx->me=gml;
    ctx->group_members_list=ctx->first=new_ctx->group_members_list;
    /* clq_decode sets ctx->last  ! */
    ctx->last=new_ctx->last;
    ctx->controller=ctx->last;
    new_ctx->group_members_list=NULL;
    /* Updating token information */
    info->time_stamp=time(0);
    strcpy (info->sender_name,ctx->member_name);
    /* I am the last new user */
    
    ret=clq_vrfy_sign (ctx, input,
                       ctx->me->prev->member->member_name, sign); 
    if(ret!=OK) goto error;
    
    ctx->epoch = new_ctx->epoch;
    if (ctx->me==ctx->last) {
      last_new_user=TRUE;
      info->message_type=MERGE_BROADCAST;
    }
    else 
      info->message_type=MASS_JOIN;
  }

  /* Every user but the last one has to contribute a new key_share. */
  if (ctx->key_share != (BIGNUM*)NULL)
    {ret=CTX_ERROR; goto error; }
  ctx->key_share= clq_grt_rnd_val (ctx->params);
  if (ctx->key_share == (BIGNUM *) NULL) {ret= MALLOC_ERROR; goto error;}
  /* Contributing with new key_share and placing it in next member
   * last_partial_key location.
   */
  if (!last_new_user) {
    if (!BN_is_one(ctx->me->next->member->last_partial_key))
      {ret=CTX_ERROR; goto error; }
    /* BN_copy needs first arg to be initialized (BN_new). */
    BN_copy(ctx->me->next->member->last_partial_key,
            ctx->me->member->last_partial_key); 
    BN_mod_exp (ctx->me->next->member->last_partial_key,
                ctx->me->next->member->last_partial_key, ctx->key_share,
                DSA_get0_p(ctx->params), bn_ctx);
  }
  clq_destroy_token(output);

  ret= clq_encode (ctx, output, info);
  if(ret!=OK) goto error;

  /* sign_message */
  ret=clq_sign_message (ctx, *output);

error:
  if (sign!=NULL)
    ret=clq_restore_sign(input,&sign);

  if (bn_ctx != (BN_CTX*) NULL) BN_CTX_free (bn_ctx); 
  if (new_ctx != (CLQ_CONTEXT*) NULL) clq_destroy_ctx(&new_ctx);
  if (info != (CLQ_TOKEN_INFO*)NULL) clq_destroy_token_info (&info);

  return ret;
}

/* clq_factor_out is called by every member in the group except by the
 * last new member upon recepction of a MERGE_BROADCAST
 * message. Although the last new member doesn't have to called this
 * function because he/she is the one that generates that message, if
 * he/she does then the function will return (no side effects will
 * occur). But output will be NULL.
 * During this operation ctx is modified to reflect the new controller
 * and new group members in the group. Also ctx->epoch is updated.
 */
int clq_factor_out (CLQ_CONTEXT *ctx, CLQ_TOKEN *input, 
                    CLQ_TOKEN **output) {
  int ret= OK;
  BIGNUM *inv_key_share= NULL;
  BN_CTX *bn_ctx= BN_CTX_new();  
  CLQ_CONTEXT *new_ctx= NULL;
  CLQ_TOKEN_INFO *info=NULL;
  CLQ_GML *gml;
  CLQ_SIGN *sign=NULL;

  clq_destroy_token (output);

  /* Checking for errors */
  if (ctx == (CLQ_CONTEXT *)NULL) {ret= CTX_ERROR; goto error;}
  if (bn_ctx == (BN_CTX*) NULL) {ret=MALLOC_ERROR; goto error;}
  if (ctx->me==ctx->last) {ret=OK; goto error;} 

  ret=clq_remove_sign(input,&sign);
  if (ret != OK) goto error;

  /* Decoding */
  if ((ret=clq_decode (&new_ctx, input, &info))!=OK) goto error;

  if (strcmp (info->group_name,ctx->group_name))
    {ret=GROUP_NAME_MISMATCH; goto error;}
  if (info->message_type != MERGE_BROADCAST) 	
    {ret= INVALID_MESSAGE_TYPE; goto error;}
  if (strcmp (info->sender_name, new_ctx->last->member->member_name))
    {ret= SENDER_NOT_CONTROLLER; goto error;} 
  if (ctx->epoch != new_ctx->epoch)
    {ret=UNSYNC_EPOCH; goto error;}
  /* Done with error checkings */

  /* Updating the group member list */
  ret=clq_gml_update (ctx,new_ctx,info->message_type);
  if (ret != OK) goto error;

  /* Factor out from last user partial key */
  inv_key_share= BN_mod_inverse (inv_key_share, ctx->key_share, 
                                 DSA_get0_q(ctx->params), bn_ctx); 

  /* Updating token information */
  info->time_stamp=time(0);
  strcpy (info->sender_name,ctx->member_name);
  info->message_type=MERGE_FACTOR_OUT;

  new_ctx->epoch=ctx->epoch;

  /* Saving time and memory doing it this way. */
  new_ctx->group_name=ctx->group_name;
  new_ctx->member_name=ctx->member_name;
  gml=(CLQ_GML *) malloc(sizeof(CLQ_GML));
  if (gml == (CLQ_GML *) NULL) goto error;
  gml->member=(CLQ_GM *) malloc(sizeof(CLQ_GM));
  if (gml->member == (CLQ_GM *) NULL) {ret=MALLOC_ERROR; goto error;}
  gml->member->member_name=(CLQ_NAME *)
    malloc(sizeof(CLQ_NAME)*MAX_LGT_NAME);
  if ((gml->member->member_name) == NULL) { ret=MALLOC_ERROR; goto error;}
  strcpy(gml->member->member_name,ctx->member_name);
  gml->member->last_partial_key=BN_new();
  if (gml->member->last_partial_key == NULL) { ret= MALLOC_ERROR; goto error;}
  BN_mod_exp (gml->member->last_partial_key, 
	      ctx->last->member->last_partial_key, 
	      inv_key_share, DSA_get0_p(ctx->params), bn_ctx);
  gml->prev=gml->next=NULL;
  gml->member->cert=NULL;
  new_ctx->group_members_list=new_ctx->first=gml;
 
  ret=clq_vrfy_sign (ctx, input,
		     ctx->last->member->member_name, sign); 
  if (ret!=OK) goto error;

  if ((ret= clq_encode (new_ctx, output, info))!=OK) goto error;

  /* sign_message */
  ret=clq_sign_message (ctx, *output);

  new_ctx->group_name=new_ctx->member_name=NULL;

error:
  clq_restore_sign(input,&sign);
  clq_destroy_ctx (&new_ctx);
  clq_destroy_token_info (&info);
  if (bn_ctx != (BN_CTX*) NULL) BN_CTX_free (bn_ctx); 

  return ret;
}

/* clq_last_step: The last step of the merge operation or of an ckd
 * event. The controller upon reception of the indiviual
 * (FACTOR_OUT or CKD_INDIVIDUAL_SHARE) messages should call this 
 * function. After he/she receives all the messages, an output token
 * will be generated. This token should be broadcasted to the entire
 * group.
 */
int clq_last_step (CLQ_CONTEXT *ctx, CLQ_NAME *sender_name, 
                   CLQ_TOKEN *input, CLQ_TOKEN **output, 
                   enum CLQ_OPER oper) {
  static CLQ_NAME *last_ctlr=NULL;
  static CLQ_GML *static_gml=NULL;
  int first_time=TRUE; /* Used only if oper == CKD_GENERATE_KEY */
  int ret=OK;
  CLQ_CONTEXT *new_ctx= NULL;
  CLQ_TOKEN_INFO *info=NULL;
  CLQ_GML *gml=NULL;
  BN_CTX *bn_ctx= BN_CTX_new();
  CLQ_SIGN *sign=NULL;

  /* Check errors */
  if ((ctx == (CLQ_CONTEXT *) NULL)) return CTX_ERROR;
  if (sender_name == NULL) return INVALID_MEMBER_NAME;
  if ((strlen(sender_name) == 0) ||
      (strlen(sender_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  if (input == (CLQ_TOKEN*) NULL) return INVALID_INPUT_TOKEN;
  if (oper == CLQ_MERGE) {
    if (ctx->me != ctx->last) return NOT_CONTROLLER;
  }
  else if (oper == CKD_GENERATE_KEY) {
    if (ctx->me != ctx->controller) return NOT_CONTROLLER;
  }
  else return INVALID_PARAM;

  ret=clq_remove_sign(input,&sign);
  /* Decoding token */
  ret= clq_decode (&new_ctx, input, &info);
  if (ret != OK) goto error;
  if (!(((oper == CLQ_MERGE) && 
         (info->message_type == MERGE_FACTOR_OUT)) ||
        ((oper == CKD_GENERATE_KEY) && 
         (info->message_type == CKD_INDIVIDUAL_SHARE))))
  { ret= INVALID_MESSAGE_TYPE; goto error; }
  if (strcmp(info->group_name, ctx->group_name))
  { ret= GROUP_NAME_MISMATCH; goto error; }
  if (new_ctx->epoch != ctx->epoch) { ret=UNSYNC_EPOCH; goto error; }
  /* The group_members_list (in new_ctx) should have only one field */
  if ((new_ctx->first == (CLQ_GML*) NULL) ||
      (new_ctx->first != new_ctx->last))
  { ret=INVALID_INPUT_TOKEN; goto error; }
  if (new_ctx->first->member == (CLQ_GM*) NULL)
  { ret=INVALID_INPUT_TOKEN; goto error; }
  if ((strcmp(sender_name,info->sender_name)) ||
      (strcmp(sender_name,new_ctx->first->member->member_name)))
  { ret=MEMBER_NAME_MISMATCH; goto error; }
  /* Done with error checkings */
  
  if (oper == CKD_GENERATE_KEY) {
    if (last_ctlr==(CLQ_NAME*) NULL) 
      last_ctlr=(CLQ_NAME *) malloc(sizeof(CLQ_NAME)*MAX_LGT_NAME);
    first_time = strcmp(last_ctlr,ctx->member_name) == 0 ? FALSE : TRUE;
    if (first_time) {
      if (memcpy (last_ctlr,ctx->member_name,MAX_LGT_NAME)==NULL) 
      {ret=MALLOC_ERROR; goto error; }
      /* printf ("USER %s\n", last_ctlr); */
      static_gml=NULL; /* Just in case ! */
    }
  }

  /* First time this function is called */
  if ((first_time && (oper == CKD_GENERATE_KEY)) ||
      (oper == CLQ_MERGE)) {
    first_time=FALSE;
    if (static_gml== (CLQ_GML*) NULL) {
      /* The next line can be removed once ctx->controller is working
         in cliques */
      if (oper == CLQ_MERGE) ctx->controller = ctx->last;
      ret=clq_create_name_list(ctx,&static_gml,TRUE);
      if (ret!=OK) goto error;
      if (ctx->group_secret == NULL) {ret=CTX_ERROR; goto error;}
    }
  }
  /* static_gml has been created already. Then let's place the
   * last_partial_key of the sender 
   */
  
  /* Updating last_partial_key */
  gml=clq_search_gml(ctx->first,sender_name);
  if (gml==NULL) {ret=CTX_ERROR; goto error;}
  /* last_partial_key of a user should be set only once */
  if (!BN_is_zero(gml->member->last_partial_key)) 
    { ret=INVALID_INPUT_TOKEN; goto error;}
  BN_clear_free(gml->member->last_partial_key);

  /* Last member's last partial key has to be modified to session key */
  if (oper==CKD_GENERATE_KEY){
    gml->member->last_partial_key=BN_new();
    ret = BN_mod_exp(gml->member->last_partial_key,
                     new_ctx->first->member->last_partial_key,
                     ctx->key_share, DSA_get0_p(ctx->params), bn_ctx);
  }
  else {
    gml->member->last_partial_key =
      new_ctx->first->member->last_partial_key;
  }
  new_ctx->first->member->last_partial_key=NULL;

  /* Updating static_gml */
  if (static_gml != NULL) {
    gml=clq_search_gml(static_gml,sender_name);
    if (gml==NULL) {ret=CTX_ERROR; goto error;}
    /* Removing member from static_gml */
    if (gml->next != NULL) 
      gml->next->prev=gml->prev;
    if (gml->prev != NULL)
      gml->prev->next=gml->next;
    else
      static_gml=gml->next;

    /* Since we don't want to free the data because it is in the
     * actual ctx->group_memeber_list, then free is used instead of
     * clq_free_gml.
     */
    gml->prev=gml->next=NULL;
    free(gml);
    gml=NULL; /* In case something still points here */

    /* Am I the last one in the list ? */
    if ((static_gml->prev == NULL) && (static_gml->next == NULL)) {
      free(static_gml); 
      static_gml=NULL;
    }
  }
  ret=clq_vrfy_sign (ctx, input, sender_name, sign);
  if(ret!=OK) goto error;

  /* I recevied a token from every user, hence I need to generate an
   * output token with a fresh key.
   */
  if (static_gml == NULL) {
    clq_destroy_token(output);
    /* Updating token info */
    info->time_stamp=time(0);
    strcpy (info->sender_name,ctx->member_name);

    if (oper == CLQ_MERGE) {
      if ((ret=clq_creat_new_key (ctx, TRUE))!=OK) goto error;
      info->message_type=KEY_MERGE_UPDATE;
      ret= clq_encode(ctx, output, info);
      if (ret!=OK) goto error;

      ret=clq_sign_message (ctx, *output);

    }
    else { /* if CKD -> Encrypting session key for every user */
      ret=ckd_compute_session_key (ctx,output);
      if (ret!=OK) goto error;
    }
  }

error:

  ret=clq_restore_sign(input,&sign);

  if (bn_ctx != (BN_CTX*) NULL) BN_CTX_free (bn_ctx); 
  if (new_ctx != (CLQ_CONTEXT*) NULL) clq_destroy_ctx (&new_ctx);
  clq_destroy_token_info (&info);
  if (ret!=OK) clq_destroy_token (output);

  return ret;
}

/* clq_get_next_username used after clq_update_key to get the name of the
 * user to send the message. 
 * Preconditions: ctx->me->next has to be valid (i.e. not NULL)
 */
CLQ_NAME *clq_get_next_username(CLQ_CONTEXT *ctx) {
  static CLQ_NAME name[MAX_LGT_NAME];

  if (ctx->me == ctx->last) return NULL;

  strcpy (name,ctx->me->next->member->member_name);

  return name;
}

/* Preconditions: ctx->last has to be valid (i.e. not NULL) */
CLQ_NAME *clq_get_controller_name (CLQ_CONTEXT *ctx) {
  static CLQ_NAME name[MAX_LGT_NAME];

  strcpy (name,ctx->last->member->member_name);

  return name;
}
