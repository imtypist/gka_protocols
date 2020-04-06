/*********************************************************************
 * ckd_api.c                                                         * 
 * Centralized Key Distribution  api source file.                    * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>

/* SSL include files */
#include "openssl/bn.h"
#include "openssl/bio.h"
#include "openssl/md5.h"
#include "openssl/err.h"
#include "openssl/dsa.h"

/* CLQ_API include files */
#include "clq_api.h"
#include "error.h"

/* CKD_API include files */
#include "ckd_api.h"

/* If SIGNATURE is defined: Default */
#include "clq_sig.h"
#include "common.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/* ckd_proc_event: Every user depending on the event (join/leave) will
 * update the group_member_list. This is necessary since any member
 * can become the controller at "any" time. Basically, every user has
 * to have the same view of the group at the same time. Hence, if the
 * controller dies any member can become the new one (knowing who the
 * member of the groups are.)  
 *
 * Finally if the controller is the one calling this function an
 * output token will be generated which includes his/her "new" short
 * term key. The short term key is new if this user will become the
 * new controller.
 *
 * Note: If member_name does not belong to the group then nothing occurs.
 *
 * IMPORTANT: msg_type can return three possible values
 * CKD_NEW_KEY_SHARE, CKD_NEW_KEY_SHARE or CKD_NEW_SESSION_KEY. If
 * CKD_NEW_SESSION_KEY is returned then every user should call
 * ckd_get_session, otherwise they should call ckd_comp_new_share upon
 * reception of the token.
 * This happens when a member (not the controller) leaves the group
 * and the only key that needs to be updated is the session one.
 * It is done this way in order to optimize communication between users.
 */
int ckd_proc_event (CKD_CONTEXT **Ctx, CLQ_NAME *member_name, enum CKD_EVENT
                    event, enum MSG_TYPE *msg_type, CLQ_TOKEN **output) {
  int ret=OK;
  CLQ_GML *gml=NULL;
  int new_cntlr=FALSE;
  CLQ_CONTEXT *ctx=*Ctx;
  
  /* Checking for errors */
  if (ctx == (CKD_CONTEXT *) NULL) return CTX_ERROR;
  if (member_name == (CLQ_NAME *) NULL) return INVALID_MEMBER_NAME;
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  /* Done with error checkings */
  
  /* Looking for member and updating the group_member_list */
  /* If join -> adding member to the end of the group_member_list */
  if (event == CKD_JOIN) {
    gml=clq_search_gml(ctx->first,member_name);
    if (gml != NULL) { ret=MEMBER_IS_IN_GROUP; goto error;}
    
    gml=ctx->last;
    if (gml == (CLQ_GML*) NULL) { ret=CTX_ERROR; goto error;}
    gml->next=clq_create_gml(member_name);
    gml=gml->next;
    if (gml == (CLQ_GML*) NULL) { ret=MALLOC_ERROR; goto error;}
    if ((gml->member->last_partial_key=BN_new()) == NULL)
      { ret=MALLOC_ERROR; goto error;}
    
    gml->prev=ctx->last;
    ctx->last=gml;
    
    if ((ctx->controller == ctx->me) && 
        (BN_is_one(ctx->key_share))) {
      /* Generetaing my first key_share */
      if ((ret=ckd_create_share(ctx)) != OK) goto error;
      new_cntlr = TRUE;
    }
  }
  /* If leave -> removing member from group_member_list */
  else if (event == CKD_LEAVE) {
    gml=clq_search_gml(ctx->first,member_name);
    if (gml == (CLQ_GML*) NULL) { ret=MEMBER_NOT_IN_GROUP; goto error;}
    
    /* If I am leaving and I call this func. then destroy my ctx */
    if (ctx->me == gml) { clq_destroy_ctx (Ctx); goto error; }
    if (gml->prev != (CLQ_GML*) NULL)
      gml->prev->next=gml->next;
    else {
      /* The controller died */
      ctx->first=ctx->controller=ctx->group_members_list=gml->next;
      if (ctx->controller == ctx->me) new_cntlr = TRUE;
      if (ctx->key_share == NULL) {ret=CTX_ERROR; goto error;}
      /* Generetaing a new key_share */
      if ((ret=ckd_create_share(ctx)) != OK) goto error;
    }
    
    if (gml->next != (CLQ_GML*) NULL)
      gml->next->prev=gml->prev;
    else
      ctx->last=gml->prev;
    
    clq_free_gm(gml->member);
    gml->member=NULL;
    free (gml);
    gml=NULL;
  }
  else if (event != CKD_REFRESH_KEY) 
  {ret=INVALID_PARAM; goto error;}
  
  clq_destroy_token (output);
  if (((event == CKD_JOIN) && (ctx->controller == ctx->me)) ||
      (new_cntlr)) {
    /* Create the output token, which contains the group_members_list
     * and my short term key. The short term key is stored in my
     * last_partial_key location. The partial keys of other users are
     * set to one.  
     */
    CLQ_TOKEN_INFO *info=NULL;
    
    if (new_cntlr) {
      ret=clq_create_token_info(&info,ctx->group_name,CKD_NEW_KEY_SHARE, 
                                time(0),ctx->member_name); 
      *msg_type=CKD_NEW_KEY_SHARE;
    }
    else {
      ret=clq_create_token_info(&info,ctx->group_name,CKD_OLD_KEY_SHARE, 
                                time(0),ctx->member_name); 
      *msg_type=CKD_OLD_KEY_SHARE;
    }
    
    if (ret!=OK) goto error;
    ret=clq_grl_encode (ctx,output,info,FALSE);
    /* sign_message */
    ret=clq_sign_message (ctx, (*output));
    
    clq_destroy_token_info(&info);
    if (ret!=OK) clq_destroy_token (output); 
  }
  else
    /* I am still the old controller, then compute new session key. */
    if ((ctx->controller == ctx->me) && 
        ((!new_cntlr) || (CKD_REFRESH_KEY))) {
      *msg_type=CKD_NEW_SESSION_KEY;
      ret=ckd_compute_session_key (ctx,output);
      if (ret!=OK) goto error;
    }
  
  error:
  
  return ret;
}


int ckd_comp_new_share (CKD_CONTEXT *ctx, CLQ_TOKEN *input, 
                        CLQ_TOKEN **output) {
  int ret=OK;
  CKD_CONTEXT *new_ctx=NULL;
  CLQ_GML *gml=NULL;
  int new_user=FALSE;
  CLQ_TOKEN_INFO *info;
  CLQ_SIGN *sign=NULL;
  
  /* Checking for errors */
  if (ctx == (CKD_CONTEXT *) NULL) return CTX_ERROR;
  if (input == (CLQ_TOKEN*) NULL) return INVALID_INPUT_TOKEN;
  
  ret=clq_remove_sign(input,&sign);
  if (ret != OK) goto error;
  if ((ret=clq_decode(&new_ctx, input, &info))!=OK)
    goto error;

  if (strcmp (info->group_name,ctx->group_name)) 
  { ret=GROUP_NAME_MISMATCH; goto error; }
  if (info->message_type != CKD_NEW_KEY_SHARE) 
    if (info->message_type != CKD_OLD_KEY_SHARE)
    { ret=INVALID_MESSAGE_TYPE; goto error; }
  if (ctx->first != (CLQ_GML*) NULL) {
    if (ctx->controller == ctx->me) { ret=OK; goto error; }
    if (new_ctx->epoch != ctx->epoch) 
    { ret=UNSYNC_EPOCH; goto error; }
    ret=ckd_cmp_gmls (ctx->first,new_ctx->first);
    if (ret!=OK) goto error;
    
    /* Updating controller partial key */
    if (info->message_type==CKD_NEW_KEY_SHARE) {
      gml=clq_search_gml(new_ctx->first,
                         ctx->controller->member->member_name);
      BN_copy (ctx->controller->member->last_partial_key,
               gml->member->last_partial_key);
      gml=NULL;
    }
  }
  else {
    /* Setting group_member_list of the new user */
    gml=clq_search_gml(new_ctx->first,ctx->member_name);
    if (gml == (CLQ_GML*) NULL) {ret=MEMBER_NOT_IN_GROUP; goto error;}
    ctx->me=gml;
    ctx->group_members_list=ctx->first=new_ctx->first;
    ctx->last=new_ctx->last;
    ctx->epoch=new_ctx->epoch;
    ctx->controller=ctx->first;
    new_ctx->first=new_ctx->group_members_list=gml=NULL;
    new_user=TRUE;
  }
  /* Done with error checkings */
  
  clq_destroy_token (output);
  /* If I am a new user or the previous controller died then I need to
   * re-compute my key_share and send it to the controller.
   */
  if (new_user || (info->message_type == CKD_NEW_KEY_SHARE)) {
    if (new_user) {
      /* I am a new member why should I have a key_share already? */
      if (ctx->key_share != (BIGNUM *) NULL) {ret=CTX_ERROR; goto error;}
      if (!BN_is_one(ctx->me->member->last_partial_key))
      {ret=CTX_ERROR; goto error;}
    }
    else
      BN_clear_free (ctx->key_share);
    
    ret=ckd_gnrt_single (ctx,output);
  }
  
  /* Get pkey and verify */
  ret=clq_vrfy_sign (ctx, input, info->sender_name, sign);
 
  if (ret != OK) goto error;
  
error:
  
  if (ret==OK) ret=clq_restore_sign(input,&sign);
  clq_destroy_token_info(&info);
  clq_destroy_ctx (&new_ctx);
  
  return ret;
}

int ckd_get_session_key (CKD_CONTEXT *ctx, CLQ_TOKEN *input) {
  int ret=OK;
  CLQ_TOKEN_INFO *info=NULL;
  CKD_CONTEXT *new_ctx=NULL;
  BN_CTX *bn_ctx=NULL;
  CLQ_SIGN *sign=NULL;
  
  /* Checking for errors */
  if (ctx == (CKD_CONTEXT *) NULL) return CTX_ERROR;
  if (ctx->controller == ctx->me) { ctx->epoch++; return OK; }
  if (input == (CLQ_TOKEN*) NULL) return INVALID_INPUT_TOKEN;
  ret=clq_remove_sign(input,&sign);
  if (ret != OK) goto error;
  if ((ret=clq_decode(&new_ctx, input, &info))!=OK)
    goto error;
  
  if (strcmp (info->group_name,ctx->group_name)) 
  { ret=GROUP_NAME_MISMATCH; goto error; }
  if (new_ctx->epoch != ctx->epoch) 
  { ret=UNSYNC_EPOCH; goto error; }
  if (info->message_type != CKD_NEW_SESSION_KEY)
  { ret=INVALID_MESSAGE_TYPE; goto error; }
  ret=ckd_cmp_gmls (ctx->first,new_ctx->first);
  if (ret!=OK) goto error;
  new_ctx->me=clq_search_gml (new_ctx->first, ctx->member_name);
  if (new_ctx->me == NULL) {ret=MEMBER_NOT_IN_GROUP; goto error;}
  /* Done with error checkings */

  /* Computing session key */

  if ((bn_ctx=BN_CTX_new()) == NULL) {ret=MALLOC_ERROR; goto error;}

  /* new_ctx->me->member->last_partial_key contains the new session
   * encrypted with my key = Ks^(g^(A*Bi)) =>
   * Ks^(g^(A*Bi))^inv(g^(A*Bi)) = Ks
   */

  if (!BN_mod_exp (ctx->group_secret,
                   new_ctx->me->member->last_partial_key,
                   ctx->me->member->last_partial_key,
                   DSA_get0_p(ctx->params), bn_ctx)) {ret=BN_ERROR; goto error;}

  if ((ret=clq_compute_secret_hash (ctx))!=OK) goto error;

  /* Get pkey and verify */
  ret=clq_vrfy_sign (ctx, input, info->sender_name, sign);
  if (ret != OK) goto error;
  
 error:
  
  if (ret==OK) {
    ret=clq_restore_sign(input,&sign);
    ctx->epoch++;
  }
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);
  clq_destroy_token_info (&info);
  clq_destroy_ctx (&new_ctx);

  return ret;
}



/* ckd_gnrt_single: Used inside ckd_comp_new_share to generate the
 * individual (single) token of this user, which will be send to the
 * controller. 
 */
int ckd_gnrt_single (CKD_CONTEXT *ctx, CLQ_TOKEN **output) {
  int ret=OK;
  CLQ_TOKEN_INFO *info=NULL;
  CLQ_GML *gml=NULL;
  CLQ_GML *gml_first=NULL;
  BN_CTX *bn_ctx=BN_CTX_new(); 
  BIGNUM *tmp_key=BN_new();

  if ((bn_ctx == (BN_CTX *) NULL) || (tmp_key == (BIGNUM *) NULL)) 
    return MALLOC_ERROR;
  
  /* Computing new key_share */
  ctx->key_share=clq_grt_rnd_val(ctx->params);
  if (ctx->key_share == (BIGNUM*) NULL) {ret=MALLOC_ERROR; goto error;}
  
  /* Saving time and memory doing it this way. */
  gml=clq_create_gml(ctx->member_name);
  gml->member->last_partial_key=BN_new();
  if (gml->member->last_partial_key == (BIGNUM*) NULL)
    { ret=MALLOC_ERROR; goto error; }

  /* g^Bi */
  if (!BN_mod_exp (gml->member->last_partial_key, DSA_get0_g(ctx->params),
                   ctx->key_share, DSA_get0_p(ctx->params), bn_ctx)) goto error;
    
/*    g^(A*Bi)  */
/*    if (!BN_mod_exp (tmp_key, */
/*                     ctx->controller->member->last_partial_key, */
/*                     ctx->key_share, ctx->params->p, bn_ctx)) goto error; */

/*    inv(g^(A*Bi)) for future use (ckd_get_session_key) */
/*    if (BN_mod_inverse (ctx->me->member->last_partial_key, tmp_key, */
/*                        ctx->params->q, bn_ctx) == NULL) goto error; */
  
  ret=clq_create_token_info(&info,ctx->group_name,
                            CKD_INDIVIDUAL_SHARE, time(0),
                            ctx->member_name); 

  if (ret!=OK) goto error;
  /* Generating output token */
  gml_first=ctx->first;
  ctx->group_members_list=ctx->first=gml;
  ret=clq_encode(ctx,output,info);
  /* sign_message */
  ret=clq_sign_message (ctx, (*output));
  ctx->group_members_list=ctx->first=gml_first;

  gml_first = clq_search_gml(ctx->group_members_list, ctx->member_name);
  /* This is not necessary... But I want to see what's going on */
  ret = BN_mod_exp(gml_first->member->last_partial_key,
                   ctx->first->member->last_partial_key, ctx->key_share,
                   DSA_get0_p(ctx->params), bn_ctx);
  if (BN_mod_inverse (gml_first->member->last_partial_key,
                      gml_first->member->last_partial_key,  
                      DSA_get0_q(ctx->params), bn_ctx) == NULL) goto error; 
  if(ret != OK){
    goto error;
  }
  
  clq_destroy_token_info(&info);

 error:

  if (bn_ctx != (BN_CTX*) NULL) BN_CTX_free (bn_ctx);
  if (tmp_key != (BIGNUM*) NULL) BN_clear_free(tmp_key);
  clq_free_gml(gml);

  return ret;
}

/* ckd_compute_session_key : Computes new session key and encrypts
 * it for each user.
 */
int ckd_compute_session_key (CLQ_CONTEXT *ctx,CLQ_TOKEN **output) {
  int ret=OK;
  BN_CTX *bn_ctx=NULL;
  CLQ_GML *gml=NULL;
  CLQ_GML *tmp_gml=NULL;
  CLQ_GML *ctx_first=ctx->first;
  CLQ_TOKEN_INFO *info=NULL;
  CLQ_GML *gml_first=NULL;

  /* Generating new session key (group_secret) for the group */
  BN_clear_free (ctx->group_secret);
  if ((bn_ctx=BN_CTX_new())==NULL) {ret=MALLOC_ERROR; goto error; }
  ctx->group_secret=clq_rand(ctx->params,DSA_get0_p(ctx->params));
  if (ctx->group_secret == NULL) {ret=MALLOC_ERROR; goto error;}

  if (!BN_mod_exp (ctx->group_secret, DSA_get0_g(ctx->params),
                   ctx->group_secret,  DSA_get0_p(ctx->params), bn_ctx))
    {ret= BN_ERROR; goto error; }
  if ((ret=clq_compute_secret_hash (ctx))!=OK) goto error;

  tmp_gml=ctx->first;
  if (tmp_gml == NULL) {ret=CTX_ERROR; goto error;}
  gml=clq_create_gml (ctx->first->member->member_name);
  if (gml == NULL) {ret=MALLOC_ERROR; goto error;}
  if ((gml->member->last_partial_key=BN_new())==NULL) 
    {ret=MALLOC_ERROR; goto error;}
  ret=BN_ERROR;
  if (tmp_gml->member != ctx->controller->member) {
    /* Encrypting session key with g^(A*Bi) for each user
       Ks^(g^(A*Bi)) */
    if (!BN_mod_exp (gml->member->last_partial_key, ctx->group_secret,
                     tmp_gml->member->last_partial_key, DSA_get0_p(ctx->params),
                     bn_ctx)) goto error;
    if (!BN_mod (gml->member->last_partial_key,
                 gml->member->last_partial_key, DSA_get0_q(ctx->params),
                 bn_ctx)) goto error;
  }
  else{
    /* This might need to be modified :-( Yongdae */
    if (BN_copy (gml->member->last_partial_key,
                 tmp_gml->member->last_partial_key) == NULL) goto error;
  }
  
  ret=OK;
  gml_first=gml;
  tmp_gml=tmp_gml->next;
  while (tmp_gml != NULL) {
    gml->next=clq_create_gml (tmp_gml->member->member_name);
    if (gml->next == NULL) {ret=MALLOC_ERROR; goto error;}
    gml->next->prev=gml;
    gml=gml->next;
    if ((gml->member->last_partial_key=BN_new())==NULL) 
      {ret=MALLOC_ERROR; goto error;}
    ret=BN_ERROR;
    if (tmp_gml->member != ctx->controller->member) {
      /* Encrypting session key with g^(A*Bi) for each user
         Ks^(g^(A*Bi)) */
      BN_mod(tmp_gml->member->last_partial_key,
             tmp_gml->member->last_partial_key, DSA_get0_q(ctx->params),
             bn_ctx);
      if (!BN_mod_exp (gml->member->last_partial_key, ctx->group_secret,
                       tmp_gml->member->last_partial_key, DSA_get0_p(ctx->params),
                       bn_ctx)) goto error;
    }
    else
      if (BN_copy (gml->member->last_partial_key,
                   tmp_gml->member->last_partial_key) == NULL) goto error;
    
    ret=OK;
    tmp_gml=tmp_gml->next;
  }

  ret=clq_create_token_info(&info,ctx->group_name,CKD_NEW_SESSION_KEY,
                            time(0),ctx->member_name); 
  if (ret!=OK) goto error;
  ctx->group_members_list=ctx->first=gml_first;
  ret= clq_encode(ctx, output, info);
  /* sign_message */
  ret=clq_sign_message (ctx, (*output));
  ctx->group_members_list=ctx->first=ctx_first;
  clq_free_gml(gml_first);
    
 error:

  if (bn_ctx != (BN_CTX*) NULL) BN_CTX_free (bn_ctx);
  clq_destroy_token_info (&info);

  return ret;
}



/* ckd_compute_user_key: Removing Kij with user.
 */ 
int ckd_compute_user_key (CLQ_CONTEXT *ctx,CLQ_GML *gml) {
  int ret=OK;
  BIGNUM *inv_long_term_key=NULL;
  BIGNUM *tmp_key=NULL;
  BN_CTX *bn_ctx=NULL;

  if ((tmp_key=BN_new())==NULL) {ret=MALLOC_ERROR; goto error; }
  if ((bn_ctx=BN_CTX_new())==NULL) {ret=MALLOC_ERROR; goto error; }
  
  ret=BN_ERROR;
  if (!BN_mod_mul (tmp_key, inv_long_term_key, ctx->key_share, 
		   DSA_get0_q(ctx->params), bn_ctx )) goto error;

  /* g^(A*Bi) mod q */
  if (!BN_mod_exp (gml->member->last_partial_key, 
		   gml->member->last_partial_key, tmp_key,
		   DSA_get0_p(ctx->params), bn_ctx)) goto error;

  if (!BN_mod (gml->member->last_partial_key,
	       gml->member->last_partial_key, DSA_get0_q(ctx->params),
	       bn_ctx)) goto error;

  ret=OK;

 error: 
  
  if (inv_long_term_key != NULL) BN_clear_free (inv_long_term_key);
  if (tmp_key != NULL) BN_clear_free(tmp_key);
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);

  return ret;
}

/* ckd_create_share: Creates a new key_share and computes my
   last_partial_key using the key_share */
int ckd_create_share (CLQ_CONTEXT *ctx) {
  int ret=OK;
  BN_CTX *bn_ctx=NULL;

  if ((bn_ctx=BN_CTX_new()) == NULL) { ret=MALLOC_ERROR; goto error;} 
  
  if (ctx->key_share == NULL) {ret=CTX_ERROR; goto error;}

  BN_clear_free (ctx->key_share);
  ctx->key_share= clq_grt_rnd_val(ctx->params);
  if (ctx->key_share == (BIGNUM*) NULL) {ret=CTX_ERROR; goto error;}
  if (ctx->me->member->last_partial_key == (BIGNUM*)NULL)
    if ((ctx->me->member->last_partial_key=BN_new()) == (BIGNUM*)NULL)
    { ret=MALLOC_ERROR; goto error;} 
  
  if (!BN_mod_exp (ctx->me->member->last_partial_key,DSA_get0_g(ctx->params),
		   ctx->key_share, DSA_get0_p(ctx->params), bn_ctx))
      ret=BN_ERROR;

 error:

  if (bn_ctx != (BN_CTX*) NULL) BN_CTX_free(bn_ctx);

  return ret;
}

/* ckd_cmp_gmls: Compare two gmls. */
int ckd_cmp_gmls (CLQ_GML *gml, CLQ_GML *tmp_gml) {
  while (gml != NULL) {
    if (tmp_gml == NULL) break;
    if (strcmp (gml->member->member_name,
		tmp_gml->member->member_name)) break;
    gml=gml->next;
    tmp_gml=tmp_gml->next;
  }
  if ((gml != NULL) || (tmp_gml != NULL))
    return MEMBER_NAME_MISMATCH;

  return OK;
}

/* Preconditions: ctx->controller has to be valid (i.e. not NULL) */
CLQ_NAME *ckd_get_controller_name (CLQ_CONTEXT *ctx) {
  static CLQ_NAME name[MAX_LGT_NAME];

  strcpy (name,ctx->controller->member->member_name);

  return name;
}

  
