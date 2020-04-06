/*********************************************************************
 * bd_api.c                                                          * 
 * Burmester-Desmedt Group Key Ageement Scheme                       * 
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

/* BD_API include files */
#include "bd_api.h"
#include "error.h"
#include "common.h" /* clq_get_cert is here */
#include "bd_sig.h"
#include "bd_test_misc.h"
#include "bd_api_misc.h" /* bd_get_time is defined here */
#include <sys/time.h>

/* bd_new_member is called by the new member in order to create its
 *   own context.
 */
int bd_new_member(BD_CONTEXT **ctx, CLQ_NAME *member_name,
                  CLQ_NAME *group_name)
{
  int ret=OK;

  if (member_name == NULL) return INVALID_MEMBER_NAME;
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;

  if((*ctx) != NULL){
    bd_destroy_ctx(&(*ctx));
  }
  
  if ((ret=bd_create_ctx(ctx)) != OK) {
    goto error;
  }
  (*ctx)->member_name=(CLQ_NAME *) calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
  if (((*ctx)->member_name) == NULL) {
    ret=MALLOC_ERROR;
    goto error;
  }
  strncpy((*ctx)->member_name,member_name,MAX_LGT_NAME);
  (*ctx)->group_name=(CLQ_NAME *) calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1);
  if (((*ctx)->group_name) == NULL) {
    ret=MALLOC_ERROR;
    goto error;
  }
  strncpy((*ctx)->group_name,group_name,MAX_LGT_NAME);
  /* Get DSA parameters */
  (*ctx)->params=clq_read_dsa(NULL,CLQ_PARAMS);
  if ((*ctx)->params == (DSA *)NULL) {
    ret=INVALID_DSA_PARAMS;
    goto error;
  }
  /* Get user private and public keys */
  (*ctx)->pkey=clq_get_pkey(member_name);
  if (((*ctx)->pkey) == (EVP_PKEY*) NULL){
    ret=INVALID_PRIV_KEY;
    goto error;
  }

  (*ctx)->list = NULL;
  
error:
  if (ret!=OK) bd_destroy_ctx(&(*ctx));
  
  return ret;
}

/* bd_refresh_session refreshes (or generates, if session random is
   NULL) session random of each user */ 
int bd_refresh_session(BD_CONTEXT *ctx)
{
  int ret=OK;
  MEMBER_LIST *tmp_list=NULL;
  BN_CTX *bn_ctx=BN_CTX_new();

  tmp_list = bd_search_list(ctx->list, ctx->member_name);
  if(tmp_list->bd_nv->z_i != NULL){
    BN_clear_free(tmp_list->bd_nv->z_i);
    tmp_list->bd_nv->z_i = NULL;
  }
  if(ctx->r_i != NULL){
    BN_clear_free(ctx->r_i);
    ctx->r_i = NULL;
  }
  if(ctx->group_secret != NULL){
    BN_clear_free(ctx->group_secret);
    ctx->group_secret = NULL;
  }
  ctx->r_i=bd_rand(ctx->params);
  if (BN_is_zero(ctx->r_i) || ctx->r_i==NULL){
    ret=MALLOC_ERROR;
    goto error;
  }
  tmp_list->bd_nv->z_i = BN_new();
  ret = BN_mod_exp(tmp_list->bd_nv->z_i, DSA_get0_g(ctx->params),
                   ctx->r_i, DSA_get0_p(ctx->params), bn_ctx);
  
error:
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);
  
  return ret;
}

/* Main functionality of this function is to broadcast session random
 *   of a user... If flag == 0 (when cascading happens), it will not
 *   refresh the session random. If it is 1, it will refresh the
 *   session random.
 */
int bd_membership_req(BD_CONTEXT *ctx, CLQ_NAME *member_name,
                      CLQ_NAME *group_name, CLQ_NAME *member_list[], 
                      CLQ_TOKEN **output, int flag)
{
  int ret=OK;
  int i=0;
  MEMBER_LIST *tmp_list=NULL, *prev=NULL;
  BD_TOKEN_INFO *info=NULL;

  if (member_name == NULL) return INVALID_MEMBER_NAME;
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;
  if (group_name == NULL) return INVALID_GROUP_NAME;
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)) return INVALID_LGT_NAME;

  if(ctx->list != NULL){
    ctx->list->prev->next = NULL;
  }
  if(ctx->list != NULL){
    bd_free_list(&(ctx->list));
  }

  i=0;
  
  while(member_list[i] != NULL){
    if(i == 0){
      ctx->list=(MEMBER_LIST *) calloc(sizeof(MEMBER_LIST),1);
      tmp_list = ctx->list;
    }
    else{
      tmp_list=(MEMBER_LIST *) calloc(sizeof(MEMBER_LIST),1);
    }
    tmp_list->bd_nv=(BD_NV *) calloc(sizeof(BD_NV),1);
    tmp_list->bd_nv->member = (BD_GM *) calloc(sizeof(BD_GM),1);
    tmp_list->bd_nv->member->member_name=(CLQ_NAME *)
      calloc(sizeof(CLQ_NAME)*MAX_LGT_NAME,1); 
    strncpy (tmp_list->bd_nv->member->member_name,
             member_list[i],MAX_LGT_NAME);
    tmp_list->bd_nv->member->cert = NULL;
    if(prev != NULL){
      prev->next=tmp_list;
      tmp_list->prev=prev;
    }
    tmp_list->next=NULL;
    prev = tmp_list;
    i++;
  }
  tmp_list->next = ctx->list;
  ctx->list->prev = tmp_list;
  ctx->num_users = i;

  if(flag == 1){
    ret = bd_refresh_session(ctx);
    if(ret != OK){
      goto error;
    }
  }
  
  if (info != NULL) bd_destroy_token_info(&info);
  /* Creating token info */
  ret=bd_create_token_info(&info, ctx->group_name,
                           BROADCAST_Z, time(0),
                           ctx->member_name);  
  if (ret!=OK) goto error;
  ret=bd_encode(ctx,output,info,0);
  if (ret!=OK) goto error;
  
  /* Sign output token; */
  ret=bd_sign_message (ctx, *output);
  
error:
  /* OK... Let's free the memory */
  if (info != NULL) bd_destroy_token_info(&info);
  if (ret!=OK) bd_destroy_ctx(&ctx);
  
  return ret;
}

/* bd_compute_xi computes x_i for other members. I need z_{i+1} and
 *   z_{i-1} to compute my x_i
 */
int bd_compute_xi (BD_CONTEXT *ctx, CLQ_NAME *member_name, 
                   CLQ_NAME *group_name, CLQ_TOKEN *input,
                   CLQ_TOKEN **output)
{
  BD_TOKEN_INFO *info=NULL;
  BD_SIGN *sign=NULL;
  int ret=CONTINUE;
  BIGNUM *tmp_bn=NULL;
  MEMBER_LIST *tmp_list=NULL, *me=NULL;
  BN_CTX *bn_ctx=BN_CTX_new();

  /* Doing some error checking */
  if (ctx == NULL){
    return CTX_ERROR;
  }
  if (member_name == NULL){
    return INVALID_MEMBER_NAME;
  }
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)){
    return INVALID_LGT_NAME;
  }
  if (group_name == NULL){
    return INVALID_GROUP_NAME;
  }
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)){
    return INVALID_LGT_NAME;
  }
  if(input == NULL){
    return INVALID_INPUT_TOKEN;
  }

  /* If I already computed x_i, then I don't need to recompute x_i */
  me = bd_search_list(ctx->list, ctx->member_name);
  if(me->bd_nv->x_i != NULL){
    ret = OK;
    goto error;
  }
  
  if(info != NULL){
    bd_destroy_token_info(&info);
  }
  ret=bd_remove_sign(input,&sign);
  if (ret != OK){
    goto error;
  }
  ret=bd_decode(input, &info);
  ctx->epoch = MAX(ctx->epoch, info->epoch);
  if (ret!=OK){
    goto error;
  }
  if (strcmp(info->group_name,group_name)){
    ret=GROUP_NAME_MISMATCH;
    goto error;
  }
  if (info->message_type != BROADCAST_Z){
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }

  tmp_list = bd_search_list(ctx->list, info->sender_name);
  if(tmp_list == NULL){
    ret = INVALID_MEMBER_NAME;
    goto error;
  }
  if(strcmp(tmp_list->prev->bd_nv->member->member_name,ctx->member_name)==0){
    me = tmp_list->prev;
  }
  if(strcmp(tmp_list->next->bd_nv->member->member_name,ctx->member_name)==0){
    me = tmp_list->next;
  }
  
  if(me != NULL){
    /* This is useful information to me */
    ret=bd_vrfy_sign (ctx, input, info->sender_name, sign);  
    if(ret!=OK){
      goto error;
    }
    /* Computing x_i */
    clq_swap((void *)&(tmp_list->bd_nv->z_i), (void *)&(info->key_info));
    if((me->prev->bd_nv->z_i != NULL) &&
       (me->next->bd_nv->z_i != NULL)){ 
      tmp_bn = BN_mod_inverse(tmp_bn, me->prev->bd_nv->z_i,
                              DSA_get0_p(ctx->params), bn_ctx);
      if(tmp_bn == NULL){
        ret = MOD_INVERSE_ERROR;
        goto error;
      }
      BN_mod_mul(tmp_bn, tmp_bn, me->next->bd_nv->z_i, DSA_get0_p(ctx->params),
                 bn_ctx);
      me->bd_nv->x_i = BN_new();
      BN_mod(ctx->r_i, ctx->r_i, DSA_get0_q(ctx->params), bn_ctx);
      BN_mod_exp(me->bd_nv->x_i, tmp_bn, ctx->r_i, DSA_get0_p(ctx->params),
                 bn_ctx);
      if (info != NULL) bd_destroy_token_info(&info);
      /* Creating token info */
      ret=bd_create_token_info(&info, ctx->group_name, BROADCAST_X,
                               time(0), ctx->member_name);  
      if (ret!=OK) goto error;
      ret=bd_encode(ctx,output,info,1);
      if (ret!=OK) goto error;
      
      /* Sign output token; */
      ret=bd_sign_message (ctx, *output);
    }
  }
  
error:
  if (info != (BD_TOKEN_INFO*)NULL){
    bd_destroy_token_info(&info);
  }
  if(tmp_bn != NULL) {
    BN_clear_free(tmp_bn);
  }
  if(input != NULL){
    ret=bd_restore_sign(input,&sign);
  }
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);
  /* If I already computed x_i, then I don't need to recompute x_i */
  me = bd_search_list(ctx->list, ctx->member_name);
  if(me->bd_nv->x_i != NULL){
    ret = OK;
  }
  if(me->bd_nv->x_i == NULL){
    ret = CONTINUE;
  }
  return ret;
}

/* bd_compute_key computes key. I need z_{i-1} and all x_i's */
int bd_compute_key (BD_CONTEXT *ctx, CLQ_NAME *member_name, 
                    CLQ_NAME *group_name, CLQ_TOKEN *input)
{
  BD_TOKEN_INFO *info=NULL;
  int ret=OK;
  MEMBER_LIST *tmp_list=NULL, *me=NULL;
  BN_CTX *bn_ctx=BN_CTX_new();
  char int_buffer[5]; /* Number of users is less than 16^4 */
  BIGNUM *tmp_bn=NULL;
  BD_SIGN *sign=NULL;
  int tmp_int=1;

  /* Doing some error checking */
  if (ctx == NULL){
    return CTX_ERROR;
  }
  if (member_name == NULL){
    return INVALID_MEMBER_NAME;
  }
  if ((strlen(member_name) == 0) ||
      (strlen(member_name) > MAX_LGT_NAME)){
    return INVALID_LGT_NAME;
  }
  if (group_name == NULL){
    return INVALID_GROUP_NAME;
  }
  if ((strlen(group_name) == 0) ||
      (strlen(group_name) > MAX_LGT_NAME)){
    return INVALID_LGT_NAME;
  }
  if(ctx->group_secret != NULL){
    goto error;
  }
  if(input == NULL){
    return INVALID_INPUT_TOKEN;
  }
  if(info != NULL){
    bd_destroy_token_info(&info);
  }
  ret=bd_remove_sign(input,&sign);
  if (ret != OK){
    goto error;
  }
  ret=bd_decode(input, &info);
  if (ret!=OK){
    goto error;
  }
  if(info->epoch != ctx->epoch){
    ret=UNSYNC_EPOCH;
    goto error;
  }
  
  if (strcmp(info->group_name,group_name)){
    ret=GROUP_NAME_MISMATCH;
    goto error;
  }
  if (info->message_type != BROADCAST_X){
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }
  tmp_list = bd_search_list(ctx->list, info->sender_name);
  if(tmp_list == NULL){
    ret = INVALID_MEMBER_NAME;
    goto error;
  }
  me = bd_search_list(ctx->list, ctx->member_name);
  if(me == NULL){
    ret = CTX_ERROR;
    goto error;
  }
  
  ret=bd_vrfy_sign (ctx, input, info->sender_name, sign);  
  if(ret!=OK){
    goto error;
  }
  /* Copy x_i */
  clq_swap((void *)&(tmp_list->bd_nv->x_i), (void *)&(info->key_info));
  if(bd_computable(ctx->list, ctx->member_name) == 0){
    ret = CONTINUE;
    goto error;
  }
  else{
    sprintf(int_buffer, "%x", ctx->num_users);
    tmp_bn = BN_new();
    BN_hex2bn(&tmp_bn, int_buffer);
    /* (n * r_i) mod q */
    BN_mod_mul(tmp_bn, tmp_bn, ctx->r_i, DSA_get0_q(ctx->params), bn_ctx);
    /* z_{i-1}^(n * r_i) mod p */

    ctx->group_secret = BN_new();
    BN_mod_exp(ctx->group_secret, me->prev->bd_nv->z_i, tmp_bn,
               DSA_get0_p(ctx->params), bn_ctx);

    tmp_list = me->prev->prev;
    tmp_int = 1;
    while(strcmp(tmp_list->bd_nv->member->member_name,
                 me->prev->bd_nv->member->member_name) != 0){
      sprintf(int_buffer, "%x", tmp_int);
      BN_hex2bn(&tmp_bn, int_buffer);
      /* x_k^(n+k-1) mod p */
      BN_mod(tmp_bn, tmp_bn, DSA_get0_q(ctx->params), bn_ctx);
      BN_mod_exp(tmp_bn, tmp_list->bd_nv->x_i, tmp_bn,
                 DSA_get0_p(ctx->params), bn_ctx);
      /* (n * r_i) mod q */
      BN_mod_mul(ctx->group_secret, tmp_bn, ctx->group_secret,
                 DSA_get0_p(ctx->params), bn_ctx);
      BN_clear_free(tmp_bn);
      tmp_bn = NULL;
      tmp_int++;
      tmp_list = tmp_list->prev;
    }
    ret = OK;
    ret=bd_compute_secret_hash (ctx);
    if (ret!=OK) goto error;
  }
  
error:
  if (info != (BD_TOKEN_INFO*)NULL){
    bd_destroy_token_info(&info);
  }
  if(input != NULL){
    ret=bd_restore_sign(input,&sign);
  }
  if (bn_ctx != NULL) BN_CTX_free (bn_ctx);
  if(ctx->group_secret != NULL){
    ret = OK;
  }
  else{
    ret = CONTINUE;
  }
  return ret;
}

/* bd_create_ctx creates the str context.
 * Preconditions: *ctx has to be NULL.
 */
int bd_create_ctx(BD_CONTEXT **ctx) 
{
  int ret=CTX_ERROR;

  if (*ctx != (BD_CONTEXT *)NULL) return CTX_ERROR;
  /* Creating ctx */
  (*ctx) = (BD_CONTEXT *) calloc(sizeof(BD_CONTEXT), 1);
  if ((*ctx) == NULL) goto error;
  (*ctx)->member_name=NULL;
  (*ctx)->group_name=NULL;
  (*ctx)->list=NULL;
  (*ctx)->group_secret_hash=(clq_uchar*) calloc (MD5_DIGEST_LENGTH,1);
  if ((*ctx)->group_secret_hash==NULL){
    goto error;
  }
  (*ctx)->r_i=NULL;
  (*ctx)->num_users=0;
  (*ctx)->params=NULL; 
  (*ctx)->pkey=NULL;
  (*ctx)->epoch=0;
  
  ret=OK;
error:
  if (ret!=OK) bd_destroy_ctx (ctx);
  
  return ret;
}

/* bd_rand: Generates a new random number of "params->q" bits, using
 *   the default parameters.
 * Returns: A pointer to a dsa structure where the random value
 *          resides. 
 *          NULL if an error occurs.
 */
BIGNUM *bd_rand (DSA *params) 
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

/* bd_compute_secret_hash: It computes the hash of the group_secret.
 * Preconditions: ctx->group_secret has to be valid.
 */
int bd_compute_secret_hash (BD_CONTEXT *ctx) 
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

/* bd_destroy_ctx frees the space occupied by the current context.
 * Including the group_members_list.
 */

void bd_destroy_ctx (BD_CONTEXT **ctx) 
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
  if (((*ctx)->r_i) != NULL) {
    BN_clear_free((*ctx)->r_i);
    (*ctx)->r_i=NULL;
  }
  if((*ctx)->list != NULL){
    (*ctx)->list->prev->next = NULL;
  }
  bd_free_list(&((*ctx)->list));
  (*ctx)->list=NULL;
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

/* bd_encode using information from the current context and from
 * token info generates the output token.
 *
 * Note: output is created here.
 * Preconditions: *output should be empty (otherwise it will be
 * freed).
 * if option is 0, z_i will be encoded
 * if option is 1, x_i will be encoded
 */
int bd_encode(BD_CONTEXT *ctx, CLQ_TOKEN **output,
              BD_TOKEN_INFO *info, int option) 
{ 
  uint pos=0;
  clq_uchar *data=NULL;
  MEMBER_LIST *list=NULL;
  
  /* Freeing the output token if necessary */
  if((*output) != NULL) bd_destroy_token(output);
  
  /* Do some error checkings HERE !! */
  if (ctx == (BD_CONTEXT *) NULL) return CTX_ERROR;
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

  list = bd_search_list(ctx->list, ctx->member_name);
  if(option == 0){
    bn_encode(data, &pos, list->bd_nv->z_i);
  }
  else if(option == 1){
    bn_encode(data, &pos, list->bd_nv->x_i);
  }
  
  *output=(CLQ_TOKEN *) calloc(sizeof(CLQ_TOKEN),1);
  if (*output == (CLQ_TOKEN *) NULL) return MALLOC_ERROR;
  (*output)->length=pos;
  (*output)->t_data=data;
  
  return OK;
}

/* bd_decode using information from the input token, it creates
 * ctx. info is also created here. It contains data recovered from
 * input such as message_type, sender, etc. (See structure for more
 * details) in readable format. 
 * Preconditions: *ctx has to be NULL.
 * Postconditions: ctx is created. The only valid data in it is
 * group_members_list (first & last), and epoch. All the other
 * variables are NULL. (bd_create_ctx behavior)
 */
int bd_decode(CLQ_TOKEN *input, BD_TOKEN_INFO **info)
{
  uint pos=0;
  int ret=CTX_ERROR;
  
  if (input == NULL){
    return INVALID_INPUT_TOKEN;
  }
  if ((input->t_data == NULL) || (input->length <= 0)){
    return INVALID_INPUT_TOKEN;
  }
  /* Creating token info */
  ret=bd_create_token_info(info,"",BD_INVALID,0L,"");
  if (ret!=OK) goto error;
  
  ret=INVALID_INPUT_TOKEN;
  if (!string_decode(input,&pos,(*info)->group_name)) 
    goto error;
  if (!int_decode(input,&pos,(uint*)&(*info)->message_type)) 
    goto error;
  if (!int_decode(input,&pos,(uint *)&(*info)->time_stamp)) 
    goto error;
  if (!string_decode(input,&pos,(*info)->sender_name)) 
    goto error;
  if (!int_decode(input,&pos,&(*info)->epoch)) 
    goto error;
  (*info)->key_info = BN_new();
  if(!bn_decode(input, &pos, (*info)->key_info)){
    goto error;
  }
  
  /* Checking after decoding */
  if ((((*info)->sender_name) == NULL) ||
      (((*info)->group_name) == NULL)){
    ret=INVALID_INPUT_TOKEN;
  }
  else{
    ret=OK;
  }
  
error:
  
  if (ret != OK) {
    if (info != NULL) bd_destroy_token_info(info);
  }
  
  return ret;
}

/* bd_create_token_info: It creates the info token. */
int bd_create_token_info (BD_TOKEN_INFO **info, CLQ_NAME *group, 
                            enum BD_MSG_TYPE msg_type, time_t time,
                            CLQ_NAME *sender/*, uint epoch*/) 
{ 
  int ret=MALLOC_ERROR;
  
  /* Creating token information */
  (*info)=(BD_TOKEN_INFO *) calloc (sizeof(BD_TOKEN_INFO),1);
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
  (*info)->key_info=NULL;
  
  ret=OK;
error:
  if (ret != OK) bd_destroy_token_info(info);

  return ret;
}

/* bd_destroy_token: It frees the memory of the token. */
void bd_destroy_token (CLQ_TOKEN **token) {
  if (*token !=(CLQ_TOKEN *) NULL) {
    if ((*token)->t_data != NULL) {
      free ((*token)->t_data);
      (*token)->t_data=NULL;
    }
    free(*token);
    *token=NULL;
  }
}

/* bd_destroy_token_info: It frees the memory of the token. */
void bd_destroy_token_info (BD_TOKEN_INFO **info) 
{
  
  if (info == NULL) return;
  if ((*info) == NULL) return;
  if ((*info)->group_name != NULL) {
    free ((*info)->group_name);
  }
  if ((*info)->sender_name != NULL) {
    free ((*info)->sender_name);
  }
  if((*info)->key_info != NULL){
    BN_clear_free((*info)->key_info);
  }
  free ((*info));
  *info = NULL;
}

/* Frees a MEMBER_LIST structure */
void bd_free_list(MEMBER_LIST **member_list) {
  MEMBER_LIST *tmp_list;
  
  if(member_list == NULL) return;
  if((*member_list) == NULL) return;

  bd_free_nv(&((*member_list)->bd_nv));
  tmp_list = (*member_list)->next;
  (*member_list)->prev = (*member_list)->next = NULL;
  free(*member_list);
  (*member_list) = NULL;
  bd_free_list(&tmp_list);
}

/* Frees a BD_NV structure */
void bd_free_nv(BD_NV **nv) {
  if ((*nv) == NULL) return; 
  if((*nv)->member != NULL){
    bd_free_gm(&((*nv)->member));
    (*nv)->member=NULL;
  }
  if ((*nv)->z_i != NULL){
    BN_clear_free((*nv)->z_i);
    (*nv)->z_i = NULL;
  }
  if ((*nv)->x_i != NULL){
    BN_clear_free((*nv)->x_i);
    (*nv)->x_i = NULL;
  }
  free((*nv));
  (*nv)=NULL;
}

/* Frees a BD_GM structure */
void bd_free_gm(BD_GM **gm) {
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

/* bd_search_list finds a member named member_name */
MEMBER_LIST *bd_search_list(MEMBER_LIST *list, CLQ_NAME *member_name)
{
  CLQ_NAME *last_member=NULL;

  last_member = list->prev->bd_nv->member->member_name;
  while(list != NULL){
    if(strcmp(list->bd_nv->member->member_name, member_name) == 0){
      return list;
    }
    if(strcmp(list->bd_nv->member->member_name, last_member) == 0){
      return NULL;
    }
    list = list->next;
  }
  return NULL;
}

/* bd_computable checks whether the member receives all x_i's and z_i
 * returns 1, if enough. Returns 0 otherwise
 */
int bd_computable(MEMBER_LIST *list, CLQ_NAME *my_name)
{
  CLQ_NAME *last_member=NULL;
  MEMBER_LIST *me=NULL;

  me = bd_search_list(list, my_name);
  last_member = me->prev->bd_nv->member->member_name;
  if(me->prev->bd_nv->z_i == NULL){
    return 0;
  }
  while(me != NULL){
    if(me->bd_nv->x_i == NULL){
      return 0;
    }
    me = me->next;
    if(strcmp(me->bd_nv->member->member_name, last_member) == 0){
      break;
    }
  }

  return 1;
}

