/*********************************************************************
 * str_sig.c (copy of str_sig.c)                                     * 
 * STR signature source file.                                        *  
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/
#include <memory.h>

#include "openssl/evp.h"
#include "openssl/x509.h"

#include "str_api.h"
#include "error.h"
#include "common.h"
#include "str_sig.h"
#ifdef SIG_TIMING
#include "str_api_misc.h" /* str_get_time is defined here */
#endif

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/* str_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int str_sign_message(STR_CONTEXT *ctx, CLQ_TOKEN *input) {
  int ret=OK;
  EVP_MD_CTX *md_ctx=NULL;
  uint sig_len=0;
  uint pkey_len=0;
  clq_uchar *data=NULL;
  uint pos=0;
#ifdef SIG_TIMING
  double Time=0.0;

  Time=str_get_time();
#endif

  if (ctx==(STR_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (input==(CLQ_TOKEN*) NULL){
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }
  md_ctx=EVP_MD_CTX_new();
  if (md_ctx == NULL) {ret=MALLOC_ERROR; goto error;}
  pkey_len=EVP_PKEY_size(ctx->pkey);
  data=(clq_uchar *) malloc (pkey_len+(input->length)+TOTAL_INT);

  if (EVP_PKEY_id(ctx->pkey) == EVP_PKEY_RSA)
    EVP_SignInit (md_ctx, RSA_MD());
  else if (EVP_PKEY_id(ctx->pkey) == EVP_PKEY_DSA)
    EVP_SignInit (md_ctx, DSA_MD());
  else {
    ret=INVALID_SIGNATURE_SCHEME;
    goto error;
  }

  EVP_SignUpdate (md_ctx, input->t_data, input->length);

  /* Encoding size of the signature (an integer), the signature
     itstr, and then the data */
  ret = EVP_SignFinal (md_ctx, data+TOTAL_INT, &sig_len, ctx->pkey);
  if (ret == 0) {
#ifdef SIG_DEBUG
    ERR_print_errors_fp (stderr);
#endif
    ret=SIGNATURE_ERROR;
    goto error;
  }
  ret = OK;

  int_encode (data,&pos,sig_len);
  if (pos != TOTAL_INT) { ret=ERROR_INT_DECODE; goto error; }


  memcpy (data+sig_len+pos,input->t_data,input->length);
  
  free(input->t_data);
  input->t_data=data;
  input->length+=sig_len+pos;

 error:

  if (md_ctx != NULL) EVP_MD_CTX_free(md_ctx);
  if (ret != OK) free(data);

#ifdef SIG_TIMING
  Time=str_get_time()-Time;
  str_print_times("str_sign_message",Time); 
#endif

  return ret;                                                        
}

int str_vrfy_sign(STR_CONTEXT *ctx, STR_CONTEXT *new_ctx,
		   CLQ_TOKEN *input,  CLQ_NAME *member_name,
		   STR_SIGN *sign) 
{ 
  int ret=OK;
  EVP_MD_CTX *md_ctx=NULL;
  EVP_PKEY *pubkey=NULL; /* will not to the public key of member_name */
  STR_KEY_TREE *tmp_tree=NULL;
#ifdef SIG_TIMING
  double Time=0.0;

  Time=str_get_time();
#endif

  if (ctx==(STR_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (new_ctx==(STR_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (input==(CLQ_TOKEN*) NULL){
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }
  if (sign==(STR_SIGN*) NULL) {ret=INVALID_SIGNATURE; goto error;}
  md_ctx=EVP_MD_CTX_new();
  if (md_ctx == NULL) {ret=MALLOC_ERROR; goto error;}

  /* Searching for the member and obtainig the public key if needed */
  tmp_tree=str_search_member(new_ctx->root, 4, member_name);
  if (tmp_tree==NULL) {
    ret=MEMBER_NOT_IN_GROUP; goto error;
  }

  if (tmp_tree->str_nv->member->cert==NULL) {
    tmp_tree->str_nv->member->cert=clq_get_cert(member_name);
    if (tmp_tree->str_nv->member->cert == NULL) 
      {ret=INVALID_MEMBER_NAME; goto error;}
  }

  if ((pubkey=X509_get_pubkey(tmp_tree->str_nv->member->cert)) == (EVP_PKEY *) NULL) {ret=INVALID_PKEY; goto error; } 

  // pubkey=tmp_tree->str_nv->member->cert->cert_info->key->pkey;
  if (EVP_PKEY_id(pubkey) == EVP_PKEY_RSA)
    EVP_VerifyInit (md_ctx, RSA_MD());
  else if (EVP_PKEY_id(pubkey) == EVP_PKEY_DSA)
    EVP_VerifyInit (md_ctx, DSA_MD());
  else {
    ret=INVALID_SIGNATURE_SCHEME;
    goto error;
  }

  EVP_VerifyUpdate (md_ctx, input->t_data, input->length);
  ret = EVP_VerifyFinal (md_ctx, sign->signature, sign->length, pubkey);
  if (ret == 0) {
#ifdef SIG_DEBUG
    ERR_print_errors_fp (stderr);
#endif
    ret=SIGNATURE_DIFER;
    goto error;
  }
  ret = OK;

 error:

  if (md_ctx != NULL) EVP_MD_CTX_free (md_ctx);

#ifdef SIG_TIMING
  Time=str_get_time()-Time;
  str_print_times("str_vrfy_sign",Time); 
#endif

  return ret;
}

int str_remove_sign(CLQ_TOKEN *input, STR_SIGN **sign) {
  uint pos=0;
  int ret=OK;
  STR_SIGN *signature=*sign;

  if (input == (CLQ_TOKEN*) NULL){
    return INVALID_INPUT_TOKEN;
  }
  
  if (signature == (STR_SIGN*) NULL) {
    signature=(STR_SIGN*) malloc (sizeof(STR_SIGN));
    if (signature == (STR_SIGN*) NULL) return MALLOC_ERROR;
  }

  int_decode (input,&pos,&(signature->length));
  /* Need when restoring the signature in token str_restore_sign */
  if (pos != TOTAL_INT) {ret=ERROR_INT_DECODE; goto error; }
  if (signature->length+pos > input->length) {
    ret=INVALID_INPUT_TOKEN;
    goto error;
  }
  /* No new memory is mallocated just pointers moved around !! */
  signature->signature=input->t_data+pos;
  input->t_data+=signature->length+pos;
  input->length-=signature->length+pos;

  *sign=signature;
  signature=NULL;
 error:

  if (ret!=OK)
    /* If we mallocate the memory, then let's free it */
    if ((*sign==(STR_SIGN*)NULL) && (signature != NULL))
      free (signature);
  
  return ret;
}

int str_restore_sign(CLQ_TOKEN *input, STR_SIGN **signature) {
  int ret=OK;
  STR_SIGN *sign=*signature;
  
  if (input == (CLQ_TOKEN*) NULL){
    return INVALID_INPUT_TOKEN;
  }
  
  if (*signature == (STR_SIGN*) NULL) return ret;
  if (input->length+sign->length+TOTAL_INT > MSG_SIZE){
    return INVALID_INPUT_TOKEN;
  }

  /* No memory needs to be free see str_remove_sign ! */
  input->length+=sign->length+TOTAL_INT;
  input->t_data-=sign->length+TOTAL_INT;

  sign->length=0;
  sign->signature=NULL;
  free (*signature);
  *signature=NULL;

  return ret;
}
