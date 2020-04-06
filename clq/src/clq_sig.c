/*********************************************************************
 * clq_sig.c                                                         * 
 * CLQ signature source file.                                        * 
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

#include "clq_api.h"
#include "error.h"
#include "common.h"
#include "clq_sig.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/* clq_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int clq_sign_message(CLQ_CONTEXT *ctx, CLQ_TOKEN *input) {
  int ret=OK;
  EVP_MD_CTX *md_ctx=NULL;
  clq_uint sig_len=0;
  clq_uint pkey_len=0;
  clq_uchar *data=NULL;
  clq_uint pos=0;

  if (ctx==(CLQ_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (input==(CLQ_TOKEN*) NULL) {ret=INVALID_INPUT_TOKEN; goto error;}
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
     itself, and then the data */
  ret = EVP_SignFinal (md_ctx, data+TOTAL_INT, &sig_len, ctx->pkey);
  if (ret == 0) {
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

  if (md_ctx != NULL) EVP_MD_CTX_free (md_ctx);
  if (ret != OK) free(data);

  return ret;                                                        
}

int clq_vrfy_sign(CLQ_CONTEXT *ctx, CLQ_TOKEN *input, 
                  CLQ_NAME *member_name, CLQ_SIGN *sign) {
  int ret=OK;
  EVP_MD_CTX *md_ctx=NULL;
  EVP_PKEY *pubkey=NULL; /* will not to the public key of member_name */
  CLQ_GML *gml=NULL;
  
  if (ctx==(CLQ_CONTEXT *)NULL) {ret=CTX_ERROR; goto error;}
  if (input==(CLQ_TOKEN*) NULL) {ret=INVALID_INPUT_TOKEN; goto error;}
  if (sign==(CLQ_SIGN*) NULL) {ret=INVALID_SIGNATURE; goto error;}
  md_ctx=EVP_MD_CTX_new();
  if (md_ctx == NULL) {ret=MALLOC_ERROR; goto error;}
  
  /* Searching for the member and obtainig the public key if needed */
  gml=clq_search_gml(ctx->first,member_name);
  if (gml==NULL) {ret=MEMBER_NOT_IN_GROUP; goto error; }
  
  if (gml->member->cert==NULL) {
    /* Using the cache */
/*     CLQ_GML *tmp_gml=clq_search_gml(ctx->gml_cache,member_name); */
/*     if (tmp_gml != NULL) */
/*       gml->member->cert=X509_dup(tmp_gml->member->cert); */
/*     else { */
      gml->member->cert=clq_get_cert(member_name);
      if (gml->member->cert == NULL) 
      {ret=INVALID_MEMBER_NAME; goto error;}
/*       ret=clq_gml_cache_add (ctx,gml->member); */
/*       if (ret!=OK) goto error; */
/*     } */
      /*     if (gml->member->cert==NULL) { ret=MEMBER_NOT_IN_GROUP; goto error; } */
  }
  
  if ((pubkey=X509_get_pubkey(gml->member->cert)) == (EVP_PKEY *) NULL) {ret=INVALID_PKEY; goto error; } 
  
  // pubkey=gml->member->cert->cert_info->key->pkey;
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
    
  return ret;
}

int clq_remove_sign(CLQ_TOKEN *input, CLQ_SIGN **sign) {
  clq_uint pos=0;
  int ret=OK;
  CLQ_SIGN *signature=*sign;

  if (input == (CLQ_TOKEN*) NULL) return INVALID_INPUT_TOKEN; 
  if (signature == (CLQ_SIGN*) NULL) {
    signature=(CLQ_SIGN*) malloc (sizeof(CLQ_SIGN));
    if (signature == (CLQ_SIGN*) NULL) return MALLOC_ERROR;
  }

  int_decode (input,&pos,&(signature->length));
  /* Need when restoring the signature in token clq_restore_sign */
  if (pos != TOTAL_INT) {ret=ERROR_INT_DECODE; goto error; }
  if (signature->length+pos > input->length) 
    {ret=INVALID_INPUT_TOKEN; goto error;}
  /* No new memory is mallocated just pointers moved around !! */
  signature->signature=input->t_data+pos;
  input->t_data+=signature->length+pos;
  input->length-=signature->length+pos;

  *sign=signature;
  signature=NULL;
 error:

  if (ret!=OK)
    /* If we mallocate the memory, then let's free it */
    if ((*sign==(CLQ_SIGN*)NULL) && (signature != NULL))
      free (signature);
  
  return ret;
}

int clq_restore_sign(CLQ_TOKEN *input, CLQ_SIGN **signature) {
  int ret=OK;
  CLQ_SIGN *sign=*signature;
  
  if (input == (CLQ_TOKEN*) NULL) return INVALID_INPUT_TOKEN; 
  if (*signature == (CLQ_SIGN*) NULL) return ret;
  if (input->length+sign->length+TOTAL_INT > MSG_SIZE) 
    return INVALID_INPUT_TOKEN; 

  /* No memory needs to be free see clq_remove_sign ! */
  input->length+=sign->length+TOTAL_INT;
  input->t_data-=sign->length+TOTAL_INT;

  sign->length=0;
  sign->signature=NULL;
  free (*signature);
  *signature=NULL;

  return ret;
}






