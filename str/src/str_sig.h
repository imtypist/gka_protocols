/*********************************************************************
 * str_sig.h                                                         * 
 * STR signature include file.                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/
#ifndef STR_SIG_H
#define STR_SIG_H

#include "openssl/evp.h"
#include "openssl/x509.h"

#include "str_api.h"

/* Both md below use sha1 */
#define RSA_MD() EVP_sha1() /* NID_sha1WithRSAEncryption see m_sha1.c */
#define DSA_MD() EVP_sha1() /* NID_dsaWithSHA1 see m_dss1.c */

typedef struct str_sign_st {
  clq_uchar *signature;
  uint length;
} STR_SIGN;


/* str_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int str_sign_message(STR_CONTEXT *ctx, CLQ_TOKEN *input);

int str_vrfy_sign(STR_CONTEXT *ctx, STR_CONTEXT *new_ctx,
		   CLQ_TOKEN *input,  CLQ_NAME *member_name,
		   STR_SIGN *sign);

int str_remove_sign(CLQ_TOKEN *input, STR_SIGN **sign);
int str_restore_sign(CLQ_TOKEN *input, STR_SIGN **signature);

#endif






