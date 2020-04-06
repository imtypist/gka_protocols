/*********************************************************************
 * clq_sig.h                                                         * 
 * CLQ signature include file.                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/
#ifndef CLQ_SIG_H
#define CLQ_SIG_H

#include "openssl/evp.h"
#include "openssl/x509.h"

#include "clq_api.h"

/* Both md below use sha1 */
#define RSA_MD() EVP_sha1() /* NID_sha1WithRSAEncryption see m_sha1.c */
#define DSA_MD() EVP_sha1() /* NID_dsaWithSHA1 see m_dss1.c */

typedef struct clq_sign_st {
  clq_uchar *signature;
  clq_uint length;
} CLQ_SIGN;


/* clq_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int clq_sign_message(CLQ_CONTEXT *ctx, CLQ_TOKEN *input);

int clq_vrfy_sign(CLQ_CONTEXT *ctx, CLQ_TOKEN *input, 
		  CLQ_NAME *member_name, CLQ_SIGN *sign);

int clq_remove_sign(CLQ_TOKEN *input, CLQ_SIGN **sign);
int clq_restore_sign(CLQ_TOKEN *input, CLQ_SIGN **signature);

#endif



