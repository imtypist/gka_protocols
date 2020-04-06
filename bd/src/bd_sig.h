/*********************************************************************
 * bd_sig.h                                                          * 
 * BD signature include file.                                        * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/
#ifndef BD_SIG_H
#define BD_SIG_H

#include "openssl/evp.h"
#include "openssl/x509.h"

#include "bd_api.h"

/* Both md below use sha1 */
#define RSA_MD() EVP_sha1() /* NID_sha1WithRSAEncryption see m_sha1.c */
#define DSA_MD() EVP_sha1() /* NID_dsaWithSHA1 see m_dss1.c */

typedef struct bd_sign_st {
  clq_uchar *signature;
  uint length;
} BD_SIGN;


/* bd_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int bd_sign_message(BD_CONTEXT *ctx, CLQ_TOKEN *input);

int bd_vrfy_sign(BD_CONTEXT *ctx, CLQ_TOKEN *input,
                 CLQ_NAME *member_name, BD_SIGN *sign);

int bd_remove_sign(CLQ_TOKEN *input, BD_SIGN **sign);
int bd_restore_sign(CLQ_TOKEN *input, BD_SIGN **signature);

#endif
