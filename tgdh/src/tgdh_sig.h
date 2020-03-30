/*********************************************************************
 * tgdh_sig.h                                                        * 
 * TREE signature include file.                                      * 
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

#ifndef TGDH_SIG_H
#define TGDH_SIG_H

#include "openssl/evp.h"
#include "openssl/x509.h"

#include "tgdh_api.h"

/* Both md below use sha1 */
#define RSA_MD() EVP_sha1() /* NID_sha1WithRSAEncryption see m_sha1.c */
#define DSA_MD() EVP_sha1() // EVP_dss1() has been removed /* NID_dsaWithSHA1 see m_dss1.c */

typedef struct tgdh_sign_st {
  clq_uchar *signature;
  uint length;
} TGDH_SIGN;


/* tgdh_sign_message: It signs the token using the current user public
 * key scheme. The signature will be appended to the begining of the
 * input token
 */
int tgdh_sign_message(TGDH_CONTEXT *ctx, CLQ_TOKEN *input);

int tgdh_vrfy_sign(TGDH_CONTEXT *ctx, TGDH_CONTEXT *new_ctx,
		   CLQ_TOKEN *input,  CLQ_NAME *member_name,
		   TGDH_SIGN *sign);

int tgdh_remove_sign(CLQ_TOKEN *input, TGDH_SIGN **sign);
int tgdh_restore_sign(CLQ_TOKEN *input, TGDH_SIGN **signature);

#endif
