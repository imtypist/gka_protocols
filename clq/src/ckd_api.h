/*********************************************************************
 * ckd_api.h                                                         * 
 * Centralized Key Distribution  api include file.                   * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef CKD_API_H
#define CKD_API_H

/* SSL include files */
/*  #include "bn.h" */

/* CLQ_API include files */
#include "clq_api.h"
#include "clq_merge.h"

typedef CLQ_CONTEXT CKD_CONTEXT;

/* CKD Event definitions */
enum CKD_EVENT { CKD_JOIN, 
		 CKD_LEAVE,
		 CKD_REFRESH_KEY};

int ckd_proc_event (CKD_CONTEXT **Ctx, CLQ_NAME *username, enum CKD_EVENT
		    event, enum MSG_TYPE *msg_type, CLQ_TOKEN **output);

int ckd_comp_new_share (CKD_CONTEXT *ctx, CLQ_TOKEN *input, 
			CLQ_TOKEN **output);

#define ckd_generates_key(ctx,sender_name,input,output) \
	clq_last_step(ctx,sender_name,input,output,CKD_GENERATE_KEY)

int ckd_get_session_key (CKD_CONTEXT *ctx, CLQ_TOKEN *input);

/* ckd_compute_session_key : Computes new session key and encrypts
 * it for each user.
 */
int ckd_compute_session_key (CLQ_CONTEXT *ctx,CLQ_TOKEN **output);

/* ckd_gnrt_single: Used inside ckd_comp_new_share to generate the
 * individual (single) token of this user, which will be send to the
 * controller. 
 */
int ckd_gnrt_single (CKD_CONTEXT *ctx, CLQ_TOKEN **output);

/* ckd_compute_user_key: Removing Kij with user.
 */ 
int ckd_compute_user_key (CLQ_CONTEXT *ctx,CLQ_GML *gml);

/* ckd_create_share: Creates a new key_share and computes my
   last_partial_key using the key_share */
int ckd_create_share (CLQ_CONTEXT *ctx);

/* ckd_cmp_gmls: Compare two gmls. */
int ckd_cmp_gmls (CLQ_GML *gml, CLQ_GML *tmp_gml);

/* Preconditions: ctx->controller has to be valid (i.e. not NULL) */
CLQ_NAME *ckd_get_controller_name (CLQ_CONTEXT *ctx);




#endif
