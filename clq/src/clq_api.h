/*********************************************************************
 * clq_api.h                                                         * 
 * CLQ api include file.                                             * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef CLQ_API_H
#define CLQ_API_H

#include <stdio.h>
#include <time.h>
#include "openssl/bn.h"
#include "openssl/dsa.h"
#include "openssl/x509.h"
#include "openssl/asn1.h"

#include "common.h"

#define CLQ_API_VERSION "1.0"

/* CLQ_GM: Group member */
typedef struct clq_gm_st {
  CLQ_NAME *member_name;
  X509 *cert;
  BIGNUM *last_partial_key;
} CLQ_GM;

/* CLQ_GML: Group member list */
typedef struct clq_gml_st { 
  CLQ_GM *member;
  struct clq_gml_st *prev;
  struct clq_gml_st *next;
} CLQ_GML;


/* CLQ_CONTEXT: Cliques context */
typedef struct clq_context_st {
  CLQ_NAME *member_name;
  CLQ_NAME *group_name;
  BIGNUM *key_share; /* session_random */
  BIGNUM *group_secret; 
  clq_uchar *group_secret_hash; /* session_key */
  CLQ_GML *group_members_list; /* use first instead, eventually this
				  pointer will be removed */
  CLQ_GML *first;
  CLQ_GML *last;
  CLQ_GML *me; /* my position in group_members */
  /* The next field is not yet implemented in cliques! (but it is in
     ckd) */
  CLQ_GML *controller; /* controller position in group_members */
  CLQ_GML *gml_cache;
  DSA *params;
  EVP_PKEY *pkey;
  clq_uint epoch;
} CLQ_CONTEXT;

/* MESSAGE TYPE definitions */
enum MSG_TYPE { NEW_MEMBER, 
		KEY_UPDATE_MESSAGE,
		KEY_MERGE_UPDATE,
		MERGE_FACTOR_OUT,
		MERGE_BROADCAST,
		MASS_JOIN,
		CKD_NEW_KEY_SHARE,
		CKD_OLD_KEY_SHARE,
		CKD_INDIVIDUAL_SHARE,
		CKD_NEW_SESSION_KEY,
		INVALID };

typedef struct clq_token_info {
  CLQ_NAME *group_name;
  enum MSG_TYPE message_type;
  time_t time_stamp;
  CLQ_NAME *sender_name;
  /*  clq_uint epoch; */
} CLQ_TOKEN_INFO;

/* clq_join is called by a new group member who has received a
 * NEW_MEMBER message from the current controller.
 */
int clq_join (CLQ_CONTEXT **ctx, CLQ_NAME *member_name, 
	      CLQ_NAME *group_name, CLQ_TOKEN *input, 
	      CLQ_TOKEN **output);

/* clq_proc_join (clq process join) is called by the current
 * controller to hand over group context to a new member (who will
 * become the next controller). 
 * ctx is modified.
 */
int clq_proc_join (CLQ_CONTEXT *ctx, CLQ_NAME *member_name, 
		   CLQ_TOKEN **output);

/* clq_update_ctx is called by a member upon reception of a
 * KEY_UPDATE_MESSAGE from the current group controller 
 */
int clq_update_ctx (CLQ_CONTEXT *ctx, CLQ_TOKEN *input);

/* Change of gears... (i.e. It does not follow what is written in the
 * API documentation.)
 * clq_leave is called by every group member right after a member
 * leaves the group or a partition occurs (i.e. several members
 * left). This function will remove all the valid members in
 * member_list from the group_member_list. It does NOT depend on the
 * type of the user. 
 * Once all the deletion has been achieved, then if the user is the
 * controller (i.e. ctx->last == ctx->me) then an output token will be
 * generated. Otherwise output token will be NULL.
 *
 * Only the members that are found in the group_members_list will be
 * deleted. Any invalid member in member_list will be ignored.
 *
 * Parameters:
 *  ctx
 *   Group context (modified).
 *  member_list
 *   List of names of users leaving the group.
 *  output
 *   New key updated message generated to be broadcasted to the group.
 *  flag
 *   if it is 1, then compute the real values... Otherwise, just remove members
 *
 * If ctx->me is NULL after the deletion, then ctx will be destroyed.
 * Preconditions: member_list has to be NULL terminated. 
 *                *output should be empty.
 *                The size of member_list should be less than MAX_LIST
 */
int clq_leave (CLQ_CONTEXT **ctx, CLQ_NAME *member_list[], 
               CLQ_TOKEN **output, int flag);

/* clq_refresh_key is called by the controller only, when
 * group_secret needs to be updated.
 */
int clq_refresh_key (CLQ_CONTEXT **ctx, CLQ_TOKEN **output);

/* clq_destroy_token_info: It frees the memory of the token. */
void clq_destroy_token_info (CLQ_TOKEN_INFO **info);

/* clq_destroy_token: It frees the memory of the token. */
void clq_destroy_token (CLQ_TOKEN **token);

/* clq_destroy_ctx is called by clq_leave.
 * It frees the space occupied by the current context.
 */
void clq_destroy_ctx (CLQ_CONTEXT **ctx);

/***********************/
/*CLQ private functions*/
/***********************/

/* clq_encode using information from the current context, it generates
 * the output token.
 */
#define clq_encode(ctx,output,info) clq_grl_encode(ctx,output,info,TRUE)
int clq_grl_encode(CLQ_CONTEXT *ctx, CLQ_TOKEN **output,
		   CLQ_TOKEN_INFO *info, int include_last_partial);

/* clq_decode using information from the input token, it creates
 * ctx. info is also created here. It contains data recovered from
 * input such as message_type, sender, etc. (See structure for more
 * details) in readable format. 
 */
int clq_decode(CLQ_CONTEXT **ctx, CLQ_TOKEN *input, CLQ_TOKEN_INFO **info);

/* clq_create_token_info: It creates the info token.
 */
int clq_create_token_info (CLQ_TOKEN_INFO **info, CLQ_NAME *group, 
		      enum MSG_TYPE msg_type, time_t time, CLQ_NAME *sender/* , clq_uint epoch*/);

/* clq_create_ctx creates the clq context.
 * Preconditions: *ctx has to be NULL.
 */
int clq_create_ctx(CLQ_CONTEXT **ctx);

#ifdef SLOW
/* clq_update_lt_key: Updates the long_term_key between this member
 * and each other member.
 */
int clq_update_lt_key(CLQ_CONTEXT *ctx);
#endif 

/* clq_compute_one_lt_key: It computes one long term key between myself
 * and member->member_name.
 * Preconditions:
 *   ctx->private should be valid.
 *   ctx->params should be valid.
 */
int clq_compute_one_lt_key (CLQ_CONTEXT *ctx, CLQ_GM* member);

/* clq_creat_new_key: Creates new key for the group members using
 * his/her new random key (key_share). The long_term_key (K) is added
 * as well to the new key.
 */
int clq_creat_new_key_rm(CLQ_CONTEXT *ctx, int AddK,int calc_inv);
#define clq_creat_new_key(ctx,addk) clq_creat_new_key_rm(ctx,addk,FALSE)

/* Frees a CLQ_GML structure */
void clq_free_gml(CLQ_GML *gml);

/* Frees a CLQ_GM structure */
void clq_free_gm(CLQ_GM *gm);

/* clq_join_update_key: It update the last_partial keys of the entire
 * group. This is necessary when a new member has joined the group. It
 * removes Kij's between the current user and everybody else's, while
 * adding a new key_share for the user. Then a new node is created
 * where the last_partial_key data for the new user is dropped.
 * Preconditions: It is assumed that the member calling this function
 * is the current controller.
 */
int clq_join_update_key(CLQ_CONTEXT *ctx,CLQ_NAME *new_user);

int clq_leave_update_key(CLQ_CONTEXT *ctx);

/* clq_sanity_check: It does a sanity check on the each member
 * last_partial_key.
 * Returns: OK succeed 
 *          GML_EMPTY: Group member list is empty.
 *          ONE_RCVD: One has been received.
 *          ZERO_RCVD: Zero has been received.
 *          NUM_NOT_IN_GROUP: Number received is not valid (invalid modulus)
 */
int clq_sanity_check(CLQ_CONTEXT *ctx);

/* clq_rand: Generates a new random number of "num" bits, using the
 * default parameters.
 * Returns: A pointer to a dsa structure where the random value
 *          resides. 
 *          NULL if an error occurs.
 */
BIGNUM *clq_rand (DSA *params,BIGNUM *num);

/* clq_grt_rnd_val: generating a random number of 'q' bits */
#define clq_grt_rnd_val(params) clq_rand(params,DSA_get0_q(params))

/* clq_new_user: Called by the first user in the group or by new
 * users in a merge operation. 
 */
int clq_new_user(CLQ_CONTEXT **Ctx,CLQ_NAME *member_name, CLQ_NAME
		   *group_name, int set_gml);

/* clq_first_user: Called by the first user in the group only!
 * Everybody else has to call clq_join.
 */
#define clq_first_user(ctx,name,group) clq_new_user(ctx,name,group,TRUE)

/* clq_search_gml search a member in group member list. */
CLQ_GML *clq_search_gml (CLQ_GML *gml, CLQ_NAME *member_name);

CLQ_GML *clq_create_gml (CLQ_NAME *member_name);

int clq_create_name_list(CLQ_CONTEXT *ctx, CLQ_GML **static_gml, int zero_key);

/* clq_compute_secret_hash: It computes the hash of the group_secret.
 * Preconditions: ctx->group_secret has to be valid.
 */
int clq_compute_secret_hash (CLQ_CONTEXT *ctx);

/* clq_gml_update: It is used by clq_update_ctx and clq_factor_out to
 * update the group member list with the new one provided in the
 * new_ctx. 
 */
int clq_gml_update (CLQ_CONTEXT *ctx, CLQ_CONTEXT *new_ctx, 
		    enum MSG_TYPE m_type);


int clq_gml_cache_add (CLQ_CONTEXT *ctx, CLQ_GM* member);

#endif /* CLQ_API_H */
