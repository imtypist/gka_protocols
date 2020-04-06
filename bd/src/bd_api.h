/*********************************************************************
 * bd_api.h                                                          * 
 * Broadcast based Group Key Ageement Scheme                         * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef BD_API_H
#define BD_API_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "openssl/bn.h"
#include "openssl/dsa.h"
#include "openssl/x509.h"
#include "openssl/asn1.h"

#include "common.h"

#define BD_API_VERSION "0.9"

/* CLQ_NAME_LIST: Linked list of users */
typedef struct bd_name_list {
  CLQ_NAME *member_name;
  struct bd_name_list *next;
} CLQ_NAME_LIST;

/* BD_GM: Group member */
typedef struct bd_gm_st {
  CLQ_NAME *member_name;
  X509 *cert;   /* X.509 certificate
                 * is not null, only if this is a leaf node
                 */
} BD_GM;

/* BD_NV: Node Values for this node */
typedef struct bd_nv {
  BD_GM *member; /* Member information */
  BIGNUM *z_i;   /* z_i */
  BIGNUM *x_i;   /* x_i */
} BD_NV;

/* member list data structures */
typedef struct member_list {
  struct member_list *prev;   /* Pointer to the previous member */
  struct member_list *next;   /* Pointer to the next member */
  BD_NV *bd_nv;               /* Node values */
} MEMBER_LIST;

/* BD_CONTEXT: BGKA context */
typedef struct bd_context_st {
  CLQ_NAME     *member_name;
  CLQ_NAME     *group_name;
  BIGNUM      *group_secret; 
  clq_uchar    *group_secret_hash; /* session_key */
  BIGNUM      *r_i;               /* session random of the member */
  int         num_users;
  MEMBER_LIST *list;              /* Pointer to the first member */
  DSA         *params;
  EVP_PKEY    *pkey;
  uint        epoch;
} BD_CONTEXT;

/* MESSAGE TYPE definitions */
enum BD_MSG_TYPE { BROADCAST_Z,
                   BROADCAST_X,
                   BD_INVALID};

typedef struct BD_token_info {
  CLQ_NAME *group_name;
  enum BD_MSG_TYPE message_type;
  time_t time_stamp;
  CLQ_NAME *sender_name;
  BIGNUM *key_info;
  uint epoch; 
} BD_TOKEN_INFO;

/* bd_new_member is called by the new member in order to create its
 *   own context.
 */
int bd_new_member(BD_CONTEXT **ctx, CLQ_NAME *member_name,
                  CLQ_NAME *group_name);

/* bd_refresh_session refreshes (or generates, if session random is
   NULL) session random of each user */ 
int bd_refresh_session(BD_CONTEXT *ctx);

/* Main functionality of this function is to broadcast session random
 *   of a user... If flag == 0 (when cascading happens), it will not
 *   refresh the session random. If it is 1, it will refresh the
 *   session random.
 */
int bd_membership_req(BD_CONTEXT *ctx, CLQ_NAME *member_name,
                      CLQ_NAME *group_name, CLQ_NAME *member_list[], 
                      CLQ_TOKEN **output, int flag);

/* bd_compute_xi computes X_i for other members. I need z_{i+1} and
 *   z_{i-1} to compute my x_i
 */
int bd_compute_xi (BD_CONTEXT *ctx, CLQ_NAME *member_name, 
                   CLQ_NAME *group_name, CLQ_TOKEN *input,
                   CLQ_TOKEN **output); 

/* bd_compute_key computes key. I need z_{i-1} and all x_i's */
int bd_compute_key (BD_CONTEXT *ctx, CLQ_NAME *member_name, 
                    CLQ_NAME *group_name, CLQ_TOKEN *input); 

/* bd_create_ctx creates the tree context.
 * Preconditions: *ctx has to be NULL.
 */
int bd_create_ctx(BD_CONTEXT **ctx);

/* bd_rand: Generates a new random number of "params->q" bits, using
 *   the default parameters.
 * Returns: A pointer to a dsa structure where the random value
 *          resides. 
 *          NULL if an error occurs.
 */
BIGNUM *bd_rand (DSA *params);

/* bd_compute_secret_hash: It computes the hash of the group_secret.
 * Preconditions: ctx->group_secret has to be valid.
 */
int bd_compute_secret_hash (BD_CONTEXT *ctx);

/* bd_destroy_ctx frees the space occupied by the current context.
 * Including the group_members_list.
 */
void bd_destroy_ctx (BD_CONTEXT **ctx);

/* Frees a MEMBER_LIST structure */
void bd_free_list(MEMBER_LIST **member_list);

/* Frees a BD_NV structure */
void bd_free_nv(BD_NV **nv);

/* Frees a BD_GM structure */
void bd_free_gm(BD_GM **gm);

/***********************/
/*TREE private functions*/
/***********************/
/* bd_encode using information from the current context, it generates
 * the output token.
 */
int bd_encode(BD_CONTEXT *ctx, CLQ_TOKEN **output,
              BD_TOKEN_INFO *info, int option);

/* bd_decode using information from the input token, it creates
 * ctx. info is also created here. It contains data recovered from
 * input such as message_type, sender, etc. (See structure for more
 * details) in readable format. 
 */
int bd_decode(CLQ_TOKEN *input, BD_TOKEN_INFO **info);

/* bd_create_token_info: It creates the info token. */
int bd_create_token_info (BD_TOKEN_INFO **info, CLQ_NAME *group, 
                           enum BD_MSG_TYPE msg_type, time_t time,
                           CLQ_NAME *sender/*, uint epoch*/);

/* bd_destroy_token: It frees the memory of the token. */
void bd_destroy_token (CLQ_TOKEN **token);

/* bd_destroy_token_info: It frees the memory of the token. */
void bd_destroy_token_info (BD_TOKEN_INFO **info);
 
/* bd_search_list finds a member named member_name */
MEMBER_LIST *bd_search_list(MEMBER_LIST *list, CLQ_NAME *member_name);

/* bd_computable checks whether the member receives all x_i's and z_i
 * returns 1, if enough. Returns 0 otherwise
 */
int bd_computable(MEMBER_LIST *list, CLQ_NAME *my_name);


#endif
