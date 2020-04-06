/*********************************************************************
 * str_api.h                                                         * 
 * STR API main file                                                 * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef STR_API_H
#define STR_API_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "openssl/bn.h"
#include "openssl/dsa.h"
#include "openssl/x509.h"
#include "openssl/asn1.h"

#include "common.h"

#define STR_API_VERSION "1.0"

/* CLQ_NAME_LIST: Linked list of users */
typedef struct str_name_list {
  CLQ_NAME *member_name;
  struct str_name_list *next;
} STR_NAME_LIST;

/* STR_GM: Group member */
typedef struct str_gm_st {
  CLQ_NAME *member_name;
  X509 *cert;   /* X.509 certificate
                 * is not null, only if this is a leaf node
                 */
} STR_GM;

/* STR_NV: Node Values for this node */
typedef struct str_nv {
  STR_GM *member; /* Member information if this is a leaf node
                    * Null otherwise
                    */
  uint index;    /* index of this node for encoding and decoding
                  * intermediate node has even number
                  * member node has odd number
                  * exception: root=1, left-most member=even number 
                  */
  BIGNUM *key;   /* key if it is on the key-path
                  * null otherwise
                  */
  BIGNUM *bkey;  /* blinded key if it is on the co-path or key-path
                  * null otherwise
                  */
  int num_user;  /* Number of users */
} STR_NV;

/* Key tree data structures */
typedef struct str_key_tree {
  struct str_key_tree *parent; /* Pointer to the parent */
  struct str_key_tree *left;   /* Pointer to the left child */
  struct str_key_tree *right;  /* Pointer to the right child */
  struct str_key_tree *prev;   /* Pointer to the previous member, if any
                                * This is null, if this node is not
                                * a leaf node
                                */
  struct str_key_tree *next;   /* Pointer to the next member, if any
                                * This is null, if this node is not
                                * a leaf node
                               */
  struct str_key_tree *bfs;    /* Only for BFS */
  STR_NV *str_nv;              /* Node values if this node is intermediate */
} STR_KEY_TREE;

/* STR_CONTEXT: BGKA context */
typedef struct str_context_st {
  CLQ_NAME      *member_name;
  CLQ_NAME      *group_name;
  BIGNUM        *group_secret; 
  clq_uchar     *group_secret_hash; /* session_key */
  STR_KEY_TREE  *root;
  STR_KEY_TREE  *cache;
  DSA           *params;
  EVP_PKEY      *pkey;
  int           status;
  int           merge_token;
  BIGNUM        *tmp_key;
  BIGNUM        *tmp_bkey;
  uint          epoch;
} STR_CONTEXT;

/* MESSAGE TYPE definitions */
enum STR_MSG_TYPE { STR_KEY_MERGE_UPDATE,
                    STR_PROCESS_EVENT,
                    STR_INVALID};

typedef struct STR_token_info {
  CLQ_NAME *group_name;
  enum STR_MSG_TYPE message_type;
  time_t time_stamp;
  CLQ_NAME *sender_name;
  /*  uint epoch; */
} STR_TOKEN_INFO;

/* TOKEN_LIST: Linked list of tokens */
typedef struct STR_token_list {
  CLQ_TOKEN *token;
  struct STR_token_list *next;
  struct STR_token_list *end;
} STR_TOKEN_LIST;

/* STR_TREE_LIST: Lisked list of key trees to be used in self_cascade */
typedef struct STR_tree_list {
  STR_KEY_TREE *tree;
  struct STR_tree_list *next;
  struct STR_tree_list *end;
} STR_TREE_LIST;

/* str_new_member is called by the new member in order to create its
 *   own context. Main functionality of this function is to generate
 *   session random for the member
 */
int str_new_member(STR_CONTEXT **ctx, CLQ_NAME *member_name,
                   CLQ_NAME *group_name); 

/* str_merge_req is called by every member in both groups when network
 * faults heels and only one member in each group returns output
 * token. The member is selected by the node_select function. 
 *   ctx: context of the caller
 *   member_name: name of the caller
 *   group_name: target group name
 *   output: output token(input token of str_merge)
 */
int str_merge_req (STR_CONTEXT *ctx, CLQ_NAME *member_name, 
                   CLQ_NAME *group_name, CLQ_TOKEN **output);

/* str_partition is called by every member several times until every
 * member can compute the new group key when network faults occur.
 * Only the siblings of the living members return output.
 *   ctx: context of the caller
 *   member_name: name of the caller
 *   member_list: list of the leaving members
 *   input[]: Array of input tokens(previous output token of str_fission)
 *   output: output token(will be used as next input token of str_fission)
 */
int str_cascade(STR_CONTEXT **ctx, CLQ_NAME *group_name,
                CLQ_NAME *users_leaving[],
                STR_TOKEN_LIST *list, CLQ_TOKEN **output);

/* str_merge merges two tree using str_merge_tree */
STR_KEY_TREE *str_merge(STR_KEY_TREE *big_tree, STR_KEY_TREE *small_tree);

/* Make a tree list for merge */
STR_TREE_LIST *str_add_tree_list(STR_TREE_LIST *list, STR_KEY_TREE *tree);

/* str_create_ctx creates the tree context.
 * Preconditions: *ctx has to be NULL.
 */
int str_create_ctx(STR_CONTEXT **ctx);

/* str_compute_bkey: Computes and returns bkey */
BIGNUM *str_compute_bkey (BIGNUM *key, DSA *params);

/* str_rand: Generates a new random number of "params->q" bits, using
 *   the default parameters.
 * Returns: A pointer to a dsa structure where the random value
 *          resides. 
 *          NULL if an error occurs.
 */
BIGNUM *str_rand (DSA *params);

/* str_compute_secret_hash: It computes the hash of the group_secret.
 * Preconditions: ctx->group_secret has to be valid.
 */
int str_compute_secret_hash (STR_CONTEXT *ctx);

/* str_destroy_ctx frees the space occupied by the current context.
 * Including the group_members_list.
 *   if flag == 1, delete all context
 *   if flag == 0, delete all except the tree(used for merge)
 */
void str_destroy_ctx (STR_CONTEXT **ctx, int flag);

/* Frees a STR_TREE structure */
void str_free_tree(STR_KEY_TREE **tree);

/* Frees a TREE structure */
void str_free_node(STR_KEY_TREE **tree);

/* Frees a STR_NV structure */
void str_free_nv(STR_NV **nv);

/* Frees a STR_GM structure */
void str_free_gm(STR_GM **gm);

/* str_merge_tree returns root of a new tree which is the result of
 *   merging two trees
 * if option is 0, the caller of this funtion is not the sibling of
 *   the joining tree 
 * if option is 1, the caller of this function is the sibling
 */
STR_KEY_TREE *str_merge_tree(STR_KEY_TREE *joiner, STR_KEY_TREE *joinee);

/***********************/
/*TREE private functions*/
/***********************/
/* str_encode using information from the current context, it generates
 * the output token.
 */
int str_encode(STR_CONTEXT *ctx, CLQ_TOKEN **output,
               STR_TOKEN_INFO *info);

/* Converts tree structure to unsigned character string */
void str_map_encode(clq_uchar *stream, uint *pos, STR_KEY_TREE *root);

/* str_decode using information from the input token, it creates
 * ctx. info is also created here. It contains data recovered from
 * input such as message_type, sender, etc. (See structure for more
 * details) in readable format. 
 */
int str_decode(STR_CONTEXT **ctx, CLQ_TOKEN *input,
               STR_TOKEN_INFO **info);

/* str_map_decode decode input token to generate tree for the new
 *   tree
 * *tree should be pointer to the root node
 */
int str_map_decode(const CLQ_TOKEN *input, uint *pos, 
                   STR_CONTEXT **ctx);

/* str_create_token_info: It creates the info token. */
int str_create_token_info (STR_TOKEN_INFO **info, CLQ_NAME *group, 
                           enum STR_MSG_TYPE msg_type, time_t time,
                           CLQ_NAME *sender/*, uint epoch*/);

/* str_destroy_token_info: It frees the memory of the token. */
void str_destroy_token (CLQ_TOKEN **token);

/* str_destroy_token_info: It frees the memory of the token. */
void str_destroy_token_info (STR_TOKEN_INFO **info);
 
/* str_search_member: returns the pointer of the previous or the next
 *   member or the first or the last member
 *   if option is 0, this will return the pointer to the previous member
 *   if option is 1, this will return the pointer to the next member
 *     in the above two cases, tree is the starting leaf node in this
 *     searching 
 *   if option is 2, this will return the pointer to the first member
 *   if option is 3, this will return the pointer to the last member
 *   if option is 4 and member_name is not null, this will return the
 *     pointer to the node with that name
 */
STR_KEY_TREE *str_search_member(STR_KEY_TREE *tree, int option, 
				CLQ_NAME *member_name );

/* str_search_index: Returns the node having the index as a child */
STR_KEY_TREE *str_search_index(STR_KEY_TREE *tree, int index);

/* str_update_index: update index of the input tree by 1
 * index 0 is for the left node
 * index > 0 is for the right node
 */
void str_update_index(STR_KEY_TREE *tree, int index, int root_index);  

/* Updates potential and joinQ except the leaf node
 * Leaf node should be precomputed before
 */
void str_update_potential(STR_KEY_TREE *tree);

/* str_copy tree structure, but to finish the real copy, we need to
   call str_dup_tree, which finishes prev and next pointer */  
STR_KEY_TREE *str_copy_tree(STR_KEY_TREE *src);
/* str_dup_tree finishes the copy process of one tree to
   another... Mainly, it just handles prev and next pointer */
STR_KEY_TREE *str_dup_tree(STR_KEY_TREE *src);
/* str_copy_node copies str_nv values of src node to dst node */
void str_copy_node(STR_KEY_TREE *src, STR_KEY_TREE *dst);
/* str_swap_bkey swap my null bkey with meaningful bkey from new token */
void str_swap_bkey(STR_KEY_TREE *src, STR_KEY_TREE *dst);
/* str_copy_bkey copies meaningful bkey from new token to my null
   token, used for cache update */
void str_copy_bkey(STR_KEY_TREE *src, STR_KEY_TREE *dst);
/* str_check_useful checks whether new_ctx has useful information
 * If it has, return 1,
 * else, return 0
 */
int str_check_useful(STR_KEY_TREE *newtree, STR_KEY_TREE *mytree);
/* str_init_bfs initializes(nullfies) bfs pointers for each node */
void str_init_bfs(STR_KEY_TREE *tree);

/* remove_sponsor: remove the sponsor from the sponsor list */
int str_remove_sponsor(CLQ_NAME *sponsor_list[], CLQ_NAME *sponsor);

/* Remove all tree list */
void STR_remove_tree_list(STR_TREE_LIST **list);

#endif
