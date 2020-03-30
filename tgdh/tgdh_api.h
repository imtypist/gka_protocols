/*********************************************************************
 * tree.h                                                            * 
 * TGDH main header file                                             * 
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

#ifndef TGDH_API_H
#define TGDH_API_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "openssl/bn.h"
#include "openssl/dsa.h"
#include "openssl/x509.h"
#include "openssl/asn1.h"

#include "common.h"

#define TGDH_API_VERSION "1.0"

/* TGDH_NAME_LIST: Linked list of users */
typedef struct tgdh_name_list {
  CLQ_NAME *member_name;
  struct tgdh_name_list *next;
} TGDH_NAME_LIST;

/* TGDH_GM: Group member */
typedef struct tgdh_gm_st {
  CLQ_NAME *member_name;
  X509 *cert;   /* X.509 certificate
                 * is not null, only if this is a leaf node
                 */
} TGDH_GM;

/* TGDH_NV: Node Values for this node */
typedef struct tgdh_nv {
  TGDH_GM *member; /* Member information if this is a leaf node
                    * Null otherwise
                    */
  uint index;    /* index of this node for encoding and decoding
                  * left child has 2 * index as the index, and 
                  * right child has 2 * index + 1 has the index
                  */
  BIGNUM *key;   /* key if it is on the key-path
                  * null otherwise
                  */
  BIGNUM *bkey;  /* blinded key if it is on the co-path or key-path
                  * null otherwise
                  */
  uint joinQ;    /* True(1) if this node is joinable
                  * False(0) otherwise
                  */
  int potential; /* Maximum height of a tree that can be joined to
                  * a node in this tree which has this node as a root
                  */
  int height;    /* Height of this tree
                  * is not -1, only if this node is root
                  */
  int num_node; /* For easy encoding and decoding */
} TGDH_NV;

/* Key tree data structures */
typedef struct key_tree {
  struct key_tree *parent; /* Pointer to the parent */
  struct key_tree *left;   /* Pointer to the left child */
  struct key_tree *right;  /* Pointer to the right child */
  struct key_tree *prev;   /* Pointer to the previous member, if any
                            * This is null, if this node is not
                            * a leaf node
                            */
  struct key_tree *next;   /* Pointer to the next member, if any
                            * This is null, if this node is not
                            * a leaf node
                            */
  struct key_tree *bfs;    /* Special pointer to be used in BFS */
  TGDH_NV *tgdh_nv;        /* Node values if this node is intermediate */
} KEY_TREE;

/* TGDH_CONTEXT: BGKA context */
typedef struct tgdh_context_st {
  CLQ_NAME *member_name;
  CLQ_NAME *group_name;
  BIGNUM *group_secret; 
  clq_uchar *group_secret_hash; /* session_key */
  KEY_TREE *root;
  KEY_TREE *cache;
  DSA *params;
  EVP_PKEY *pkey;
  int status;
  int merge_token;
  BIGNUM *tmp_key;
  BIGNUM *tmp_bkey;
  uint epoch;
} TGDH_CONTEXT;

/* MESSAGE TYPE definitions */
enum TGDH_MSG_TYPE { TGDH_KEY_MERGE_UPDATE,
                     PROCESS_EVENT,
                     TGDH_INVALID};

typedef struct TGDH_token_info {
  CLQ_NAME *group_name;
  enum TGDH_MSG_TYPE message_type;
  time_t time_stamp;
  CLQ_NAME *sender_name;
  /*  uint epoch; */
} TGDH_TOKEN_INFO;

/* TOKEN_LIST: Linked list of tokens */
typedef struct token_list {
  CLQ_TOKEN *token;
  struct token_list *next;
  struct token_list *end;
} TOKEN_LIST;

/* TREE_LIST: Linked list of key trees to be used in tgdh_cascade */
typedef struct tree_list {
  KEY_TREE *tree;
  struct tree_list *next;
  struct tree_list *end;
} TREE_LIST;

/* tgdh_new_member is called by the new member in order to create its
 *   own context. Main functionality of this function is to generate
 *   session random for the member
 */
int tgdh_new_member(TGDH_CONTEXT **ctx, CLQ_NAME *member_name,
                    CLQ_NAME *group_name); 

/* tgdh_merge_req is called by every members in both groups and only
 * the sponsors will return a output token
 *   o When any addtive event happens this function will be called.
 *   o In other words, if merge and leave happen, we need to call this
 *     function also.
 *   o If only addtive event happens, users_leaving should be NULL.
 *   ctx: context of the caller
 *   member_name: name of the caller
 *   users_leaving: name of the leaving members
 *   group_name: target group name
 *   output: output token(input token of tgdh_merge)
 */
int tgdh_merge_req (TGDH_CONTEXT *ctx, CLQ_NAME *member_name, 
                    CLQ_NAME *group_name, CLQ_NAME *users_leaving[],
                    CLQ_TOKEN **output);

/* tgdh_cascade is called by every member several times until every
 * member can compute the new group key when network faults occur.
 * Only the sponsors return output.
 *   ctx: context of the caller
 *   member_name: name of the caller
 *   member_list: list of the leaving members
 *   list: Linked list of input tokens(previous output token of
 *         tgdh_cascade or tgdh_merge_req )
 *   output: output token(will be used as next input token of tgdh_cascade)
 */
int tgdh_cascade(TGDH_CONTEXT **ctx, CLQ_NAME *group_name,
                 CLQ_NAME *users_leaving[],
                 TOKEN_LIST *list, CLQ_TOKEN **output);

/* tgdh_create_ctx creates the tree context.
 * Preconditions: *ctx has to be NULL.
 */
int tgdh_create_ctx(TGDH_CONTEXT **ctx);

/* tgdh_compute_bkey: Computes and returns bkey */
BIGNUM *tgdh_compute_bkey (BIGNUM *key, DSA *params);

/* tgdh_rand: Generates a new random number of "params->q" bits, using
 *   the default parameters.
 * Returns: A pointer to a dsa structure where the random value
 *          resides. 
 *          NULL if an error occurs.
 */
BIGNUM *tgdh_rand (DSA *params);

/* tgdh_compute_secret_hash: It computes the hash of the group_secret.
 * Preconditions: ctx->group_secret has to be valid.
 */
int tgdh_compute_secret_hash (TGDH_CONTEXT *ctx);

/* tgdh_destroy_ctx frees the space occupied by the current context.
 * Including the group_members_list.
 *   if flag == 1, delete all context
 *   if flag == 0, delete all except the tree(used for merge)
 */
void tgdh_destroy_ctx (TGDH_CONTEXT **ctx, int flag);

/* Frees a TGDH_TREE structure */
void tgdh_free_tree(KEY_TREE **tree);

/* Frees a TREE structure */
void tgdh_free_node(KEY_TREE **tree);

/* Frees a TGDH_NV structure */
void tgdh_free_nv(TGDH_NV **nv);

/* Frees a TGDH_GM structure */
void tgdh_free_gm(TGDH_GM **gm);

/* tgdh_merge_tree returns root of a new tree which is the result of
 *   merging two trees
 * if option is 0, the caller of this funtion is not the sibling of
 *   the joining tree 
 * if option is 1, the caller of this function is the sibling
 */
KEY_TREE *tgdh_merge_tree(KEY_TREE *joiner, KEY_TREE *joinee);

/***********************/
/*TREE private functions*/
/***********************/
/* tgdh_encode using information from the current context, it generates
 * the output token.
 */
int tgdh_encode(TGDH_CONTEXT *ctx, CLQ_TOKEN **output,
                TGDH_TOKEN_INFO *info);

/* Converts tree structure to unsigned character string */
void tgdh_map_encode(clq_uchar *stream, uint *pos, KEY_TREE *root);

/* tgdh_decode using information from the input token, it creates
 * ctx. info is also created here. It contains data recovered from
 * input such as message_type, sender, etc. (See structure for more
 * details) in readable format. 
 */
int tgdh_decode(TGDH_CONTEXT **ctx, CLQ_TOKEN *input,
                TGDH_TOKEN_INFO **info);

/* tgdh_map_decode decode input token to generate tree for the new
 *   tree
 * *tree should be pointer to the root node
 */
int tgdh_map_decode(const CLQ_TOKEN *input, uint *pos, 
                    TGDH_CONTEXT **ctx);

/* tgdh_create_token_info: It creates the info token. */
int tgdh_create_token_info (TGDH_TOKEN_INFO **info, CLQ_NAME *group, 
                            enum TGDH_MSG_TYPE msg_type, time_t time,
                            CLQ_NAME *sender/*, uint epoch*/);

/* tgdh_destroy_token_info: It frees the memory of the token. */
void tgdh_destroy_token (CLQ_TOKEN **token);

/* tgdh_destroy_token_info: It frees the memory of the token. */
void tgdh_destroy_token_info (TGDH_TOKEN_INFO **info);
 
/* tgdh_search_member: returns the pointer of the previous or the next
 *   member or the first or the last member
 *   if option is 0, this will return the pointer to the previous member
 *   if option is 1, this will return the pointer to the next member
 *     in the above two cases, tree is the starting leaf node in this
 *     searching 
 *   if option is 2, this will return the pointer to the first member
 *   if option is 3, this will return the pointer to the last member
 *   if option is 4 and member_name is not null, this will return the
 *     pointer to the node with that name
 *   if option is 5, this will return the pointer to the root
 *   if option is 6, this will return the shallowest leaf node
 */
KEY_TREE *tgdh_search_member(KEY_TREE *tree, int option, 
                             CLQ_NAME *member_name );

/* tgdh_search_node: Returns the first fit or worst fit node
 *   if option is 0, search policy is the first fit
 *   if option is 1, search policy is the best fit
 * The return value is NULL, if the joiner cannot join 
 *   to a subtree of joinee
 * Otherwise, it returns the node(first fit or best fit)
 */
KEY_TREE *tgdh_search_node(KEY_TREE *joiner, KEY_TREE *joinee,
                           int option);

/* tgdh_search_index: Returns the node having the index as a child */
KEY_TREE *tgdh_search_index(KEY_TREE *tree, int index);

/* tgdh_update_index: update index of the input tree by 1
 * index 0 is for the left node
 * index > 0 is for the right node
 */
void tgdh_update_index(KEY_TREE *tree, int index, int root_index);  

/* Updates potential and joinQ except the leaf node
 * Leaf node should be precomputed before
 */
void tgdh_update_potential(KEY_TREE *tree);

/* tgdh_update_index: update joinQ, potential of key_path
 */
void tgdh_update_key_path(KEY_TREE **tree);

/* tgdh_copy tree structure, but to finish the real copy, we need to
   call tgdh_dup_tree, which finishes prev and next pointer */  
KEY_TREE *tgdh_copy_tree(KEY_TREE *src);
/* tgdh_dup_tree finishes the copy process of one tree to
   another... Mainly, it just handles prev and next pointer */
KEY_TREE *tgdh_dup_tree(KEY_TREE *src);
/* tgdh_copy_node copies tgdh_nv values of src node to dst node */
void tgdh_copy_node(KEY_TREE *src, KEY_TREE *dst);
/* tgdh_swap_bkey swap my null bkey with meaningful bkey from new token */
void tgdh_swap_bkey(KEY_TREE *src, KEY_TREE *dst);
/* tgdh_copy_bkey copy meaningful bkey from new token to my null
   token, used for cache update */
void tgdh_copy_bkey(KEY_TREE *src, KEY_TREE *dst);
/* tgdh_check_useful checks whether new_ctx has useful information
 * If it has, return 1,
 * else, return 0
 */
int tgdh_check_useful(KEY_TREE *newtree, KEY_TREE *mytree);
/* tgdh_init_bfs initializes(nullfies) bfs pointers for each node */
void tgdh_init_bfs(KEY_TREE *tree);

/* remove_sponsor: remove the sponsor from the sponsor list */
int remove_sponsor(CLQ_NAME *sponsor_list[], CLQ_NAME *sponsor);

/* leaderQ: true if I am the right-most bottom-most subnode of the
     tree, false otherwise
*/
int leaderQ(KEY_TREE *tree, CLQ_NAME *my_name);

/* remove_member removes leaving members from the current tree.
 * o Reason for this function: It was leave part of tgdh_cascade
 *    function, but I decided to make a function since we need to add
 *    this functionality to tgdh_merge_req too...
 * o What is it doing?
 *   - This function will only remove the leaving members...
 *   - No key update happens...
 */
int remove_member(TGDH_CONTEXT *ctx, CLQ_NAME *users_leaving[],
                  KEY_TREE *sponsor_list[]);

/* Find all sponsors */
int find_sponsors(KEY_TREE *root, KEY_TREE *sponsor_list[]);


/* Make a tree list for merge */
TREE_LIST *add_tree_list(TREE_LIST *list, KEY_TREE *tree);
/* Remove all tree list */
void remove_tree_list(TREE_LIST **list);

/* tgdh_merge merges two tree using tgdh_merge_tree */
KEY_TREE *tgdh_merge(KEY_TREE *big_tree, KEY_TREE *small_tree);

#endif
