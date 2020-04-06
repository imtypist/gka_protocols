/*********************************************************************
 * str_api_misc.c                                                    * 
 * STR api miscellaneous source file.                                * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <stdio.h>
/* The next three are needed for creat() in str_gen_params */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <unistd.h>
#include <malloc.h>

#ifdef TIMING
/* Needed by getrusgae */
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

int print=1;

#endif

/* SSL include files */
#include "openssl/bio.h"
#include "openssl/dsa.h"
#include "openssl/bn.h"
#include "openssl/rand.h"
#include "openssl/md5.h"

/* STR_API include files */
#include "str_api.h"
#include "str_api_misc.h"
#include "common.h"

#ifdef MEMCHECK
int number_malloc[length_memcheck];
int number_free[length_memcheck];
#endif

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

int str_print_dsa(DSA *dsa) {
  char *tmp;
  
  if (dsa == NULL) { 
    fprintf(ERR_STRM,"Invalid DSA structure.\n"); 
    return 0;
  }

  fprintf(ERR_STRM,"\n--- begin DSA structure ---\n");
  fprintf(ERR_STRM,"Size: %d\n\n",DSA_get0_p(dsa)==NULL ? 0: BN_num_bits(DSA_get0_p(dsa)));
  tmp=BN_bn2hex(DSA_get0_p(dsa));
  fprintf(ERR_STRM,"p = %s\n", tmp==NULL ? "n.d.": tmp);
  free(tmp); tmp=BN_bn2hex(DSA_get0_q(dsa));
  fprintf(ERR_STRM,"q = %s\n", tmp==NULL ? "n.d.": tmp);
  free(tmp); tmp=BN_bn2hex(DSA_get0_g(dsa));
  fprintf(ERR_STRM,"g = %s\n\n", tmp==NULL ? "n.d.": tmp);
  free(tmp); tmp=BN_bn2hex(DSA_get0_priv_key(dsa));
  fprintf(ERR_STRM,"secr = %s\n", tmp==NULL ? "n.d.": tmp);
  free(tmp); tmp=BN_bn2hex(DSA_get0_pub_key(dsa));
  fprintf(ERR_STRM,"pub  = %s\n", tmp==NULL ? "n.d.": tmp);
  free (tmp);
  fprintf(ERR_STRM,"\n--- end DSA structure ---\n");

  return 1;
}

void str_print_ctx(char *name, STR_CONTEXT *ctx){

  fprintf(ERR_STRM,"\n--- %s ---\n\t", name);
  if(ctx == NULL) {
    fprintf(ERR_STRM,"CTX for %s is null\t", name);
    return;
  }
  if(ctx->member_name != NULL)
    fprintf(ERR_STRM,"name     = %s\t", ctx->member_name);
  else fprintf(ERR_STRM,"name     = NULL\t");
  if(ctx->group_name != NULL)
    fprintf(ERR_STRM,"group    = %s\t", ctx->group_name);
  else fprintf(ERR_STRM,"group    = NULL\t");
  if(ctx->group_secret != NULL){
    fprintf(ERR_STRM,"grpsecret= ");
    BN_print_fp(ERR_STRM, ctx->group_secret);
    fprintf(ERR_STRM,"\n");
  }
  else fprintf(ERR_STRM,"grpsecret= NULL\n");
  if(ctx->epoch != (int)NULL){
    fprintf(ERR_STRM,"epoch= %d\n", ctx->epoch);
  }
  else fprintf(ERR_STRM,"epoch= NULL\n");

  str_print_all(name, ctx->root);

  return;
}

/* str_search_number: Returns the node having the index
 */
STR_KEY_TREE *str_search_number(STR_KEY_TREE *tree, int index)
{
  int height=0;
  int i;
  STR_KEY_TREE *tmp_tree;
  
  height = clq_log2(index);
  
  tmp_tree = tree;
  
  for(i=1; i<=height; i++){
    if((index >> (height-i)) & 0x1){
      if(tmp_tree->right == NULL) return NULL;
      else tmp_tree = tmp_tree->right;
    }
    else{
      if(tmp_tree->left == NULL) return NULL;
      else tmp_tree = tmp_tree->left;
    }
  }
  
  return tmp_tree;
}

void str_print_node(char *name, STR_KEY_TREE *tree) {
  fprintf(ERR_STRM,"\n\t---tree print %s ---\n\t", name);
  if(tree->str_nv != NULL){
    fprintf(ERR_STRM,"index     = %d\t", tree->str_nv->index);
    if(tree->str_nv->num_user > -2)
      fprintf(ERR_STRM,"num_user  = %d\n\t", tree->str_nv->num_user);
    else fprintf(ERR_STRM,"num_user  = NULL\n\t");
    if(tree->str_nv->key != NULL){
      fprintf(ERR_STRM,"key  = ");
      BN_print_fp(ERR_STRM, tree->str_nv->key);
    }
    else fprintf(ERR_STRM,"key  = NULL");
    if(tree->str_nv->bkey != NULL){
      fprintf(ERR_STRM,"\n\tbkey = ");
      BN_print_fp(ERR_STRM, tree->str_nv->bkey);
    }
    else fprintf(ERR_STRM,"\n\tbkey = NULL");
    fprintf(ERR_STRM,"\n\tmypt      = %x\t", (int)tree);
    if(tree->str_nv->member != NULL){
      if(tree->str_nv->member->member_name != NULL)
        fprintf(ERR_STRM,"name      = %s\n\t", tree->str_nv->member->member_name);
      else fprintf(ERR_STRM, "name     = NULL\n\t");  
      if(tree->str_nv->member->cert != NULL)
        fprintf(ERR_STRM,"cert      = %x\n\t", (int)tree->str_nv->member->cert);
      else fprintf(ERR_STRM, "cert     = NULL\n\t");  
    }
    if(tree->parent != NULL)
      fprintf(ERR_STRM,"prntpt    = %x\t", (int)tree->parent);
    if(tree->left != NULL)
      fprintf(ERR_STRM,"leftpt    = %x\t", (int)tree->left);
    if(tree->right != NULL)
      fprintf(ERR_STRM,"rightpt   = %x\t", (int)tree->right);
    if(tree->prev != NULL)
      fprintf(ERR_STRM,"prevpt    = %x\t", (int)tree->prev);
    if(tree->next != NULL)
      fprintf(ERR_STRM,"nextpt    = %x\t", (int)tree->next);
  }
  
  return;
}

void str_print_all(CLQ_NAME *name, STR_KEY_TREE *tree) {
  if(tree == NULL) return;
  str_print_node(name,tree);
  str_print_all(name, tree->left);
  str_print_all(name, tree->right);
}

int compare_key(STR_CONTEXT *ctx[], int num) {
  int i=0;
  BIGNUM *tmp_key=NULL;

  for(i=0; i<num; i++)
    if(ctx[i])
      if(ctx[i]->root->str_nv->key)
        tmp_key=ctx[i]->root->str_nv->key;

  
  for(i=0; i<num; i++){
    if(ctx[i] != NULL){
      if(BN_cmp(tmp_key, ctx[i]->root->str_nv->key) != 0){
        fprintf(stderr, "()()())(()()()()()()()()()\n");
        return -1;
      }
    }
    else{
      printf("***************Some context is empty\n");
    }
  }
  
#ifdef DEBUG_ALL    
  fprintf(stderr, "\n\n\nAll right... All keys are same!!!\n");
  fprintf(stderr, "All right... All keys are same!!!\n");
  fprintf(stderr, "All right... All keys are same!!!\n");
#endif
  
  return 1;
}

/* str_write_dsa: Writes the dsa structure into outfile. 
 * oper could be any of the following: 
 * PUB_FMT, PRV_FMT
 * dsa should be a valid pointer.
 * If outfile is NULL, then stdout will be used.
 * Returns 1 if succeed 0 otherwise.
 * Note: This function should be used in conjuction with
 * clq_read_dsa (i.e. USE_CLQ_READ_DSA should be defined.)
 */
int str_write_dsa(DSA *dsa, char *oper, char *outfile) {
  BIO *out=NULL;
  int i=0;
  int ok=0;
  char oper_str[30];

  strcpy(oper_str, "Invalid.");
  
  out=BIO_new(BIO_s_file());
  if (out == NULL) {
    fprintf (ERR_STRM,"Error: Could not create bio file.\n");
    goto end;
  }

  /* If this is NULL, then stdout will be used. */
  if(outfile != NULL) { 
    if (BIO_write_filename(out,outfile) <= 0) {
      perror(outfile); 
      goto end;
    }
#ifdef DEBUG_MISC
    fprintf(ERR_STRM,"Creating file %s.\n", outfile);
#endif
  } 
  else BIO_set_fp(out,stdout,BIO_NOCLOSE);

#ifdef DEBUG_MISC
  fprintf(ERR_STRM,"\tWriting DSA "); 
#endif
  
  if(!strcmp(oper,"params")) {
    strcpy (oper_str,"parameters");
    i=i2d_DSAparams_bio(out,dsa);
  }
  else if(!strcmp(oper,PUB_FMT)) {
    strcpy (oper_str,"public key");
    i=i2d_DSAPublicKey_bio(out,dsa);
  }
  else if(!strcmp(oper,PRV_FMT)) {
    strcpy (oper_str,"private key");
    i=i2d_DSAPrivateKey_bio(out,dsa);
  }

#ifdef DEBUG_MISC
  fprintf(ERR_STRM," %s.\n",oper_str);
#endif

  if (!i) {
    fprintf(ERR_STRM,"ERROR: Unable to write DSA %s.\n",oper_str);
    goto end;
  }

  ok = 1;

end:
  if (out != NULL) BIO_free(out);

  return ok;
}

/* str_get_secret: Returns in a static variable with
 * ctx->group_secret_hash 
 */ 
clq_uchar *str_get_secret(STR_CONTEXT *ctx) {
  static clq_uchar tmp[MD5_DIGEST_LENGTH];

  memcpy (tmp,ctx->group_secret_hash,MD5_DIGEST_LENGTH);

  return tmp;
}

void str_print_group_secret(STR_CONTEXT *ctx) {
  int i;

  fprintf(ERR_STRM,"Group Secret (MD5): ");
  if (ctx->group_secret_hash == NULL) fprintf (ERR_STRM,"EMPTY");
  else {
    for (i=0; i < MD5_DIGEST_LENGTH; i++) 
      fprintf(ERR_STRM, "%02X",ctx->group_secret_hash[i]);
  }

  fprintf(ERR_STRM,"\n");
}
