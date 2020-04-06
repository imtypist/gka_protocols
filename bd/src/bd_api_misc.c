/*********************************************************************
 * bd_api_misc.c                                                     * 
 * Burmester-Desmedt miscellaneous source file.                      * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <stdio.h>
/* The next three are needed for creat() in bd_gen_params */
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

/* BD_API include files */
#include "bd_api.h"
#include "bd_api_misc.h"
#include "common.h"

int bd_print_dsa(DSA *dsa) {
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

void bd_print_ctx(char *name, BD_CONTEXT *ctx){

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

  return;
}

int compare_key(BD_CONTEXT *ctx[], int num) {
  int i=0;
  BIGNUM *tmp_key=NULL;

  for(i=0; i<num; i++){
    if(ctx[i]){
      if(ctx[i]->group_secret){
        tmp_key=ctx[i]->group_secret;
      }
    }
  }
  for(i=0; i<num; i++){
    if(ctx[i] != NULL){
      if(BN_cmp(tmp_key, ctx[i]->group_secret) != 0){
        fprintf(stderr, "()()())(()()()()()()()()()\n");
        return -1;
      }
    }
    else{
    }
  }
  
#ifdef VERBOSE
  fprintf(stderr, "\n\n\nAll right... All keys are same!!!\n");
#endif
  
  return 1;
}

/* bd_write_dsa: Writes the dsa structure into outfile. 
 * oper could be any of the following: 
 * PUB_FMT, PRV_FMT
 * dsa should be a valid pointer.
 * If outfile is NULL, then stdout will be used.
 * Returns 1 if succeed 0 otherwise.
 * Note: This function should be used in conjuction with
 * clq_read_dsa (i.e. USE_CLQ_READ_DSA should be defined.)
 */
int bd_write_dsa(DSA *dsa, char *oper, char *outfile) {
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

/* bd_get_secret: Returns in a static variable with
 * ctx->group_secret_hash 
 */ 
clq_uchar *bd_get_secret(BD_CONTEXT *ctx) {
  static clq_uchar tmp[MD5_DIGEST_LENGTH];

  memcpy (tmp,ctx->group_secret_hash,MD5_DIGEST_LENGTH);

  return tmp;
}

void bd_print_group_secret(BD_CONTEXT *ctx) {
  int i;

  fprintf(ERR_STRM,"Group Secret (MD5): ");
  if (ctx->group_secret_hash == NULL) fprintf (ERR_STRM,"EMPTY");
  else {
    for (i=0; i < MD5_DIGEST_LENGTH; i++) 
      fprintf(ERR_STRM, "%02X",ctx->group_secret_hash[i]);
  }

  fprintf(ERR_STRM,"\n");
}
