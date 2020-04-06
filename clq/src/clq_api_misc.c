/*********************************************************************
 * clq_api_misc.c                                                    * 
 * CLQ api miscellaneous source file.                                * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#include <stdio.h>
/* The next three are needed for creat() in clq_gen_params */
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

/* CLQ_API include files */
#include "clq_api.h"
#include "clq_api_misc.h"
#include "common.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

/* clq_gen_params: Generates the common DSA parameters
 * (i.e. p,q,alpha). p_size specify the size of the prime p in bits.
 * Returns 1 if succeed 0 otherwise.
 * Note: This function should be used in conjuction with
 * clq_read_dsa (i.e. USE_CLQ_READ_DSA should be defined.)
 */
int clq_gen_params (int p_size) {
  DSA *dsa=NULL;
  char buffer[200];
  char *randfile=NULL;
  int ok = 0;
  int rnum;

  fprintf(ERR_STRM,"Generating common parameters (p,q and alpha)...\n");
  fprintf(ERR_STRM,"p = %d bits, q = %d bits\n", p_size, Q_SIZE_IN_BITS);

  /* Now we are initializing the random seed. Although, randfile is
   * not used anywhere else, these lines are required before calling
   * DSA_generate_parameters. This is needed because inside
   * DSA_generate parameters RAND_bytes is called (since seed_len is 0) 
   * and before calling this function RAND_seed has to be called (from
   * rand.doc) which occurs inside RAND_load_file.
   * One can specify a random file by setting the RANDFILE environemnt
   * variable. By default is: $HOME/.rnd defined in e_os.h
   * Note: The only purpose of this random file is to get stats of it.
   */
  randfile=(char*)RAND_file_name(buffer,200);
  if (randfile == NULL) goto end;
  if (!(rnum=RAND_load_file(randfile,1024L*1024L))) {
    /* RANDFILE doesn't exist. Let's create one. */
    close(creat(randfile,0400)); /* Creating a read_only file */
    fprintf(ERR_STRM,"Creating file '%s'.\n",randfile);
    /* Let's try again */
    if (!(rnum=RAND_load_file(randfile,1024L*1024L))) {
      fprintf(ERR_STRM,"Unable to load 'random state'.\n");
      goto end;
    }
  }
  if (rnum == 0)
    fprintf(ERR_STRM,"Warning, not much extra random data.\n");
      
  /* Initializing the parameters of DSA. The second argument is
   * NULL, since we are not using any seed. The third argument is
   * the size of the seed. The forth argument returns the number of
   * iterations it took to generate the prime p. The fifth argument
   * returns the number of iterations it took to generate the prime
   * q. The sixth arg. is just a call back function (now is NULL)
   * and its arguments.
   */
  dsa=DSA_generate_parameters(p_size,NULL,0,NULL,NULL,NULL,NULL);
  if (dsa == (DSA *)NULL) {
    fprintf(ERR_STRM,"Error while generating the common parameters.\n");
    goto end;
  }
#ifdef DEBUG_MISC
    clq_print_dsa(dsa);
#endif

  fprintf(ERR_STRM,"Done.\n");

  if (!clq_write_dsa(dsa,"params",COMMON_FILE)) goto end;
  
  ok=1;
end:

  if (dsa != (DSA *)NULL) DSA_free (dsa);
  RAND_cleanup();

  return ok;
}

/* clq_gen_key_set: Generate a pair of public and private key for the
 * user_name.
 * Returns 1 if succeed 0 otherwise.
 * Note: This function should be used in conjuction with
 * clq_read_dsa (i.e. USE_CLQ_READ_DSA should be defined.)
 */
int clq_gen_key_set(char *user_name) {   
  DSA *pubKey=NULL;
  DSA *privKey=NULL;
  int ok=0;
  char fileName[FN_LENGTH];

#ifdef DEBUG_MISC
    fprintf(ERR_STRM,"Generating key set for user %s ...\n",
	    user_name);
#endif

  if ((privKey=clq_read_dsa((CLQ_NAME *)NULL,CLQ_PARAMS))==(DSA*)NULL)  goto end;
  if (!DSA_generate_key(privKey)) goto end;
  if ((pubKey=DSA_new())==(DSA*)NULL) goto end;
  /* Copying the public stuff to pubKey */
  // pubKey->pad=privKey->pad;
  // pubKey->version=privKey->version;
  // pubKey->write_params=privKey->write_params;
  if (DSA_set0_pqg(pubKey, DSA_get0_p(privKey), DSA_get0_q(privKey), DSA_get0_g(privKey)) == 0) goto end;
  if (DSA_set0_key(pubKey, DSA_get0_pub_key(privKey), NULL) == 0) goto end;
  // pubKey->kinv= NULL; /* Signing pre-calc */
  // pubKey->r= NULL;    /* Signing pre-calc */
  // pubKey->references=privKey->references;

#ifdef DEBUG_MISC
  fprintf(ERR_STRM,"Done.\n"); 
#endif

  sprintf (fileName, "%s_%s.%s",PUB_FMT, user_name, FILE_EXT);
  if (!clq_write_dsa(pubKey,PUB_FMT,fileName)) goto end;
  sprintf (fileName, "%s_%s.%s",PRV_FMT, user_name, FILE_EXT);
  if (!clq_write_dsa(privKey,PRV_FMT,fileName)) goto end;
  
  ok=1;
end:

  if (pubKey != NULL) DSA_free (pubKey);
  if (privKey != NULL) DSA_free (privKey);

  return ok;
}

int clq_print_dsa(DSA *dsa) {
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

/* clq_write_dsa: Writes the dsa structure into outfile. 
 * oper could be any of the following: 
 * PUB_FMT, PRV_FMT
 * dsa should be a valid pointer.
 * If outfile is NULL, then stdout will be used.
 * Returns 1 if succeed 0 otherwise.
 * Note: This function should be used in conjuction with
 * clq_read_dsa (i.e. USE_CLQ_READ_DSA should be defined.)
 */
int clq_write_dsa(DSA *dsa, char *oper, char *outfile) {
  BIO *out=NULL;
  int i=0;
  int ok=0;
  char oper_str[30]="Invalid.";
  
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


#ifdef TIMING
double clq_get_time(void) {
  struct rusage used;
  
  getrusage(RUSAGE_SELF, &used);
  /*
  printf (":%ld %ld %ld %ld:\n", used.ru_utime.tv_sec, used.ru_utime.tv_usec,
	  used.ru_stime.tv_sec, used.ru_stime.tv_usec);
	  */
  return (used.ru_utime.tv_sec + used.ru_stime.tv_sec +
	  (used.ru_utime.tv_usec + used.ru_stime.tv_usec) / 1e6);
}
#endif


/* clq_print_ctx: Prints ctx to stdout */
void clq_print_ctx(CLQ_CONTEXT *ctx) {
  char *tmp=NULL;
  CLQ_GML *grp=NULL;

  if (ctx==NULL) return;

  grp=ctx->first;
  printf ("Member name: %s\n",ctx->member_name);
  printf ("Group name: %s\n",ctx->group_name);
  tmp=BN_bn2hex(ctx->key_share);
  printf ("Key Share: %s\n",tmp);
  free (tmp);
  printf ("Epoch: %d\n", ctx->epoch);
  if (ctx->group_secret != NULL) clq_print_group_secret(ctx);

  printf ("Group member list: \n");
  while (grp != NULL) {
    printf ("\tMember Name: %s\n",grp->member->member_name);
    if (grp->member->last_partial_key != NULL) {
      tmp=BN_bn2hex(grp->member->last_partial_key);
      tmp[10]=(char)NULL;
      printf ("\t Last Partial Key: %s\n",tmp);
      tmp[10]='a';
      free (tmp);
    }
    grp=grp->next;
  }
  printf ("--\n");
}

/* clq_get_secret: Returns in a static variable with
 * ctx->group_secret_hash 
 */ 
clq_uchar *clq_get_secret(CLQ_CONTEXT *ctx) {
  static clq_uchar tmp[MD5_DIGEST_LENGTH];

  memcpy (tmp,ctx->group_secret_hash,MD5_DIGEST_LENGTH);

  return tmp;
}

void clq_print_group_secret(CLQ_CONTEXT *ctx) {
  int i;

  fprintf(ERR_STRM,"Group Secret (MD5): ");
  if (ctx->group_secret_hash == NULL) fprintf (ERR_STRM,"EMPTY");
  else {
    for (i=0; i < MD5_DIGEST_LENGTH; i++) 
      fprintf(ERR_STRM, "%02X",ctx->group_secret_hash[i]);
  }

  fprintf(ERR_STRM,"\n");
}

