/*********************************************************************
 * common.c                                                          * 
 * Common source file         .                                      * 
 * Date      Mon Jun 17, 2002 11:24 AM                               *
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

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <netinet/in.h>

/* OPENSSL include files */
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/dsa.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/pem.h"

#include "error.h"
#include "common.h"

#ifdef TIMING
#include <sys/time.h>

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

double clq_gettimeofday(void) {
  struct timeval used;
  
  gettimeofday(&used, 0);
  return (used.tv_sec + (double)((used.tv_usec) / 1e6));
}
#ifdef GETRUSAGE
double clq_gettimeofday(void) {
  struct rusage used;
  
  getrusage(RUSAGE_SELF, &used);
  /*    printf (":%ld %ld:\n", used.tv_sec, used.tv_usec); */
  return (used.ru_utime.tv_sec + used.ru_stime.tv_sec +
          (used.ru_utime.tv_usec + used.ru_stime.tv_usec) / 1e6);
}
#endif /* end of GETRUSAGE */
#endif /* end of TIMING */

static int cert_error=OK;

#define PRINT_CERT_ERRORS

#ifdef PRINT_CERT_ERRORS
static BIO *cert_bio_err=NULL;
#endif

/* name of the environment variable that specifies the path to users' certificates  */
#define CLQ_CERTF_PATH    "CLQ_CERTF"
#define CLQ_KPRIV_PATH    "CLQ_KPRIV"
#define CLQ_CA_PATH       "CLQ_CA"

static void do_ssl_setup() {
  static int need_setup=1;
  
  if (need_setup) {
#ifdef PRINT_CERT_ERRORS
    if (cert_bio_err==NULL) 
      if ((cert_bio_err=BIO_new(BIO_s_file())) != NULL)
        BIO_set_fp(cert_bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
#endif
    ERR_load_crypto_strings();
    X509V3_add_standard_extensions();
    SSLeay_add_all_algorithms();
    need_setup=0;
  }
}

DSA *clq_get_dsa_param() {
  BIO *in=NULL;
  DSA *dsa=NULL;
  char *path = NULL;
  char file_path[2048];
  
  in=BIO_new(BIO_s_file());
  if (in == NULL) { 
    /* ERR_print_errors(bio_err); */
    goto error;
  }
  
  if((path = getenv(CLQ_CERTF_PATH)) != NULL) {
    sprintf(file_path, "%s/%s", path, DSA_PARAM_CERT);
    if (BIO_read_filename(in, file_path) <= 0) goto error;
  }
  else {
    if (BIO_read_filename(in,DSA_PARAM_CERT) <= 0) goto error;
  }
  
  dsa=PEM_read_bio_DSAparams(in,NULL,NULL,NULL);
  
  error:
  
  if (in != NULL) BIO_free(in);
  
  return dsa;
}

DSA *clq_get_dsa_key (char *member_name, enum CLQ_KEY_TYPE type) { 
  X509 *x=NULL;
  DSA *dsa=NULL;
  EVP_PKEY *pkey=NULL;
  
  switch (type) {
    case CLQ_PARAMS:
      /* member_name is not used! */
      dsa=clq_get_dsa_param ();
      break;
    case CLQ_PRV:
      pkey=clq_get_pkey(member_name);
      if (pkey==(EVP_PKEY *)NULL) return NULL;
      if (EVP_PKEY_id(pkey) == EVP_PKEY_DSA) { // pkey->type
        dsa=EVP_PKEY_get0_DSA(pkey); // dsa=pkey->pkey.dsa;
        EVP_PKEY_set1_DSA(pkey, NULL); // pkey->pkey.ptr=NULL;
        EVP_PKEY_set_alias_type(pkey, NID_undef); // pkey->type=NID_undef;
      }
      else {
        cert_error=INVALID_DSA_TYPE;
        goto error;
      }
      break;
    case CLQ_PUB:
      x=clq_get_cert(member_name);
      if (x!=NULL) {
        if (x->cert_info->key->pkey != NULL) {
          if (NID_dsa == x->cert_info->key->pkey->type) 
            dsa=(DSA *)x->cert_info->key->pkey->pkey.dsa; 
        }
        if (dsa!=NULL){
          x->cert_info->key->pkey->pkey.dsa=NULL;
        }
        
        X509_free(x);
      }
      break;
    default:
      cert_error=INVALID_DSA_TYPE;
      goto error;
  }
  
  error:
  
  if (pkey != NULL) EVP_PKEY_free (pkey);
  
  return dsa;
}

/* The main idea of this function was obtained from apps/dsa.c */
/* If member_name is NULL then DSA parameters will be read from disk ! */
/* For private keys ONLY ! */
EVP_PKEY *clq_get_pkey (char *member_name) {
  BIO *in=NULL;
  EVP_PKEY *pkey=NULL;
  char infile[MAX_LGT_NAME*2];
  
  char *path = NULL;
  char file_path[2048];
  
  do_ssl_setup();
  
  if (member_name == NULL) {cert_error=INVALID_MEMBER_NAME; return NULL;}
  
  sprintf(infile,"%s_%s.%s",member_name,PRV_FMT,FILE_EXT); 
  
  in=BIO_new(BIO_s_file());
  if (in == NULL) {
#ifdef PRINT_CERT_ERRORS
    ERR_print_errors(cert_bio_err);
#endif
    cert_error=MALLOC_ERROR;
    goto error;
  }
  
  if((path = getenv(CLQ_KPRIV_PATH)) != NULL) {
    sprintf(file_path, "%s/%s", path, infile);
  }
  else {
    strcpy(file_path, infile);
  }
  
  if (BIO_read_filename(in, file_path) <= 0) {
#ifdef PRINT_CERT_ERRORS
    ERR_print_errors(cert_bio_err);
#endif
    cert_error=INVALID_MEMBER_NAME;
    goto error;
  }
  
  /* FORMAT_PEM */
  pkey=(EVP_PKEY *)PEM_read_bio_PrivateKey(in,NULL,NULL,NULL);
  
  if (pkey == NULL) {
#ifdef PRINT_CERT_ERRORS
    ERR_print_errors(cert_bio_err);
#endif
    cert_error=INVALID_PKEY;
    goto error;
  }
  
  error:
  if (in != NULL) BIO_free(in);
  
  return pkey;
}

/* This function is based on apps/verify.c from openssl */
X509 *clq_get_cert (char *member_name) {
  char *CApath=NULL,CAfile[]=CA_CERT_FN; 
  X509_STORE *cert_ctx=NULL;
  X509 *x=NULL;
  X509_LOOKUP *lookup=NULL;
  char infile[MAX_LGT_NAME*2];
  
  char *path = NULL;
  char *ca_path = NULL;
  char file_path[2048];
  char ca_file_path[2048];
  
  do_ssl_setup();
  
  if (member_name==NULL) {cert_error=INVALID_MEMBER_NAME; return NULL;}
  sprintf (infile, "%s_%s.%s",member_name, PUB_CERT, FILE_EXT);  
  
  if((path = getenv(CLQ_CERTF_PATH)) != NULL) {
    sprintf(file_path, "%s/%s", path, infile);
  }
  else {
    strcpy(file_path, infile);
  }
  if((ca_path = getenv(CLQ_CA_PATH)) != NULL) {
    sprintf(ca_file_path, "%s/%s", ca_path, CAfile);
  }
  else {
    strcpy(ca_file_path, CAfile);
  }
  
  cert_ctx=X509_STORE_new();
  if (cert_ctx == NULL) {cert_error= MALLOC_ERROR; goto error; }
  /*
    X509_STORE_set_verify_cb_func(cert_ctx,cb);
  */
  
  cert_error=INVALID_CA_FILE;
  lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_file());
  if (lookup == NULL) goto error;
  if (!X509_LOOKUP_load_file(lookup,ca_file_path,X509_FILETYPE_PEM))
    X509_LOOKUP_load_file(lookup,NULL,X509_FILETYPE_DEFAULT);
  
  lookup=X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_hash_dir());
  if (lookup == NULL) goto error;
  if (!X509_LOOKUP_add_dir(lookup,CApath,X509_FILETYPE_PEM))
    X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);
  
  ERR_clear_error();
  
  x=clq_vrfy_cert(cert_ctx,file_path);
  
  error:
  if (cert_ctx != NULL) X509_STORE_free(cert_ctx);
  if (x != NULL) return x;
  
  cert_error=INVALID_CERT_FILE;
  return NULL;
}

X509 *clq_vrfy_cert(X509_STORE *ctx, char *file) {
  X509 *x=NULL;
  BIO *in=NULL;
  int i=0;
  X509_STORE_CTX csc;
  
  ERR_load_crypto_strings();
  if (file == NULL) goto error;
  
  do_ssl_setup();
  
  in=BIO_new(BIO_s_file());
  if (in == NULL) {
#ifdef PRINT_CERT_ERRORS
    ERR_print_errors(cert_bio_err);
#endif
    goto error;
  }
  
  if (BIO_read_filename(in,file) <= 0) {
    cert_error=INVALID_MEMBER_NAME;
    goto error;
  }
  
  x=(X509*)PEM_read_bio_X509(in,NULL,NULL,NULL);
  /*
   * x->cert_info->key is not yet available do ..
   * x->cert_info->key->pkey=X509_get_pubkey(x);
   * before using it.
   */
  if (x == NULL) {
    cert_error=INVALID_CERT_FILE;
#ifdef PRINT_CERT_ERRORS
    ERR_print_errors(cert_bio_err);
#endif
    goto error;
  }
  /* x->cert_info->key->pkey=X509_get_pubkey(x); */
  
  X509_STORE_CTX_init(&csc,ctx,x,NULL); 
  i=X509_verify_cert(&csc); /* cacert retrieved from disk */
  X509_STORE_CTX_cleanup(&csc);
  
  error:
  if (!i) {
    X509_free (x);
    x=NULL;
#ifdef PRINT_CERT_ERRORS
    ERR_print_errors(cert_bio_err);
#endif
  }
  
  if (in != NULL) BIO_free(in);
  
  return x;
}

/* clq_read_dsa: Reads a DSA structure from disk depending on
 * CLQ_KEY_TYPE (CLQ_PARAMS, CLQ_PRV, CLQ_PUB)
 *
 * Parameters:
 *  member_name
 *   User name requesting key. 
 *   If type is CLQ_PARAMS then this parameter is not used. 
 *  type
 *   Type of key required.
 *
 * Return: A pointer to a DSA structure with the requested key if
 * succeed, otherwise NULL is returned. 
 *
 * Note: This function can be replaced for one provided by the
 * program using the API. Hence, the keys can be obtained form
 * another media if necessary. The only only condition required is
 * that the function returns a pointer to a DSA structure.
 */
DSA *clq_read_dsa(char *member_name, enum CLQ_KEY_TYPE type) 
{ 
  return (DSA*)clq_get_dsa_key(member_name,type);
}

/* return log_2 a */
int clq_log2(int a)
{
  int tmp = a;
  int i=-1;
  
  while(tmp > 0){
    i++;
    tmp >>= 1;
  }
  
  return i;
}

/* swap pointer a and b */
void clq_swap(void **a, void **b)
{
  void *tmp;

  tmp = *a;
  *a = *b;
  *b = tmp;
}

/* int_encode: It puts an integer number in stream. Note that the size
 * of the integer number is added to the stream as well.
 */
void int_encode(clq_uchar *stream, clq_uint *pos, clq_uint data) {
  int int_size=htonl(INT_SIZE);

  data=htonl(data);
  bcopy (&int_size,stream+*pos,LENGTH_SIZE);
  *pos+=LENGTH_SIZE;
  bcopy (&data,stream+*pos,INT_SIZE);
  *pos+=INT_SIZE;
}

/* int_decode: It gets an integer number from input->t_data. Note that
 * the size of the integer number is decoded first, and then the
 * actual number is decoded.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int int_decode(const CLQ_TOKEN *input,clq_uint *pos, clq_uint *data) {
  int int_size;

  if (input->length  < LENGTH_SIZE+*pos) return 0;
  bcopy (input->t_data+*pos,&int_size,LENGTH_SIZE);
  int_size=ntohl(int_size);
  *pos+=LENGTH_SIZE;
  if (input->length  < int_size+*pos) return 0;
  bcopy (input->t_data+*pos,data,int_size);
  *pos+=int_size;
  *data=ntohl(*data);

  return 1;
}

/* string_encode: It puts the valid 'c' string into stream. It first
 * stores the message length (including \0) and the the actual
 * message.
 */
void string_encode (clq_uchar *stream, clq_uint *pos, char *data) {
  int str_len=1;

  /* Note: we are copying the '/0' also */
  str_len+=strlen(data); 
  int_encode(stream,pos,str_len);
  bcopy (data,stream+*pos,str_len);
  *pos+=str_len;
}

/* string_decode: It restores a valid 'c' string from
 * input->t_data. First the string length is decode (this one should
 * have \0 already), and the actual string.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int string_decode (const CLQ_TOKEN *input, clq_uint *pos, char *data) {
  clq_uint str_len;

  if (!int_decode(input,pos,&str_len)) return 0;
  if (input->length  < str_len+*pos) return 0;
  bcopy(input->t_data+*pos,data,str_len);
  *pos+=str_len;

  return 1;
}

/* bn_encode: BIGNUM encoding. */
void bn_encode (clq_uchar *stream, clq_uint *pos, BIGNUM *num) {
  clq_uint size;

  size=BN_num_bytes(num);
  assert (size > 0);
  int_encode(stream,pos,size);
  BN_bn2bin(num,stream+*pos);
  *pos+=size;
}

/* bn_decode: BIGNUM decoding.
 * Preconditions: num has to be different from NULL.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int bn_decode (const CLQ_TOKEN *input, clq_uint *pos, BIGNUM *num) {
  clq_uint size=0;

  if (num == (BIGNUM *) NULL) return 0;
  if (!int_decode(input,pos,&size)) return 0;
  if (size <= 0) return 0;
  if (input->length < size+*pos) return 0;
  BN_bin2bn(input->t_data+*pos,size,num);
  *pos+=size;

  return 1;
}

