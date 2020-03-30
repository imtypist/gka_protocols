/*********************************************************************
 * common.h                                                          * 
 * Common header file         .                                      * 
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
#ifndef CLQ_CERT_H
#define CLQ_CERT_H
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/dsa.h"
#include "openssl/x509.h"

/* data structures */
typedef char CLQ_NAME;
#ifndef clq_uchar
typedef unsigned char clq_uchar;
#endif
#ifndef clq_uint
typedef unsigned int clq_uint;
#endif
#ifndef uint
typedef unsigned int uint;
#endif

#define ERR_STRM stderr /* If DEBUG is enable then extra information will be printed in ERR_STRM */


/***************************************************************/
/* Be careful... previously, 32768                             */
/* I changed since for 148 users, we need more than 32768 bytes*/
/***************************************************************/
#define MSG_SIZE 65536
#define INT_SIZE sizeof(int)
#define LENGTH_SIZE 4 /* The length of the size in a token */
#define TOTAL_INT INT_SIZE+LENGTH_SIZE
#define MAX_LIST 200 /* Maximum number of members */ 

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

/* clq_get_cert stuff */
#define DSA_PARAM_CERT "dsa_param.pem"
#define PUB_CERT "cert"
#define CA_CERT_FN "cacert.pem"

#define MAX_LGT_NAME 50 /* Maximum length a CLQ_NAME can have. */

/* clq_read_DSA stuff */
#define COMMON_FILE "public_values.clq"
#define PUB_FMT "pub"
#define PRV_FMT "priv"
#ifdef USE_CLQ_READ_DSA
#define FILE_EXT "clq"
#else
#define FILE_EXT "pem"
#endif

/* Macros not implemented in SSL */
#ifndef d2i_DSAPublicKey_bio
#define d2i_DSAPublicKey_bio(bp,x) (DSA *)ASN1_d2i_bio((char *(*)())DSA_new, \
                (char *(*)())d2i_DSAPublicKey,(bp),(unsigned char **)(x))
#endif
#ifndef i2d_DSAPublicKey_bio
#define i2d_DSAPublicKey_bio(bp,x) ASN1_i2d_bio(i2d_DSAPublicKey,(bp), \
                (unsigned char *)(x)) 
#endif

/* Private Macros */

#ifndef MAX
#define MAX(x,y)                        ((x)>(y)?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y)                        ((x)<(y)?(x):(y))
#endif

/* CLQ_KEY_TYPE definitions, used by clq_read_dsa */
enum CLQ_KEY_TYPE { CLQ_PARAMS,
                    CLQ_PRV,
                    CLQ_PUB};

typedef struct clq_token_st {
  uint length;
  clq_uchar *t_data;
} CLQ_TOKEN;


#ifdef TIMING
double clq_gettimeofday(void);
#endif

DSA *clq_get_dsa_key (char *member_name, 
                      enum CLQ_KEY_TYPE type);

EVP_PKEY *clq_get_pkey (char *member_name);

DSA *clq_get_dsa_param();

X509 *clq_get_cert (char *member_name);

X509 *clq_vrfy_cert(X509_STORE *ctx, char *file);

/* clq_read_DSA: Reads a DSA structure from disk depending on
 * CLQ_KEY_TYPE (CLQ_PARAMS, CLQ_PRIV, CLQ_PUB)
 * Returns the structure if succeed otherwise NULL is returned.
 */
DSA *clq_read_dsa(char *member_name, enum CLQ_KEY_TYPE type);

/* max: return maximum of a and b */
int max(int a, int b);
/* return log_2 a */
int clq_log2(int a);
/* swap pointer a and b */
void clq_swap(void **a, void **b);

/* int_endoce: It puts an integer number in stream. Note that the size
 * of the integer number is addded to the stream as well.
 */
/* NOTE: HTONL should be added here */
void int_encode(clq_uchar *stream, clq_uint *pos, clq_uint data);


/* int_decode: It gets an integer number from input->t_data. Note that
 * the size of the integer number is decoded first, and then the
 * actual number is decoded.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int int_decode(const CLQ_TOKEN *input,clq_uint *pos, clq_uint *data);

/* string_encode: It puts the valid 'c' string into stream. It first
 * stores the message length (including \0) and the the actual
 * message.
 */
void string_encode (clq_uchar *stream, clq_uint *pos, char *data);

/* string_decode: It restores a valid 'c' string from
 * input->t_data. First the string length is decode (this one should
 * have \0 already), and the actual string.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int string_decode (const CLQ_TOKEN *input, clq_uint *pos, char *data);

/* bn_encode: BIGNUM encoding. */
void bn_encode (clq_uchar *stream, clq_uint *pos, BIGNUM *num);

/* bn_decode: BIGNUM decoding.
 * Preconditions: num has to be different from NULL.
 * Returns: 1 succeed.
 *          0 Fails.
 */
int bn_decode (const CLQ_TOKEN *input, clq_uint *pos, BIGNUM *num);

#endif
