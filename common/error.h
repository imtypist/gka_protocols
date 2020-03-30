/*********************************************************************
 * error.h                                                           * 
 * error codes for cliques library                                   * 
 * Wrote by:                                                         * 
 *  Yongdae Kim                                                      *
 *                                                                   *
 * Date      Tue March 24, 2020  9:48 PM                             *
 * Maintained by:                                                    *
 * Junqin Huang                                                      *
 *                                                                   *
 * Shanghai Jiao Tong University                                     *
 *********************************************************************/

#ifndef CLQ_ERROR_H
#define CLQ_ERROR_H

/* Return codes */
#define OK                          1
#define CONTINUE                    2
#define KEY_COMPUTED                3

/* General errors */
#define CTX_ERROR                  -1
#define INVALID_INPUT_TOKEN       -10
#define INVALID_MESSAGE_TYPE      -11
#define INVALID_MEMBER_NAME       -12
#define INVALID_GROUP_NAME        -13
#define GROUP_NAME_MISMATCH       -14
#define INVALID_LGT_NAME          -15
#define MEMBER_IS_IN_GROUP        -16
#define MEMBER_NOT_IN_GROUP       -17
#define MEMBER_NAME_MISMATCH      -18
#define MEMBER_REPEATED           -19
#define LIST_EMPTY                -20
#define ERROR_INT_DECODE          -21
#define STRUCTURE_ERROR           -21
#define MERGE_FAILURE             -22
#define NOT_CONTROLLER            -23
#define UNSYNC_EPOCH              -24
#define SEVERAL_JOINS             -25
#define SENDER_NOT_CONTROLLER     -26
#define MALLOC_ERROR              -27
#define BN_ERROR                  -28
#define ERROR_INT_DECODE          -29
#define GML_EMPTY                 -30
#define ONE_RCVD                  -31
#define ZERO_RCVD                 -32
#define NUM_NOT_IN_GROUP          -33
#define MOD_INVERSE_ERROR         -34
#define MOD_MUL_ERROR             -35
#define MOD_EXP_ERROR             -36
#define BN_CONVERT_ERROR          -37

/* Certificate Related */
#define INVALID_DSA_PARAMS        -40
#define INVALID_PUB_KEY           -41
#define INVALID_PRIV_KEY          -42
#define INVALID_PARAM             -43
#define INVALID_DSA_TYPE          -44 
#define INVALID_CA_FILE           -45
#define INVALID_CERT_FILE         -46
#define INVALID_PKEY              -47


/* Signature Related */
#define INVALID_SIGNATURE_SCHEME  -50
#define SIGNATURE_ERROR           -51
#define SIGNATURE_DIFER           -52
#define INVALID_SIGNATURE         -53

#endif
