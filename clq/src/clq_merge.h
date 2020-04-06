/*********************************************************************
 * clq_merge.h                                                       * 
 * Date      Tue Jun 11, 2002  8:37 PM                               *
 * Wrote by:                                                         * 
 * Yongdae Kim                                                       *
 *                                                                   *
 * SCONCE/CLIQUES Project                                            *
 * University of California at Irvine                                *
 *********************************************************************/

#ifndef CLQ_MERGE_H
#define CLQ_MERGE_H

#include "clq_api.h"

enum CLQ_OPER { CLQ_MERGE,
		CKD_GENERATE_KEY };

/* clq_update_key is called by every new user (who are part of the
 * merge operation) and the group controller. If the group controller
 * is the one calling this function then member_list will be
 * valid. Otherwise, for every other user input token will be valid (and
 * member_list will be NULL.
 * The last new member calling this function will not add his/her
 * key_share.
 * member_list has to be NULL terminated.
 * last_partial_keys of old members in the group remain in the context
 * of the current controller, but they will not be encoded in the
 * token.
 */
int clq_update_key (CLQ_CONTEXT *ctx, CLQ_NAME *member_list[], 
		    CLQ_TOKEN *input, CLQ_TOKEN **output);

/* clq_factor_out is called by every member in the group except by the
 * last new member upon recepction of a MERGE_BROADCAST
 * message. Although the last new member doesn't have to called this
 * function because he/she is the one that generates that message, if
 * he/she does then the function will return (no side effects will
 * occur).
 * During this operation ctx is not modified (but ctx->epoch is).
 */
int clq_factor_out (CLQ_CONTEXT *ctx, CLQ_TOKEN *input, 
		    CLQ_TOKEN **output_token);
/* clq_last_step: The last step of the merge operation or of an ckd
 * event. The controller upon reception of the indiviual
 * (FACTOR_OUT or CKD_SHORT_TERM_KEY) messages should call this 
 * function. After he/she receives all the messages, an output token
 * will be generated. This token should be broadcasted to the entire
 * group.
 */
int clq_last_step (CLQ_CONTEXT *ctx, CLQ_NAME *sender_name, 
		   CLQ_TOKEN *input, CLQ_TOKEN **output, 
		   enum CLQ_OPER oper);

#define clq_merge(ctx,sender_name,input,output) \
        clq_last_step(ctx,sender_name,input,output,CLQ_MERGE)


CLQ_NAME *clq_get_next_username(CLQ_CONTEXT *ctx);

CLQ_NAME *clq_get_controller_name(CLQ_CONTEXT *ctx);


#endif
