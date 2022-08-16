/*
 * Copyright (c) 2022 FlexiWAN
 *
 * List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *  - acl_based_classification: Feature to provide traffic classification using
 *  ACL plugin. Matching ACLs provide the service class and importance
 *  attribute. The classification result is marked in the packet and can be
 *  made use of in other functions like scheduling, policing, marking etc.
 *
 * This file is added by the Flexiwan feature: acl_based_classification.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <classifier_acls/classifier_acls.h>
#include <classifier_acls/inlines.h>

typedef struct 
{
  u32 next_index;
} classifier_acls_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 * format_classifier_acls_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  classifier_acls_trace_t * t = va_arg (*args, classifier_acls_trace_t *);
  
  s = format (s, "CLASSIFIER_ACLS: next index %d\n", t->next_index);
  return s;
}

#endif /* CLIB_MARCH_VARIANT */


#define foreach_classifier_acls_counter \
_(MATCHES, "acl matches") \
_(MISSES, "acl misses")

typedef enum {
#define _(sym,str) CLASSIFIER_ACLS_##sym,
  foreach_classifier_acls_counter
#undef _
  CLASSIFIER_ACLS_N_COUNTER,
} classifier_acls_error_t;

#ifndef CLIB_MARCH_VARIANT
static char * classifier_acls_error_strings[] = 
{
#define _(sym,string) string,
  foreach_classifier_acls_counter
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum 
{
  CLASSIFIER_ACLS_NEXT_DROP,
  CLASSIFIER_ACLS_N_NEXT,
} classifier_acls_next_t;


always_inline uword
classifier_acls_node_inline (vlib_main_t * vm,
			     vlib_node_runtime_t * node,
			     vlib_frame_t * frame, u8 is_ip6)
{
  u32 n_left_from, * from;
  classifier_acls_next_t next_index;
  u32 matches = 0;
  u32 misses = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next, * to_next;
      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0;
	  u32 sw_if_index;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (classifier_acls_classify_packet (b0, sw_if_index, is_ip6))
	    {
	      matches++;
	    }
	  else
	    {
	      misses++;
	    }

	  /* move on down the feature arc */
	  vnet_feature_next (&next0, b0);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (matches)
    vlib_node_increment_counter (vm, node->node_index,
				 CLASSIFIER_ACLS_MATCHES, matches);

  if (misses)
    vlib_node_increment_counter (vm, node->node_index,
				 CLASSIFIER_ACLS_MISSES, misses);

  return frame->n_vectors;
}


VLIB_NODE_FN (ip4_classifier_acls_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return classifier_acls_node_inline (vm, node, frame, 0 /* is_ip6 */);

}

VLIB_NODE_FN (ip6_classifier_acls_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  return classifier_acls_node_inline (vm, node, frame, 1 /* is_ip6 */);
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ip4_classifier_acls_node) = 
{
  .name = "ip4-classifier-acls",
  .vector_size = sizeof (u32),
  .format_trace = format_classifier_acls_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(classifier_acls_error_strings),
  .error_strings = classifier_acls_error_strings,

  .n_next_nodes = CLASSIFIER_ACLS_N_NEXT,

  .next_nodes = {
        [CLASSIFIER_ACLS_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ip6_classifier_acls_node) = 
{
  .name = "ip6-classifier-acls",
  .vector_size = sizeof (u32),
  .format_trace = format_classifier_acls_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(classifier_acls_error_strings),
  .error_strings = classifier_acls_error_strings,

  .n_next_nodes = CLASSIFIER_ACLS_N_NEXT,

  .next_nodes = {
        [CLASSIFIER_ACLS_NEXT_DROP] = "error-drop",
  },
};

#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
