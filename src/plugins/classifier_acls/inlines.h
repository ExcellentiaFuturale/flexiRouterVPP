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

#ifndef included_classifier_acls_inlines_h
#define included_classifier_acls_inlines_h

#include <vnet/qos/qos_types.h>

#include <plugins/classifier_acls/classifier_acls.h>

extern classifier_acls_main_t classifier_acls_main;

/*
 * The function classifies the given packet based on ACLs attached to the
 * specified interface
 */
always_inline u32
classifier_acls_classify_packet (vlib_buffer_t *b, u32 sw_if_index, u8 is_ip6,
                                 u32 *out_acl_index, u32 *out_acl_rule_index)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  fa_5tuple_opaque_t fa_5tuple0;
  u32 match_acl_index;
  u32 match_acl_pos;
  u32 match_rule_index;
  u32 trace_bitmap;
  u8 action;

  vec_validate_init_empty (cmp->acl_lc_index_by_sw_if_index, sw_if_index, ~0);
  if (cmp->acl_lc_index_by_sw_if_index[sw_if_index] == ~0)
    {
      /* No ACLs attached */
      return 0;
    }
  acl_plugin_fill_5tuple_inline
    (cmp->acl_plugin.p_acl_main,
     cmp->acl_lc_index_by_sw_if_index[sw_if_index],
     b, is_ip6, 1 /* is_input */, 0 /* is_l2 */, &fa_5tuple0);
  if (acl_plugin_match_5tuple_inline
      (cmp->acl_plugin.p_acl_main,
       cmp->acl_lc_index_by_sw_if_index[sw_if_index],
       &fa_5tuple0, is_ip6, &action, &match_acl_pos,
       &match_acl_index, &match_rule_index, &trace_bitmap))
    {
      /* match - fetch acl attributes */
      u8 service_class, importance;
      if (acl_plugin_get_acl_attributes_inline
          (cmp->acl_plugin.p_acl_main, match_acl_index, match_rule_index,
           &service_class, &importance) != 0)
        {
          clib_warning ("ACL attr get failed- ACL index: %u Rule index: %u",
			  match_acl_index, match_rule_index);
	  return 0;
        }

      vnet_buffer2 (b)->qos.service_class = service_class;
      vnet_buffer2 (b)->qos.importance = importance;
      vnet_buffer2 (b)->qos.source = QOS_SOURCE_IP;
      b->flags |= VNET_BUFFER_F_IS_CLASSIFIED;
      if (out_acl_index)
        {
	  *out_acl_index = match_acl_index;
        }
      if (out_acl_rule_index)
        {
	  *out_acl_rule_index = match_rule_index;
        }
      return 1;
    }
  else
    {
      return 0;
    }
}

#endif
