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

#ifndef __included_classifier_acls_h__
#define __included_classifier_acls_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#include <plugins/acl/exported_types.h>
#include <plugins/acl/public_inlines.h>

typedef struct {
    /* ACL plugin struct of exported functions */
    acl_plugin_methods_t acl_plugin;

    /* Classifer ACLs module user id */
    u32 acl_user_id;

    /* Per interface ACL lookup context IDs. Indexed by sw_if_index */
    u32 *acl_lc_index_by_sw_if_index;

    /* Vector of classifier acl indexes */
    u32 *acls;

    /* Vector of interface added for classification */
    u32 *intfs_indexed_by_sw_if_index;

    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
} classifier_acls_main_t;


/*
 * The function classify the given packet based on ACLs attached to the
 * specified interface
 */
u32 classifier_acls_classify_packet_api (vlib_buffer_t *b, u32 sw_if_index,
                                         u8 is_ip6, u32 *out_acl_index,
                                         u32 *out_acl_rule_index);


#endif /* __included_classifier_acls_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
