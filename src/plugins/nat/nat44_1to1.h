/*
 *  Copyright (C) 2023 FlexiWAN Ltd.
 *
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *
 *  - policy_nat44_1to1 : The feature programs a list of nat4-1to1 actions.
 *  The match criteria is defined as ACLs and attached to the interfaces. The
 *  ACLs are encoded with the value that points to one of the nat44-1to1
 *  actions. The feature checks for match in both in2out and out2in directions
 *  and applies NAT on a match.
 */

/* The file is added as part of the policy_nat44_1to1 feature */

#ifndef __included_nat44_1to1_h__
#define __included_nat44_1to1_h__


void
nat44_1to1_init ();

i32
nat44_ed_1to1_add_del_acl_actions (u32 count, void* config_actions);


i32
nat44_ed_1to1_attach_detach_match_acls (u32 sw_if_index,
                                        u32 * in_acls, u32 * out_acls);

u32
nat44_ed_match_1to1_mapping (vlib_buffer_t * b, u8 out2in,
                             ip4_address_t *out_src_addr,
                             ip4_address_t *out_nat_addr);

u32
nat44_ed_matches_1to1_action (ip4_address_t src_addr, ip4_address_t dst_addr);

#endif /* __included_nat44_1to1_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
