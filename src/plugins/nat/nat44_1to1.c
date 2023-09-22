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

#include <nat/nat.h>
#include <nat/nat44_1to1.h>
#include <nat/nat44.api_types.h>


void
nat44_1to1_init ()
{
  snat_main_t *sm = &snat_main;
  sm->acl_user_id = ~0;
  sm->nat44_1to1_acl_matches = NULL;
  sm->nat44_1to1_acl_actions = NULL;
  /* Init the ACL plugin contexts */
  clib_error_t *error = acl_plugin_exports_init (&sm->acl_plugin);
  if (!error)
    sm->acl_user_id = sm->acl_plugin.register_user_module
      ("NAT44 1to1 ACLs", "sw_if_index", NULL);
  else
    clib_warning ("NAT44 1to1 ACL plugin register failed: %U",
                  format_clib_error, error);
}


i32
nat44_ed_1to1_add_del_acl_actions (u32 count, void* config_actions)
{
  /*
   * Setup ACL action contexts.
   * The Actions represent the Source and Destination NAT to be used on
   * matching this action
   */
  vl_api_nat44_1to1_acl_action_t *actions = config_actions;
  snat_main_t *sm = &snat_main;
  vec_free (sm->nat44_1to1_acl_actions);
  for (u32 i = 0; i < count; i++)
    {
      nat44_1to1_acl_action_t action;
      clib_memcpy (action.nat_src_prefix.data, actions[i].nat_src.address,
                   sizeof (ip4_address_t));
      clib_memcpy (action.nat_dst_prefix.data, actions[i].nat_dst.address,
                   sizeof (ip4_address_t));
      action.src_prefix_len = actions[i].nat_src.len;
      action.dst_prefix_len = actions[i].nat_dst.len;
      vec_add1 (sm->nat44_1to1_acl_actions, action);
    }
  return 0;
}

static i32
nat44_ed_setup_acl_match (snat_main_t * sm, u32 sw_if_index,
                          u32 * in_acls, u32 * out_acls)
{
  i32 rv = 0;
  nat44_1to1_acl_match_t *match = &sm->nat44_1to1_acl_matches[sw_if_index];
  /* Init ACL lookup context if not already set */
  if ((in_acls) && (match->acl_in_lc == ~0))
    {
      rv = sm->acl_plugin.get_lookup_context_index (sm->acl_user_id,
                                                    sw_if_index, 0);
      if (rv < 0)
        clib_warning("NAT44 1to1 match IN acl setup failed: %d", rv);
      else
        match->acl_in_lc = rv;
    }
  if ((!rv) && (out_acls) && (match->acl_out_lc == ~0))
    {
      rv = sm->acl_plugin.get_lookup_context_index (sm->acl_user_id,
                                                    sw_if_index, 1);
      if (rv < 0)
        clib_warning("NAT44 1to1 match OUT acl setup failed: %d", rv);
      else
        match->acl_out_lc = rv;
    }
  /* Attach the ACLs to the lookup context */ 
  if (rv >= 0)
    {
      if (in_acls)
        {
          rv = sm->acl_plugin.set_acl_vec_for_context
            (match->acl_in_lc, in_acls);
          if (rv)
            clib_warning("NAT44 1to1 IN acls attach failed: %d", rv);
        }
      if (((!in_acls) || (!rv)) && (out_acls))
        {
          rv = sm->acl_plugin.set_acl_vec_for_context
            (match->acl_out_lc, out_acls);
          if (rv < 0)
            clib_warning("NAT44 1to1 Out acls attach failed: %d", rv);
        }
    }
  return rv;
}

static void
nat44_ed_release_acl_match (snat_main_t * sm, u32 sw_if_index, u8 out_flag)
{
  nat44_1to1_acl_match_t *match = &sm->nat44_1to1_acl_matches[sw_if_index];
  /* Release the ACL lookup context */ 
  if (out_flag)
    {
      if (match->acl_out_lc != ~0)
        {
          sm->acl_plugin.put_lookup_context_index (match->acl_out_lc);
          match->acl_out_lc = ~0;
        }
    }
  else if (match->acl_in_lc != ~0)
    {
      sm->acl_plugin.put_lookup_context_index (match->acl_in_lc);
      match->acl_in_lc = ~0;
    }
}

i32
nat44_ed_1to1_attach_detach_match_acls (u32 sw_if_index,
                                        u32* in_acls, u32 * out_acls)
{
  /*
   * Sets up per interface ACL lookup context and attaches the given match ACLs
   * If both in_acls and out_acls are passed as None. It is treated as
   * detachment (cleanup contexts) request
   */
  snat_main_t *sm = &snat_main;
  u32 len = vec_len (sm->nat44_1to1_acl_matches);
  if (((!in_acls) && (!out_acls)) && (sw_if_index >= len))
    return 0;

  vec_validate (sm->nat44_1to1_acl_matches, sw_if_index);
  if (len <= sw_if_index)
    memset (&sm->nat44_1to1_acl_matches[len], ~0,
            (sw_if_index - len + 1) * sizeof (sm->nat44_1to1_acl_matches[0]));

  if (!in_acls)
    nat44_ed_release_acl_match (sm, sw_if_index, 0);
  if (!out_acls)
    nat44_ed_release_acl_match (sm, sw_if_index, 1);
  if ((!in_acls) && (!out_acls))
    return 0;

  return nat44_ed_setup_acl_match (sm, sw_if_index, in_acls, out_acls);
}


static inline void
nat44_get_1to1_nat_addr (ip4_address_t nat_prefix, u32 nat_prefix_len,
                         ip4_address_t in_addr, ip4_address_t *out_addr)
{
  /*
   * NAT the in_address based on the NAT prefix. For example,
   * Given in_addr : 10.10.10.1
   * Configured Action nat_prefix : 172.16.11.0/24
   * then the out_addr shall be 172.16.11.10
   */
  u32 in_addr_nb = clib_net_to_host_u32 (in_addr.as_u32);
  if ((!nat_prefix_len) || (nat_prefix_len == 32))
    {
      if (nat_prefix.as_u32)
        out_addr->as_u32 = nat_prefix.as_u32;
      else
        out_addr->as_u32 = in_addr.as_u32;
    }
  else
    out_addr->as_u32 = nat_prefix.as_u32 +
      clib_host_to_net_u32(in_addr_nb & (0xFFFFFFFF >> nat_prefix_len));
}

static inline u32
nat44_ed_match_1to1_acls (u32 acl_lc, vlib_buffer_t *b,
                          ip4_address_t *out_src_addr,
                          ip4_address_t *out_dst_addr)
{
  snat_main_t *sm = &snat_main;
  fa_5tuple_opaque_t fa_5tuple0;
  u32 match_acl_index;
  u32 match_acl_pos;
  u32 match_rule_index;
  u32 trace_bitmap;
  u8 acl_value;

  acl_plugin_fill_5tuple_inline
    (sm->acl_plugin.p_acl_main, acl_lc, b, 0, 1 /* is_input */, 0 /* is_l2 */,
     &fa_5tuple0);
  if (acl_plugin_match_5tuple_inline
      (sm->acl_plugin.p_acl_main, acl_lc, &fa_5tuple0, 0, &acl_value,
       &match_acl_pos, &match_acl_index, &match_rule_index, &trace_bitmap))
    {
      if (acl_value >= vec_len (sm->nat44_1to1_acl_actions))
        {
          clib_warning ("NAT44 1to1 ACL refers invalid action: %u (Max: %u)",
                        acl_value, vec_len (sm->nat44_1to1_acl_actions));
          return 1;
        }
      /*
       * Match Found - apply NAT based on acl_value (action field of ACL)
       *
       * ACLs: While programming ACLs, the action field is configured with the
       * index value of the corresponding Action.
       * For example, if acl_value is 3, then the action configured in
       * sm->nat44_1to1_acl_actions[3] shall be applied.
       */
      ip4_header_t * ip = vlib_buffer_get_current (b);
      nat44_1to1_acl_action_t *action = &sm->nat44_1to1_acl_actions[acl_value];
      nat44_get_1to1_nat_addr (action->nat_src_prefix, action->src_prefix_len,
                               ip->src_address, out_src_addr);
      nat44_get_1to1_nat_addr (action->nat_dst_prefix, action->dst_prefix_len,
                               ip->dst_address, out_dst_addr);
      return 0;
    }
  return 1;
}

u32
nat44_ed_match_1to1_mapping (vlib_buffer_t *b, u8 out2in,
                             ip4_address_t *out_src_addr,
                             ip4_address_t *out_dst_addr)
{
  /*
   * Check if there is a NAT44 1to1 match and return the NAT addresses to be
   * applied for the packet
   */
  snat_main_t *sm = &snat_main;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  if (vec_len (sm->nat44_1to1_acl_matches) > sw_if_index)
    {
      nat44_1to1_acl_match_t * intf_acls =
        &sm->nat44_1to1_acl_matches[sw_if_index];
      u32 acl_lc = out2in ? intf_acls->acl_out_lc : intf_acls->acl_in_lc;
      if (acl_lc != ~0)
        return nat44_ed_match_1to1_acls (acl_lc, b,
                                         out_src_addr, out_dst_addr);
    }
  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
