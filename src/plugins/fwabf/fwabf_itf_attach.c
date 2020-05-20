/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  Copyright (C) 2020 flexiWAN Ltd.
 *  This file is part of the FWABF plugin.
 *  The FWABF plugin is fork of the FDIO VPP ABF plugin.
 *  It enhances ABF with functionality required for Flexiwan Multi-Link feature.
 *  For more details see official documentation on the Flexiwan Multi-Link.
 */

// nnoww - document

#include <plugins/fwabf/fwabf_itf_attach.h>
#include <plugins/fwabf/fwabf_locals.h>

#include <vnet/dpo/load_balance_map.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/ip4_mtrie.h>
#include <vnet/fib/ip6_fib.h>
#include <plugins/acl/exports.h>

/**
 * Forward declarations;
 */
extern vlib_node_registration_t fwabf_ip4_node;
extern vlib_node_registration_t fwabf_ip6_node;

/**
 * Pool of ABF interface attachment objects
 */
fwabf_itf_attach_t *fwabf_itf_attach_pool;

/**
 * A per interface vector of attached policies. used in the data-plane
 */
static u32 **abf_per_itf[FIB_PROTOCOL_MAX];

/**
 * Per interface values of ACL lookup context IDs. used in the data-plane
 */
static u32 *abf_alctx_per_itf[FIB_PROTOCOL_MAX];

/**
 * ABF ACL module user id returned during the initialization
 */
static u32 abf_acl_user_id;
/*
 * ACL plugin method vtable
 */

static acl_plugin_methods_t acl_plugin;

/**
 * A DB of attachments; key={abf_index,sw_if_index}
 */
static uword *abf_itf_attach_db;

static u64
abf_itf_attach_mk_key (u32 abf_index, u32 sw_if_index)
{
  u64 key;

  key = abf_index;
  key = key << 32;
  key |= sw_if_index;

  return (key);
}

static fwabf_itf_attach_t *
abf_itf_attach_db_find (u32 abf_index, u32 sw_if_index)
{
  uword *p;
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  p = hash_get (abf_itf_attach_db, key);

  if (NULL != p)
    return (pool_elt_at_index (fwabf_itf_attach_pool, p[0]));

  return (NULL);
}

static void
abf_itf_attach_db_add (u32 abf_index, u32 sw_if_index, fwabf_itf_attach_t * aia)
{
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  hash_set (abf_itf_attach_db, key, aia - fwabf_itf_attach_pool);
}

static void
abf_itf_attach_db_del (u32 abf_index, u32 sw_if_index)
{
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  hash_unset (abf_itf_attach_db, key);
}

static int
abf_cmp_attach_for_sort (void *v1, void *v2)
{
  const fwabf_itf_attach_t *aia1;
  const fwabf_itf_attach_t *aia2;

  aia1 = fwabf_itf_attach_get (*(u32 *) v1);
  aia2 = fwabf_itf_attach_get (*(u32 *) v2);

  return (aia1->aia_prio - aia2->aia_prio);
}

void
abf_setup_acl_lc (fib_protocol_t fproto, u32 sw_if_index)
{
  u32 *acl_vec = 0;
  u32 *aiai;
  fwabf_itf_attach_t *aia;

  if (~0 == abf_alctx_per_itf[fproto][sw_if_index])
    return;

  vec_foreach (aiai, abf_per_itf[fproto][sw_if_index])
  {
    aia = fwabf_itf_attach_get (*aiai);
    vec_add1 (acl_vec, aia->aia_acl);
  }
  acl_plugin.set_acl_vec_for_context (abf_alctx_per_itf[fproto][sw_if_index],
				      acl_vec);
  vec_free (acl_vec);
}

int
fwabf_itf_attach (fib_protocol_t fproto,
		u32 policy_id, u32 priority, u32 sw_if_index)
{
  fwabf_itf_attach_t *aia;
  fwabf_policy_t *ap;
  u32 api;

  api = fwabf_policy_find (policy_id);

  ASSERT (INDEX_INVALID != api);
  ap = fwabf_policy_get (api);

  /*
   * check this is not a duplicate
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL != aia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  /*
   * construct a new attachment object
   */
  pool_get (fwabf_itf_attach_pool, aia);

  aia->aia_prio = priority;
  aia->aia_acl = ap->ap_acl;
  aia->aia_abf = api;
  aia->aia_sw_if_index = sw_if_index;

  abf_itf_attach_db_add (policy_id, sw_if_index, aia);

  /*
   * Insert the policy on the interfaces list.
   */
  vec_validate_init_empty (abf_per_itf[fproto], sw_if_index, NULL);
  vec_add1 (abf_per_itf[fproto][sw_if_index], aia - fwabf_itf_attach_pool);
  if (1 == vec_len (abf_per_itf[fproto][sw_if_index]))
    {
      /*
       * when enabling the first ABF policy on the interface
       * we need to enable the interface input feature
       */
      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "fwabf-input-ip4" :
				    "fwabf-input-ip6"),
				   sw_if_index, 1, NULL, 0);

      /* if this is the first ABF policy, we need to acquire an ACL lookup context */
      vec_validate_init_empty (abf_alctx_per_itf[fproto], sw_if_index, ~0);
      abf_alctx_per_itf[fproto][sw_if_index] =
	acl_plugin.get_lookup_context_index (abf_acl_user_id, sw_if_index, 0);
    }
  else
    {
      vec_sort_with_function (abf_per_itf[fproto][sw_if_index],
			      abf_cmp_attach_for_sort);
    }

  /* Prepare and set the list of ACLs for lookup within the context */
  abf_setup_acl_lc (fproto, sw_if_index);

  return (0);
}

int
fwabf_itf_detach (fib_protocol_t fproto, u32 policy_id, u32 sw_if_index)
{
  fwabf_itf_attach_t *aia;
  u32 index;

  /*
   * check this is a valid attachment
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL == aia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  /*
   * first remove from the interface's vector
   */
  ASSERT (abf_per_itf[fproto]);
  ASSERT (abf_per_itf[fproto][sw_if_index]);

  index = vec_search (abf_per_itf[fproto][sw_if_index],
		      aia - fwabf_itf_attach_pool);

  ASSERT (index != ~0);
  vec_del1 (abf_per_itf[fproto][sw_if_index], index);

  if (0 == vec_len (abf_per_itf[fproto][sw_if_index]))
    {
      /*
       * when deleting the last ABF policy on the interface
       * we need to disable the interface input feature
       */
      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "fwabf-input-ip4" :
				    "fwabf-input-ip6"),
				   sw_if_index, 0, NULL, 0);

      /* Return the lookup context, invalidate its id in our records */
      acl_plugin.put_lookup_context_index (abf_alctx_per_itf[fproto]
					   [sw_if_index]);
      abf_alctx_per_itf[fproto][sw_if_index] = ~0;
    }
  else
    {
      vec_sort_with_function (abf_per_itf[fproto][sw_if_index],
			      abf_cmp_attach_for_sort);
    }

  /* Prepare and set the list of ACLs for lookup within the context */
  abf_setup_acl_lc (fproto, sw_if_index);

  /*
   * remove the attachment from the DB
   */
  abf_itf_attach_db_del (policy_id, sw_if_index);

  /*
   * return the object
   */
  pool_put (fwabf_itf_attach_pool, aia);

  return (0);
}

static u8 *
format_abf_intf_attach (u8 * s, va_list * args)
{
  fwabf_itf_attach_t *aia = va_arg (*args, fwabf_itf_attach_t *);
  fwabf_policy_t *ap;

  ap = fwabf_policy_get (aia->aia_abf);
  s = format (s, "abf-interface-attach: policy:%d priority:%d",
	      ap->ap_id, aia->aia_prio);
  return (s);
}

static clib_error_t *
abf_itf_attach_cmd (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id, sw_if_index;
  fib_protocol_t fproto;
  u32 is_del, priority;
  vnet_main_t *vnm;

  is_del = 0;
  sw_if_index = policy_id = ~0;
  vnm = vnet_get_main ();
  fproto = FIB_PROTOCOL_MAX;
  priority = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "add"))
	is_del = 0;
      else if (unformat (input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (input, "policy %d", &policy_id))
	;
      else if (unformat (input, "priority %d", &priority))
	;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == policy_id)
    {
      return (clib_error_return (0, "invalid policy ID:%d", policy_id));
    }
  if (~0 == sw_if_index)
    {
      return (clib_error_return (0, "invalid interface name"));
    }
  if (FIB_PROTOCOL_MAX == fproto)
    {
      return (clib_error_return (0, "Specify either ip4 or ip6"));
    }

  if (~0 == fwabf_policy_find (policy_id))
    return (clib_error_return (0, "invalid policy ID:%d", policy_id));

  if (is_del)
    fwabf_itf_detach (fproto, policy_id, sw_if_index);
  else
    fwabf_itf_attach (fproto, policy_id, priority, sw_if_index);

  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Attach an ABF policy to an interface.
 */
VLIB_CLI_COMMAND (abf_itf_attach_cmd_node, static) = {
  .path = "fwabf attach",
  .function = abf_itf_attach_cmd,
  .short_help = "fwabf attach <ip4|ip6> [del] policy <value> [priority <value>] <interface>",
};
/* *INDENT-ON* */

static clib_error_t *
abf_show_attach_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const fwabf_itf_attach_t *aia;
  u32 sw_if_index, *aiai;
  fib_protocol_t fproto;
  vnet_main_t *vnm;

  sw_if_index = ~0;
  vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == sw_if_index)
    {
      vlib_cli_output (vm, "specify an interface");
    }

  /* *INDENT-OFF* */
  FOR_EACH_FIB_IP_PROTOCOL(fproto)
  {
    if (sw_if_index < vec_len(abf_per_itf[fproto]))
      {
        if (vec_len(abf_per_itf[fproto][sw_if_index]))
          vlib_cli_output(vm, "%U:", format_fib_protocol, fproto);

        vec_foreach(aiai, abf_per_itf[fproto][sw_if_index])
          {
            aia = pool_elt_at_index(fwabf_itf_attach_pool, *aiai);
            vlib_cli_output(vm, " %U", format_abf_intf_attach, aia);
          }
      }
  }
  /* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abf_show_attach_cmd_node, static) = {
  .path = "show fwabf attach",
  .function = abf_show_attach_cmd,
  .short_help = "show fwabf attach <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

typedef enum abf_next_t_
{
  ABF_NEXT_DROP,
  ABF_N_NEXT,
} abf_next_t;

typedef struct abf_input_trace_t_
{
  abf_next_t next;
  index_t index;
} abf_input_trace_t;

typedef enum
{
#define abf_error(n,s) ABF_ERROR_##n,
#include "fwabf_error.def"
#undef abf_error
  ABF_N_ERROR,
} abf_error_t;

static uword
fwabf_input_ip4 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index, matches;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  matches = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          const u32*            attachments0;
          const fwabf_itf_attach_t* aia0;
          abf_next_t            next0 = ABF_NEXT_DROP;
          vlib_buffer_t*        b0;
          fa_5tuple_opaque_t    fa_5tuple0;
          const dpo_id_t*       dpo0;
          dpo_id_t              dpo0_policy;
          u32 bi0;
          u32 sw_if_index0;
          u32 match_acl_index   = ~0;
          u32 match_acl_pos     = ~0;
          u32 match_rule_index  = ~0;
          u32 trace_bitmap      = 0;
          u32 match0            = 0;
          u8 action;
          ip4_header_t*         ip40 = NULL;
          int                   local0;
          u32                   hash_c0;
          u32                   lbi0;
          const load_balance_t* lb0;
          flow_hash_config_t    flow_hash_config0;
          ip4_main_t*           im = &ip4_main;
          ip4_fib_mtrie_t*      mtrie0;
          ip4_fib_mtrie_leaf_t  leaf0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          ip40 = vlib_buffer_get_current (b0);

          /*
           * The fwabf_input_inline node replaces the ip4_lookup_inline node.
           * This is done to avoid FIB lookup twice in case, when packet does
           * not match policy classification (ACL lookup failure).
           * Therefore we have to resuse the ip4_lookup_inline code.
           * The last is consist of two parts - lookup in FIB and fetching
           * DPO out of found DPO.
           * Below the first part is placed - FIB lookup.
           */
          ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b0);
          mtrie0 = &ip4_fib_get (vnet_buffer (b0)->ip.fib_index)->mtrie;
          leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, &ip40->dst_address);
          leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip40->dst_address, 2);
          leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip40->dst_address, 3);

          lbi0  = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
          ASSERT (lbi0);
          lb0 = load_balance_get(lbi0);
          ASSERT (lb0->lb_n_buckets > 0);
          ASSERT (is_pow2 (lb0->lb_n_buckets));

          /*
           * Check if the packet is designated to local node.
           * In that case we should not check for policy, as 'all packets' rule
           * might send it out of VPP! Just go right to the ip4_lookup_inline
           * finish: use FIB lookup result to forward packet to next node.
           */
          local0 = fwabf_locals_ip4_exists (&ip40->dst_address);

          if (!local0)
            {
              /*
               * Perform ACL lookup and if found - apply policy.
               */

              sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

              ASSERT (vec_len (abf_per_itf[FIB_PROTOCOL_IP4]) > sw_if_index0);
              attachments0 = abf_per_itf[FIB_PROTOCOL_IP4][sw_if_index0];

              ASSERT (vec_len (abf_alctx_per_itf[FIB_PROTOCOL_IP4]) > sw_if_index0);
              /*
              * check if any of the policies attached to this interface matches.
              */
              u32 lc_index = abf_alctx_per_itf[FIB_PROTOCOL_IP4][sw_if_index0];

              /*
                A non-inline version looks like this:

                acl_plugin.fill_5tuple (lc_index, b0, (FIB_PROTOCOL_IP6 == fproto),
                1, 0, &fa_5tuple0);
                if (acl_plugin.match_5tuple
                (lc_index, &fa_5tuple0, (FIB_PROTOCOL_IP6 == fproto), &action,
                &match_acl_pos, &match_acl_index, &match_rule_index,
                &trace_bitmap))
                . . .
              */
              acl_plugin_fill_5tuple_inline (acl_plugin.p_acl_main, lc_index, b0,
                    0, 1, 0, &fa_5tuple0);

              if (acl_plugin_match_5tuple_inline
                  (acl_plugin.p_acl_main, lc_index, &fa_5tuple0,
                  0, &action, &match_acl_pos,
                  &match_acl_index, &match_rule_index, &trace_bitmap))
                {
                  /*
                  * match:
                  *  follow the DPO chain if available. Otherwise fallback to feature arc.
                  */
                  aia0 = fwabf_itf_attach_get (attachments0[match_acl_pos]);
                  match0 = fwabf_policy_get_dpo_ip4 (aia0->aia_abf, b0, lb0, &dpo0_policy);
                  if (PREDICT_TRUE(match0))
                    {
                      next0 = dpo0_policy.dpoi_next_node;
                      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0_policy.dpoi_index;
                    }
                  matches++;
                }
            } /*if (local) else*/

          /*
           * If packet is locally designated or if policy was not applied,
           * finish the ip4_lookup_inline logic - part two of ip4_lookup_inline
           * code - use DPO found by FIB lookup.
           */
          if (match0==0)
            {
              hash_c0 = vnet_buffer (b0)->ip.flow_hash = 0;
              if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
                {
                  /* Use flow hash to compute multipath adjacency. */
                  flow_hash_config0 = lb0->lb_hash_config;
                  hash_c0 = vnet_buffer (b0)->ip.flow_hash =
                            ip4_compute_flow_hash (ip40, flow_hash_config0);
                  dpo0 = load_balance_get_fwd_bucket (lb0,
                                  (hash_c0 & (lb0->lb_n_buckets_minus_1)));
                }
              else
                {
                  dpo0 = load_balance_get_bucket_i (lb0, 0);
                }

              next0 = dpo0->dpoi_next_node;
              vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
            }


          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              abf_input_trace_t *tr;

              tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next = next0;
              tr->index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                  to_next, n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, fwabf_ip4_node.index, ABF_ERROR_MATCHED, matches);

  return frame->n_vectors;
}

static uword
fwabf_input_ip6 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index, matches;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  matches = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          const u32*            attachments0;
          const fwabf_itf_attach_t* aia0;
          abf_next_t            next0 = ABF_NEXT_DROP;
          vlib_buffer_t*        b0;
          fa_5tuple_opaque_t    fa_5tuple0;
          const dpo_id_t*       dpo0;
          dpo_id_t              dpo0_policy;
          u32 bi0;
          u32 sw_if_index0;
          u32 match_acl_index   = ~0;
          u32 match_acl_pos     = ~0;
          u32 match_rule_index  = ~0;
          u32 trace_bitmap      = 0;
          u32 match0            = 0;
          u8 action;
          ip6_header_t*         ip60;
          int                   local0;
          u32                   hash_c0;
          u32                   lbi0;
          const load_balance_t* lb0;
          flow_hash_config_t    flow_hash_config0;
          ip6_main_t* im        = &ip6_main;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          /*
           * The fwabf_input_inline node replaces the ip6_lookup_inline node.
           * This is done to avoid FIB lookup twice in case, when packet does
           * not match policy classification (ACL lookup failure).
           * Therefore we have to resuse the ip6_lookup_inline code.
           * The last is consist of two parts - lookup in FIB and fetching
           * DPO out of found DPO.
           * Below the first part is placed - FIB lookup.
           */
          ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b0);
          ip60 = vlib_buffer_get_current (b0);
          lbi0 = ip6_fib_table_fwding_lookup (
                    im, vnet_buffer (b0)->ip.fib_index, &ip60->dst_address);
          ASSERT (lbi0);
          lb0 = load_balance_get(lbi0);
          ASSERT (lb0->lb_n_buckets > 0);
          ASSERT (is_pow2 (lb0->lb_n_buckets));

          /*
           * Check if the packet is designated to local node.
           * In that case we should not check for policy, as 'all packets' rule
           * might send it out of VPP! Just go right to the ip6_lookup_inline
           * finish: use FIB lookup result to forward packet to next node.
           */
          local0 = fwabf_locals_ip6_exists (&ip60->dst_address);

          if (!local0)
            {
              /*
               * Perform ACL lookup and if found - apply policy.
               */

              sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

              ASSERT (vec_len (abf_per_itf[FIB_PROTOCOL_IP6]) > sw_if_index0);
              attachments0 = abf_per_itf[FIB_PROTOCOL_IP6][sw_if_index0];

              ASSERT (vec_len (abf_alctx_per_itf[FIB_PROTOCOL_IP6]) > sw_if_index0);
              /*
              * check if any of the policies attached to this interface matches.
              */
              u32 lc_index = abf_alctx_per_itf[FIB_PROTOCOL_IP6][sw_if_index0];

              acl_plugin_fill_5tuple_inline (acl_plugin.p_acl_main, lc_index, b0,
                    1, 1, 0, &fa_5tuple0);

              if (acl_plugin_match_5tuple_inline
                  (acl_plugin.p_acl_main, lc_index, &fa_5tuple0,
                  1, &action, &match_acl_pos,
                  &match_acl_index, &match_rule_index, &trace_bitmap))
                {
                  /*
                  * match:
                  *  follow the DPO chain if available. Otherwise fallback to feature arc.
                  */
                  aia0 = fwabf_itf_attach_get (attachments0[match_acl_pos]);
                  match0 = fwabf_policy_get_dpo_ip6 (aia0->aia_abf, b0, lb0, &dpo0_policy);
                  if (PREDICT_TRUE(match0))
                    {
                      next0 = dpo0_policy.dpoi_next_node;
                      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0_policy.dpoi_index;
                    }
                  matches++;
                }
            } /*if (local) else*/

          /*
           * If packet is locally designated or if policy was not applied,
           * finish the ip4_lookup_inline logic - part two of ip4_lookup_inline
           * code - use DPO found by FIB lookup.
           */
          if (match0 == 0)
            {
              hash_c0 = vnet_buffer (b0)->ip.flow_hash = 0;
              if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
                {
                  /* Use flow hash to compute multipath adjacency. */
                  flow_hash_config0 = lb0->lb_hash_config;
                  hash_c0 = vnet_buffer (b0)->ip.flow_hash =
                            ip6_compute_flow_hash (ip60, flow_hash_config0);
                  dpo0 = load_balance_get_fwd_bucket (lb0,
                                  (hash_c0 & (lb0->lb_n_buckets_minus_1)));
                }
              else
                {
                  dpo0 = load_balance_get_bucket_i (lb0, 0);
                }

              next0 = dpo0->dpoi_next_node;
              vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

              /* Only process the HBH Option Header if explicitly configured to do so */
              if (PREDICT_FALSE(ip60->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS))
                {
                  next0 = (dpo_is_adj (dpo0) && im->hbh_enabled) ?
                          (ip_lookup_next_t) IP6_LOOKUP_NEXT_HOP_BY_HOP : next0;
                }
            }

          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              abf_input_trace_t *tr;

              tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next = next0;
              tr->index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                  to_next, n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, fwabf_ip6_node.index, ABF_ERROR_MATCHED, matches);

  return frame->n_vectors;
}

static u8 *
format_abf_input_trace (u8 * s, va_list * args)
{
  // nnoww - TODO - check if we can add some usefull info here!
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  abf_input_trace_t *t = va_arg (*args, abf_input_trace_t *);

  s = format (s, " next %d index %d", t->next, t->index);
  return s;
}

static char *abf_error_strings[] = {
#define abf_error(n,s) s,
#include "fwabf_error.def"
#undef abf_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (fwabf_ip4_node) =
{
  .function = fwabf_input_ip4,
  .name = "fwabf-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_abf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ABF_N_ERROR,
  .error_strings = abf_error_strings,
  .n_next_nodes = ABF_N_NEXT,
  .next_nodes =
  {
    [ABF_NEXT_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (fwabf_ip6_node) =
{
  .function = fwabf_input_ip6,
  .name = "fwabf-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_abf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = ABF_N_NEXT,

  .next_nodes =
  {
    [ABF_NEXT_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (abf_ip4_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "fwabf-input-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

VNET_FEATURE_INIT (abf_ip6_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "fwabf-input-ip6",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};
/* *INDENT-ON* */

static clib_error_t *
abf_itf_bond_init (vlib_main_t * vm)
{
  clib_error_t *acl_init_res = acl_plugin_exports_init (&acl_plugin);
  if (acl_init_res)
    return (acl_init_res);

  abf_acl_user_id =
    acl_plugin.register_user_module ("ABF plugin", "sw_if_index", NULL);

  return (NULL);
}

VLIB_INIT_FUNCTION (abf_itf_bond_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
