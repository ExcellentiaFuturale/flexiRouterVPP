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
 *  Copyright (C) 2022 flexiWAN Ltd.
 *  This file is part of the FWAPP plugin.
 *  The FWAPP plugin is fork of the FDIO VPP ABF plugin.
 *  It enhances ABF with functionality required for Flexiwan Multi-Link feature.
 *  For more details see official documentation on the Flexiwan Multi-Link.
 */

/**
 * This file includes implemenation of the Attachment part of the Flexiwan ACL Based
 * Forwarding Policy object.
 * The Attachment binds poolicy to RX interface, thus activating it.
 *
 * Every Policy object has as much Attachment objects as a number of interfaces
 * on which packets that might be a subject for policy are received.
 * Currently every LAN interface and every tunnel interface has Attachment.
 * Attachment to tunnel is needed to apply policy on intermediate VPPs on the way
 * to tunnel remote end.
 *
 * The Attachment module implements fwapp-input-ip4/fwapp-input-ip6 node.
 * This node is placed on ip4-unicast/ip6-unicast arc. Once the Attachment
 * feature is activated, the node starts to receive buffers from ip4-input/
 * ip4-input-nochecksum/NAT/ACL nodes and instead of ip4-lookup node.
 * The node logic performs following:
 *    1. Make FIB lookup (copied from ip4-lookup/ip6-lookup nodes)
 *    2. Make ACL lookup (copied from ABF plugin)
 *    3. If ACL lookup fails, hence policy should NOT be applied to packet,
 *       than:
 *          Forward packet according ip4-lookup/ip6-lookup logic:
 *          peek DPO from children of lookup Load Balancing DPO and use
 *          it for next node and for adjacency metadata.
 *          If there are multiple children, the flow hash is used to choose.
 *          This code was copied from ip4-lookup/ip6-lookup nodes.
 *       else:
 *          Forward packet according FWAPP policy:
 *          find Attachment object based on ACL lookup output and fetch the DPO
 *          to be used for forwarding out of it's parent Policy object.
 *          If Policy fails for some reason, the ip4-lookup/ip6-lookup logic
 *          will take a place.
 *
 * In comparison to original abf_itf_attach file, where the FWAPP Attachment was
 * forked of, the FWAPP Attachment fetches DPO to be used from Policy object.
 * In addition the Attachment logic completely replaces ip4_lookup/ip6_lookup
 * node. The ip4_lookup/ip6_lookup code is simply copied here. It is needed
 * to avoid lookup twice for packets that are not subject for policy,
 * as policy algorithm requires lookup to choose path out of available pathes.
 */

#include <vlib/node.h>
#include <plugins/acl/exports.h>
#include "fwapp_types.h"

/**
 * Forward declarations;
 */
extern vlib_node_registration_t fwapp_ip4_node;
extern vlib_node_registration_t fwapp_ip6_node;


typedef struct fwapp_main_t
{
  fwapp_application_t* apps;

  uword * apps_by_name;  /*hash that maps app name into app object*/


  // app graph
  // Let's adopt Linus approach - less if-s :)
  fwapp_application_t graph_head;
  fwapp_application_t graph_tail;

  /**
   * Pool of ABF interface attachment objects
   */
  // nnoww - check if needed
  fwapp_itf_attach_t *itf_attach_pool;

  /**
   * A per interface vector of attached policies. used in the data-plane
   */
  // nnoww - check if needed
  u32 **attach_per_itf[FIB_PROTOCOL_MAX];

  /**
   * Per interface values of ACL lookup context IDs. used in the data-plane
   */
  // nnoww - check if needed
  u32 *acl_lc_per_itf[FIB_PROTOCOL_MAX];

  /**
   * ABF ACL module user id returned during the initialization
   */
  // nnoww - check if needed
  u32 acl_user_id;

  /*
  * ACL plugin method vtable
  */
  acl_plugin_methods_t acl_plugin;

  /**
   * A DB of attachments; key={abf_index,sw_if_index}
   */
  // nnoww - check if needed
  uword *itf_attach_db;

} fwapp_main_t;

fwapp_main_t fwapp_main;

u64
fwapp_itf_attach_mk_key (u32 policy, u32 sw_if_index)
{
  // nnoww - check if needed
  u64 key;

  key = policy;
  key = key << 32;
  key |= sw_if_index;

  return key;
}

static fwapp_itf_attach_t *
fwapp_itf_attach_db_find (u32 policy, u32 sw_if_index)
{
  // nnoww - check if needed
  uword *p;
  u64 key;

  key = fwapp_itf_attach_mk_key (policy, sw_if_index);

  p = hash_get (fwapp_itf_attach_db, key);

  if (p != NULL)
    return (pool_elt_at_index (fwapp_itf_attach_pool, p[0]));

  return NULL;
}

static void
fwapp_itf_attach_db_add (u32 policy, u32 sw_if_index, fwapp_itf_attach_t * fia)
{
  // nnoww - check if needed
  u64 key = fwapp_itf_attach_mk_key (policy, sw_if_index);
  hash_set (fwapp_itf_attach_db, key, fia - fwapp_itf_attach_pool);
}

static void
fwapp_itf_attach_db_del (u32 policy, u32 sw_if_index)
{
  // nnoww - check if needed
  u64 key = fwapp_itf_attach_mk_key (policy, sw_if_index);
  hash_unset (fwapp_itf_attach_db, key);
}

void fwapp_setup_acl_lc (fib_protocol_t fproto, u32 sw_if_index)
{
  // nnoww - check if needed
  u32 *acl_vec = 0;
  u32 *fiai;
  fwapp_itf_attach_t *fia;

  if (~0 == fwapp_acl_lc_per_itf[fproto][sw_if_index])
    return;

  vec_foreach (fiai, fwapp_attach_per_itf[fproto][sw_if_index])
  {
    fia = fwapp_itf_attach_get (*fiai);
    vec_add1 (acl_vec, fia->fia_acl);
  }
  acl_plugin.set_acl_vec_for_context (
                        fwapp_acl_lc_per_itf[fproto][sw_if_index], acl_vec);
  vec_free (acl_vec);
}

int fwapp_itf_attach (fib_protocol_t fproto, u32 policy_id, u32 priority, u32 sw_if_index)
{
  // nnoww - check if needed
  fwapp_itf_attach_t* fia;
  fwapp_policy_t*     p;
  u32                 pi;

  pi = fwapp_policy_find (policy_id);

  ASSERT (INDEX_INVALID != pi);
  p = fwapp_policy_get (pi);
  p->refCounter++;

  /*
   * check this is not a duplicate
   */
  fia = fwapp_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL != fia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  /*
   * construct a new attachment object
   */
  pool_get (fwapp_itf_attach_pool, fia);

  fia->fia_prio   = priority;
  fia->fia_acl    = p->acl;
  fia->fia_policy = pi;
  fia->fia_sw_if_index = sw_if_index;

  fwapp_itf_attach_db_add (policy_id, sw_if_index, fia);

  /*
   * Insert the attachment/policy on the interfaces list.
   */
  vec_validate_init_empty (fwapp_attach_per_itf[fproto], sw_if_index, NULL);
  vec_add1 (fwapp_attach_per_itf[fproto][sw_if_index], fia - fwapp_itf_attach_pool);
  if (1 == vec_len (fwapp_attach_per_itf[fproto][sw_if_index]))
    {
      /*
       * When enabling the first FWAPP policy on the interface
       * we need:
       *  1. to enable the interface input feature.
       *  2. to acquire an ACL lookup context in ACL plugin
       */
      vnet_feature_enable_disable (
          (FIB_PROTOCOL_IP4 == fproto ? "ip4-unicast" : "ip6-unicast"),
				  (FIB_PROTOCOL_IP4 == fproto ? "fwapp-input-ip4" : "fwapp-input-ip6"),
				  sw_if_index, 1, NULL, 0);

      vec_validate_init_empty (fwapp_acl_lc_per_itf[fproto], sw_if_index, ~0);
      fwapp_acl_lc_per_itf[fproto][sw_if_index] =
        acl_plugin.get_lookup_context_index (fwapp_acl_user_id, sw_if_index, 0);
    }
  else
    {
    }

  /*
   * update ACL plugin with our contexts
   */
  fwapp_setup_acl_lc (fproto, sw_if_index);
  return (0);
}

int
fwapp_itf_detach (fib_protocol_t fproto, u32 policy_id, u32 sw_if_index)
{
  // nnoww - check if needed
  fwapp_itf_attach_t* fia;
  fwapp_policy_t*     p;
  u32 index;

  /*
   * check this is a valid attachment
   */
  fia = fwapp_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL == fia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  p = fwapp_policy_get (fwapp_policy_find(policy_id));
  p->refCounter--;

  /*
   * first remove from the interface's vector
   */
  ASSERT (fwapp_attach_per_itf[fproto]);
  ASSERT (fwapp_attach_per_itf[fproto][sw_if_index]);

  index = vec_search (fwapp_attach_per_itf[fproto][sw_if_index],
		                  fia - fwapp_itf_attach_pool);

  ASSERT (index != ~0);
  vec_del1 (fwapp_attach_per_itf[fproto][sw_if_index], index);

  if (0 == vec_len (fwapp_attach_per_itf[fproto][sw_if_index]))
    {
      /*
       * When deleting the last FWAPP attachment on the interface
       * we need:
       *  - to disable the interface input feature
       *  - to release ACL lookup context in ACL plugin
       */
      vnet_feature_enable_disable (
          (FIB_PROTOCOL_IP4 == fproto ? "ip4-unicast" : "ip6-unicast"),
          (FIB_PROTOCOL_IP4 == fproto ? "fwapp-input-ip4" : "fwapp-input-ip6"),
				  sw_if_index, 0, NULL, 0);

      acl_plugin.put_lookup_context_index (fwapp_acl_lc_per_itf[fproto][sw_if_index]);
      fwapp_acl_lc_per_itf[fproto][sw_if_index] = ~0;
    }

  /*
   * update ACL plugin with our contexts
   */
  fwapp_setup_acl_lc (fproto, sw_if_index);

  /*
   * remove the attachment from the DB
   */
  fwapp_itf_attach_db_del (policy_id, sw_if_index);
  pool_put (fwapp_itf_attach_pool, fia);

  return (0);
}

static u8 *
format_fwapp_itf_attach (u8 * s, va_list * args)
{
  // nnoww - check if needed
  fwapp_itf_attach_t *fia = va_arg (*args, fwapp_itf_attach_t *);
  fwapp_policy_t *p;

  p = fwapp_policy_get (fia->fia_policy);
  s = format (s, "fabf-interface-attach: policy:%d priority:%d", p->id, fia->fia_prio);
  return (s);
}

static fwapp_application_t* fwapp_app_find (u8* name)
{
  fwapp_application_t** p_app;
  p_app = (fwapp_application_t**)hash_get_mem (fwapp->apps_by_name, name);
  if (p_app)
    return p_app[0];
  return NULL;
}

static u32 fwapp_app_add (u8* name, u8* descr, u8* next, fwapp_app_type_t type,
                          fwapp_fallback_t fb, u32 acl, fwapp_interface_arg_t* iface_args)
{
  fwapp_main_t*        fwapp = &fwapp_main;
  fwapp_application_t* curr, app = NULL;
  fwapp_application_t* next_app = NULL;
  u32                  res;

  if (next) {
    next_app = fwapp_app_find (name);
    if (!next_app) {
      clib_error ("the next=%s application was not found");
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
  }

  /* No need to lock fwapp, as applications are added and are deleted by main thread only */

  vec_foreach (curr, fwapp->apps)
  {
    if (curr->allocated == 0) {
      curr->allocated = 1;
      app = curr;
      break;
    }
  }
  if (!app) {
    clib_error ("no more space, increase FWAPP_MAX_NUM_APPLICATIONS=%d", FWAPP_MAX_NUM_APPLICATIONS);
    return VNET_API_ERROR_LIMIT_EXCEEDED;
  }

  fwapp_interface_create(&app->iface, iface_args, res);
  if (res) {
    curr->allocated = 0;
    clib_error ("failed to create interface %d: res=%d", iface_args->type, res);
    return res;
  }

  app->name        = vec_dup(name);
  app->description = vec_dup(descr);
  app->type        = type;
  app->fallback    = fallback;
  app->acl         = acl;

  hash_set_mem (fwapp->apps_by_name, name, app);

  /* Insert application into graph
  */
  if (!next_app)
    next_app = &fwapp->graph_tail;
  app->prev            = next_app->prev;
  next_app->prev->next = app;
  next_app->prev       = app;
  app->next            = next_app;

  return 0;
}

static u32 fwapp_app_delete (fwapp_application_t*  app)
{
  /* Firstly remove app from graph to avoid datapath to use it,
     than close the interface to the app.
  */
  app->prev->next = app->next;
  app->next->prev = app->prev;

  fwapp_interface_destroy(&app->iface);

  hash_unset_mem (fwapp->apps_by_name, app->name);

  vec_free(app->name);
  vec_free(app->description);

  app->allocated = 0;
  return 0;
}

uword
unformat_fwapp_interface (unformat_input_t * input, va_list * args)
{
  fwapp_interface_arg_t* a = va_arg (*args, fwapp_interface_arg_t*);

  clib_memset (a, 0, sizeof (*a));
  if (unformat (input, "tap"))
    a->type = FWAPP_INTERFACE_TAP;
  else
    return 0;
  return 1;
}

static clib_error_t *
fwapp_app_add_del_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 is_del            = 0;
  u8* name              = NULL;
  u8* descr             = NULL;
  u8* next              = NULL;
  fwapp_app_type_t type = FWAPP_APP_TYPE_MONITOR;
  fwapp_fallback_t fb   = FWAPP_FALLBACK_CONTINUE;
  u32 acl               = INVALID_INDEX;
  fwapp_interface_arg_t iface_args;
  clib_error_t*         ret = NULL;
  fwapp_application_t*  app = NULL;
  u32                   res;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_del = 1;
      else if (unformat (input, "add"))
        is_del = 0;
      else if (unformat (input, "%s", &name))
	      ;
      else if (unformat (input, "descr %s", &descr))
	      ;
      else if (unformat (input, "monitor"))
	      type = FWAPP_APP_TYPE_MONITOR;
      else if (unformat (input, "divert"))
	      type = FWAPP_APP_TYPE_DIVERT;
      else if (unformat (input, "fallback drop"))
	      fb = FWAPP_FALLBACK_DROP;
      else if (unformat (input, "next %s", &next))
	      ;
      else if (unformat (input, "acl %d", &acl))
	      ;
      else if (unformat (input, "interface %U", unformat_fwapp_interface, &iface_args))
	      ;
      else {
        ret = (clib_error_return (0, "unknown input '%U'", format_unformat_error, input));
        goto done;
      }
    }

  if (!name)
    {
      ret = (clib_error_return (0, "no name was provided"));
      goto done;
    }
  if (acl == INVALID_INDEX)
    {
      ret = (clib_error_return (0, "no ACL index was provided"));
      goto done;
    }
  if (iface_args.type == FWAPP_INTERFACE_UNDEFINED)
    {
      ret = (clib_error_return (0, "no interface was provided"));
      goto done;
    }

  app = fwapp_app_find (name);
  if (app && is_del==0)
  {
      ret = (clib_error_return (0, "app %s exists", name));
      goto done;
  }
  else if (app==NULL && is_del==1)
  {
      ret = (clib_error_return (0, "app %s was not found", name));
      goto done;
  }

  if (is_del)
    res = fwapp_app_delete (app);
  else {
    res = fwapp_app_add (name, descr, next, type, fb, acl, &iface_args);
  }
  if (res)
  {
      ret = clib_error_return (0, "failed to %s app %s: %u",
              (is_del?"delete":"add"), name, res);
      goto done;
  }

done:
  if (name)
    vec_free(name);
  if (descr)
    vec_free(descr);
  if (next)
    vec_free(next);
  return ret;
}

/* *INDENT-OFF* */
/**
 * Attach an ABF policy to an interface.
 */
VLIB_CLI_COMMAND (fwapp_app_add_del_command, static) = {
  .path = "fwapp app",
  .function = fwapp_app_add_del_cmd,
  .short_help = "fwapp app [add|del] <name> [descr <value>] <monitor|divert> [fallback <drop>] "
                "[next <name>] acl <index> interface <tap>",
};
/* *INDENT-ON* */

// nnoww - implement: implement [verbose] option - show application descriptions!
static clib_error_t *
fwapp_show_graph_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  // nnoww - implement: show fwapp graph
  const fwapp_itf_attach_t *fia;
  u32 sw_if_index, *fiai;
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
    if (sw_if_index < vec_len(fwapp_attach_per_itf[fproto]))
      {
        if (vec_len(fwapp_attach_per_itf[fproto][sw_if_index]))
          vlib_cli_output(vm, "%U:", format_fib_protocol, fproto);

        vec_foreach(fiai, fwapp_attach_per_itf[fproto][sw_if_index])
          {
            fia = pool_elt_at_index(fwapp_itf_attach_pool, *fiai);
            vlib_cli_output(vm, " %U", format_fwapp_itf_attach, fia);
          }
      }
  }
  /* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (fwapp_show_graph_command, static) = {
  .path = "show fwapp graph",
  .function = fwapp_show_graph_cmd,
  .short_help = "show fwapp graph",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

// nnoww - implement: make proper trace for fwapp!!!
typedef struct fwapp_input_trace_t_
{
  ip_lookup_next_t  next;     /* next node */
  index_t           adj;      /* resolved adjacency index */
  u32               match;    /* ACL match & Resolved by Policy */
  index_t           policy;   /* Policy index or UNDEFINED */
} fwapp_input_trace_t;

typedef enum
{
#define fwapp_error(n,s) FWAPP_ERROR_##n,
#include "fwapp_error.def"
#undef fwapp_error
  FWAPP_N_ERROR,
} fwapp_error_t;

static uword
fwapp_input_ip4 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
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
          const fwapp_itf_attach_t* fia0 = 0;
          ip_lookup_next_t      next0 = IP_LOOKUP_NEXT_DROP;
          vlib_buffer_t*        b0;
          fa_5tuple_opaque_t    fa_5tuple0;
          const dpo_id_t*       dpo0;
          dpo_id_t              dpo0_policy;
          u32 bi0;
          u32 sw_if_index0;
          u32 lc_index;
          u32 match_acl_index   = ~0;
          u32 match_acl_pos     = ~0;
          u32 match_rule_index  = ~0;
          u32 trace_bitmap      = 0;
          u32 match0            = 0;
          u8 action;
          ip4_header_t*         ip40 = NULL;
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
           * The fwapp_input_inline node replaces the ip4_lookup_inline node.
           * This is done to avoid FIB lookup twice in case, when packet does
           * not match policy classification (ACL lookup failure).
           * Therefore we have to reuse the ip4_lookup_inline code.
           * The last is consist of two parts - lookup in FIB and fetching
           * adjacency DPO out of found load balancing DPO.
           * Note the FIB lookup always brings the load balancing DPO, even
           * if it points to single adjacency DPO only.
           * Below the first part comes - FIB lookup.
           * It is used in both cases - either packet matches policy or not.
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
           * If FIB lookup brings not labeled DPO-s, the policy can't be applied,
           * as it uses labels to choose DPO-s for forwarding.
           * In this case there is no need to bother with ACL & Policy,
           * go directly to deafult routing - use FIB lookup result.
           * ASSUMPTION: if user wants policy, it labels all available tunnels,
           *             so FIB lookup can't bring mix of labeled and not labeled
           *             tunnels!
           *
           * The exception for this algorithm is DPO of default route.
           * Even if it is not labeled, user might want to enforce the default
           * route packets to go into policy tunnels on ACL & Policy match.
           * This is needed for use case of Branch-to-HeadQuaters topology,
           * where all traffic on the Branch VPP should go to the Head Quaters VPP,
           * and there it should go to internet or to other tunnel.
           */
          match0 = 0;
          if (fwapp_links_is_dpo_labeled_or_default_route (lb0, DPO_PROTO_IP4))
            {
              /*
                * Perform ACL lookup and if found - apply policy.
                */
              sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

              ASSERT (vec_len (fwapp_attach_per_itf[FIB_PROTOCOL_IP4]) > sw_if_index0);
              attachments0 = fwapp_attach_per_itf[FIB_PROTOCOL_IP4][sw_if_index0];

              ASSERT (vec_len (fwapp_acl_lc_per_itf[FIB_PROTOCOL_IP4]) > sw_if_index0);
              lc_index = fwapp_acl_lc_per_itf[FIB_PROTOCOL_IP4][sw_if_index0];

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
                  acl_main_t *am = acl_plugin.p_acl_main;
                  fwapp_quality_service_class_t sc = am->acls[match_acl_index].rules[match_rule_index].service_class;
                  if (sc <= FWAPP_QUALITY_SC_MIN || sc >= FWAPP_QUALITY_SC_MAX) {
                    clib_warning("wrong value for service class %d must be in range from %d to %d",
                                sc, FWAPP_QUALITY_SC_MIN, FWAPP_QUALITY_SC_MAX);
                    sc = FWAPP_QUALITY_SC_STANDARD;
                  }
                  fia0 = fwapp_itf_attach_get (attachments0[match_acl_pos]);
                  match0 = fwapp_policy_get_dpo_ip4 (fia0->fia_policy, b0, lb0, sc, &dpo0_policy);
                  if (PREDICT_TRUE(match0))
                    {
                      next0 = dpo0_policy.dpoi_next_node;
                      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0_policy.dpoi_index;
                    }

		  /* Mark the packet with classification result */
		  vnet_buffer2 (b0)->qos.service_class = sc;
		  vnet_buffer2 (b0)->qos.importance =
		    am->acls[match_acl_index].rules[match_rule_index].importance;
		  vnet_buffer2 (b0)->qos.source = QOS_SOURCE_IP;
		  b0->flags |= VNET_BUFFER_F_IS_CLASSIFIED;

                  matches++;
                }
            } /*if (fwapp_links_is_dpo_labeled_or_default_route (lb0)*/

          /*
           * If policy was not applied, finish the ip4_lookup_inline logic -
           * part two of ip4_lookup_inline code - use DPO found by FIB lookup.
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
              fwapp_input_trace_t *tr;

              tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next   = next0;
              tr->adj    = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
              tr->match  = match0;
              tr->policy = fia0 ? fia0->fia_policy : -1;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                  to_next, n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, fwapp_ip4_node.index, FWAPP_ERROR_MATCHED, matches);

  return frame->n_vectors;
}

// nnoww - implement: don't forget to mirror fwapp_input_ip4 into fwapp_input_ip6
static uword
fwapp_input_ip6 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
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
          const fwapp_itf_attach_t* fia0 = 0;
          ip_lookup_next_t      next0 = IP_LOOKUP_NEXT_DROP;
          vlib_buffer_t*        b0;
          fa_5tuple_opaque_t    fa_5tuple0;
          const dpo_id_t*       dpo0;
          dpo_id_t              dpo0_policy;
          u32 bi0;
          u32 sw_if_index0;
          u32 lc_index;
          u32 match_acl_index   = ~0;
          u32 match_acl_pos     = ~0;
          u32 match_rule_index  = ~0;
          u32 trace_bitmap      = 0;
          u32 match0            = 0;
          u8 action;
          ip6_header_t*         ip60;
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
           * The fwapp_input_inline node replaces the ip6_lookup_inline node.
           * This is done to avoid FIB lookup twice in case, when packet does
           * not match policy classification (ACL lookup failure).
           * Therefore we have to resuse the ip6_lookup_inline code.
           * The last is consist of two parts - lookup in FIB and fetching
           * adjacency DPO out of found load balancing DPO.
           * Note the FIB lookup always brings the load balancing DPO, even
           * if it points to single adjacency DPO only.
           * Below the first part comes - FIB lookup.
           * It is used in both cases - either packet matches policy or not.
           */
          ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b0);
          ip60 = vlib_buffer_get_current (b0);
          lbi0 = ip6_fib_table_fwding_lookup (
                    vnet_buffer (b0)->ip.fib_index, &ip60->dst_address);
          ASSERT (lbi0);
          lb0 = load_balance_get(lbi0);
          ASSERT (lb0->lb_n_buckets > 0);
          ASSERT (is_pow2 (lb0->lb_n_buckets));

          /*
           * If FIB lookup brings not labeled DPO-s, the policy can't be applied,
           * as it uses labels to choose DPO-s for forwarding.
           * In this case there is no need to bother with ACL & Policy,
           * go directly to deafult routing - use FIB lookup result.
           * ASSUMPTION: if user wants policy, it labels all available tunnels,
           *             so FIB lookup can't bring mix of labeled and not labeled
           *             tunnels!
           *
           * The exception for this algorithm is DPO of default route. We have
           * to enable policy on such DPO in order to drop specific DIA packets
           * without DIA label! That means even if DPO is not labeled.
           * This is for user convenience, so he could set policy without
           * binding labels to interfaces.
           */
          match0 = 0;
          if (fwapp_links_is_dpo_labeled_or_default_route (lb0, DPO_PROTO_IP6))
            {
              /*
                * Perform ACL lookup and if found - apply policy.
                */
              sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

              ASSERT (vec_len (fwapp_attach_per_itf[FIB_PROTOCOL_IP6]) > sw_if_index0);
              attachments0 = fwapp_attach_per_itf[FIB_PROTOCOL_IP6][sw_if_index0];

              ASSERT (vec_len (fwapp_acl_lc_per_itf[FIB_PROTOCOL_IP6]) > sw_if_index0);
              lc_index = fwapp_acl_lc_per_itf[FIB_PROTOCOL_IP6][sw_if_index0];

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
                  acl_main_t *am = acl_plugin.p_acl_main;
                  fwapp_quality_service_class_t sc = am->acls[match_acl_index].rules[match_rule_index].service_class;
                  if (sc <= FWAPP_QUALITY_SC_MIN || sc >= FWAPP_QUALITY_SC_MAX) {
                    clib_warning("wrong value for service class %d must be in range from %d to %d",
                                sc, FWAPP_QUALITY_SC_MIN, FWAPP_QUALITY_SC_MAX);
                    sc = FWAPP_QUALITY_SC_STANDARD;
                  }
                  fia0 = fwapp_itf_attach_get (attachments0[match_acl_pos]);
                  match0 = fwapp_policy_get_dpo_ip6 (fia0->fia_policy, b0, lb0, sc, &dpo0_policy);
                  if (PREDICT_TRUE(match0))
                    {
                      next0 = dpo0_policy.dpoi_next_node;
                      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = dpo0_policy.dpoi_index;
                    }

		  /* Mark the packet with classification result */
		  vnet_buffer2 (b0)->qos.service_class = sc;
		  vnet_buffer2 (b0)->qos.importance =
		    am->acls[match_acl_index].rules[match_rule_index].importance;
		  vnet_buffer2 (b0)->qos.source = QOS_SOURCE_IP;
		  b0->flags |= VNET_BUFFER_F_IS_CLASSIFIED;

                  matches++;
                }
            } /*if (fwapp_links_is_dpo_labeled_or_default_route (lb0)*/

          /*
           * If policy was not applied, finish the ip4_lookup_inline logic -
           * part two of ip4_lookup_inline code - use DPO found by FIB lookup.
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
              fwapp_input_trace_t *tr;

              tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next   = next0;
              tr->adj    = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
              tr->match  = match0;
              tr->policy = fia0 ? fia0->fia_policy : -1;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                  to_next, n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, fwapp_ip6_node.index, FWAPP_ERROR_MATCHED, matches);

  return frame->n_vectors;
}

static u8 *
format_fwapp_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  fwapp_input_trace_t *t = va_arg (*args, fwapp_input_trace_t *);
// nnoww - implement: add proper trace here
  s = format (s, " next %d adj %d match %d policy %d",
                t->next, t->adj, t->match, t->policy);
  return s;
}

static char *fwapp_error_strings[] = {
#define fwapp_error(n,s) s,
#include "fwapp_error.def"
#undef fwapp_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (fwapp_ip4_node) =
{
  .function = fwapp_input_ip4,
  .name = "fwapp-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_fwapp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = FWAPP_N_ERROR,
  .error_strings = fwapp_error_strings,
  .n_next_nodes = IP_LOOKUP_N_NEXT,   //  nnoww - check: what exact nodes I need here?
  .next_nodes = IP4_LOOKUP_NEXT_NODES,
};

VLIB_REGISTER_NODE (fwapp_ip6_node) =
{
  .function = fwapp_input_ip6,
  .name = "fwapp-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_fwapp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = IP6_LOOKUP_N_NEXT,  //  nnoww - check: what exact nodes I need here?
  .next_nodes = IP6_LOOKUP_NEXT_NODES,
};

VNET_FEATURE_INIT (fwapp_ip4_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "fwapp-input-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
  .runs_before = VNET_FEATURES ("fwabf_ip4_feature"),
};

VNET_FEATURE_INIT (fwapp_ip6_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "fwapp-input-ip6",
  .runs_after = VNET_FEATURES ("fwabf_ip6_feature"),
};
/* *INDENT-ON* */

static clib_error_t *
fwapp_init (vlib_main_t * vm)
{
  clib_error_t*        acl_init_res;
  fwapp_main_t*        fwapp = &fwapp_main;
  fwapp_application_t* curr;

  memset(fwapp, 0, sizeof(*fwapp));
  fwapp.graph_head->next = &fwapp.graph_tail;
  fwapp.graph_tail->prev = &fwapp.graph_head;
  fwapp.graph_head.name = "start";
  fwapp.graph_tail.name = "end";

  fwapp.apps_by_name = hash_create_string (FWAPP_MAX_NUM_APPLICATIONS, sizeof (fwapp_application_t*));

  acl_init_res = acl_plugin_exports_init (fwapp->acl_plugin);
  if (acl_init_res)
    return acl_init_res;

  fwapp->acl_user_id = acl_plugin.register_user_module ("FWAPP plugin", "app_index", NULL);

  vec_validate(fwapp->apps, FWAPP_MAX_NUM_APPLICATIONS);

  return (NULL);
}

// nnoww - implement: use app_index with vppctl fwapp add

VLIB_INIT_FUNCTION (fwapp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
