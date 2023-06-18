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

// nnoww - document

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

#include "fwapp_types.h"

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vppinfra/pool.h>

fwapp_main_t fwapp_main;

u32  static fwapp_tap_send(fwapp_interface_t* iface, vlib_buffer_t* b0);
u32  static fwapp_dpdk_send(fwapp_interface_t* iface, vlib_buffer_t* b0);
void static fwapp_app_detach_one(fwapp_application_t* app, u32 i);

typedef enum _fwapp_node_next_t
{
  FWAPP_NODE_NEXT_DROP,
  FWAPP_NODE_NEXT_ERROR_DROP,
  FWAPP_NODE_NEXT_INTERFACE_OUTPUT,
  FWAPP_NODE_N_NEXT
} fwapp_node_next_t;


// nnoww - implement
// If packet was received on APP interface:
// no ACL matching is performed
// if app is of divert type - forward to next on VPP arc
// if app is of span type  - drop (sanity, APP SERVER should not send us packets)

u32 fwapp_add_app (fwapp_application_cfg_t* cfg)
{
  fwapp_main_t*           fam = &fwapp_main;
  fwapp_application_t*    app = NULL;
  fwapp_application_t*    next_app = NULL;
  u32                     ai;
  u32                     ret;

  if (cfg->next_name) {
    next_app = fwapp_get_app_by_name (cfg->next_name);
    if (!next_app) {
      clib_error ("the next=%s application was not found");
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
  }

  /* No need to lock fwapp, as applications are added and are deleted by main thread only */

  pool_get(fam->apps, app);
  app->name        = vec_dup(cfg->name);
  app->description = vec_dup(cfg->description);
  app->type        = cfg->type;
  app->fallback    = cfg->fallback;
  app->acl         = cfg->acl;

  ai = app - fam->apps;
  hash_set_mem (fam->app_by_name, cfg->name, ai);

  ret = fwapp_app_attach (app, cfg->ifaces);
  if (ret != 0) {
    clib_error("failed to attach to the provided interfaces");
    pool_put(fam->apps, app);
    return ret;
  }

  /* Insert application into graph
  */
  if (!next_app)
    next_app = &fam->graph_tail;
  app->prev            = next_app->prev;
  next_app->prev->next = app;
  next_app->prev       = app;
  app->next            = next_app;

  return 0;
}

u32 fwapp_del_app (fwapp_application_t*  app)
{
  fwapp_main_t* fam = &fwapp_main;

  for (u32 i = 0; i < vec_len(app->ifaces); i++)
      fwapp_app_detach_one(app, i);
  vec_free(app->ifaces);

  if (app->prev && app->next) {
    /* as we use anchor head and tail, both prev and next should exist */
    app->prev->next = app->next;
    app->next->prev = app->prev;
  }
  if (app->name) {
    hash_unset_mem (fam->app_by_name, app->name);
    vec_free(app->name);
  }
  if (app->description)
    vec_free(app->description);
  pool_put(fam->apps, app);
  return 0;
}

u32 fwapp_app_attach (fwapp_application_t* app, fwapp_interface_cfg_t* cfgs)
{
  fwapp_main_t*           fam = &fwapp_main;
  fwapp_interface_cfg_t*  cfg;
  fwapp_interface_t       iface;
  u32                     app_sw_if_index, src_sw_if_index;
  u32                     ai = app - fam->apps;
  u32                     i, new_index_start = vec_len(app->ifaces);

  /* No need to lock fwapp, as applications are added and are deleted by main thread only */

  vec_foreach (cfg, cfgs)
  {
    memset(&iface, 0, sizeof(iface));
    iface.type             = cfg->type;
    iface.app_sw_if_index  = cfg->app_sw_if_index;
    iface.src_sw_if_index  = cfg->src_sw_if_index;
    if (cfg->type == FWAPP_INTERFACE_TAP) {
      iface.pfn_send = fwapp_tap_send;
    } else if (cfg->type == FWAPP_INTERFACE_DPDK) {
      iface.pfn_send = fwapp_dpdk_send;
    } else {
      clib_error("not supported interface type: %d", cfg->type);
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }
    vec_add1(app->ifaces, iface);
  }

  for (i = new_index_start; i < vec_len(app->ifaces); i++)
  {
    src_sw_if_index = app->ifaces[i].src_sw_if_index;
    app_sw_if_index = app->ifaces[i].app_sw_if_index;

    /* enable dispatching packets to the application node
    */
    if (src_sw_if_index != INDEX_INVALID)
    {
      vec_validate_init_empty(fam->src_if_indexes, src_sw_if_index+1, 0);
      if (fam->src_if_indexes[src_sw_if_index] == 0)
        vnet_feature_enable_disable("ip4-unicast", "fwapp-input-ip4", src_sw_if_index, 1, NULL, 0);
      fam->src_if_indexes[src_sw_if_index]++;
    }

    /* map app_sw_if_index into application
    */
    if (app_sw_if_index != INDEX_INVALID)
    {
      vec_validate_init_empty(fam->app_by_app_sw_if_index, app_sw_if_index+1, INDEX_INVALID);
      fam->app_by_app_sw_if_index[app_sw_if_index] = ai;
    }
  }
  return 0;
}

u32 fwapp_app_detach (fwapp_application_t* app, fwapp_interface_cfg_t* cfgs)
{
  fwapp_interface_cfg_t*  cfg;
  fwapp_interface_t*      iface;

  /* No need to lock fwapp, as applications are added and are deleted by main thread only */

  vec_foreach(cfg, cfgs) {
    for (u32 i = vec_len(app->ifaces); i >= 0; --i) {  /*go in reverse order to optimize a bit - dynamic interfaces like tunnels are located at the end*/
      iface = &app->ifaces[i];
      if (iface->app_sw_if_index == cfg->app_sw_if_index &&
          iface->src_sw_if_index == cfg->src_sw_if_index)
      {
        fwapp_app_detach_one(app, i);
        vec_del1 (app->ifaces, i);
        break;
      }
    }
  }
  return 0;
}

void fwapp_app_detach_one (fwapp_application_t* app, u32 i)
{
  fwapp_main_t*     fam             = &fwapp_main;
  u32               src_sw_if_index = app->ifaces[i].src_sw_if_index;
  u32               app_sw_if_index = app->ifaces[i].app_sw_if_index;

  if (app_sw_if_index != INDEX_INVALID)
    fam->app_by_app_sw_if_index[app_sw_if_index] = INDEX_INVALID;
  if (src_sw_if_index != INDEX_INVALID) {
    fam->src_if_indexes[src_sw_if_index]--;
    if (fam->src_if_indexes[src_sw_if_index] == 0)
      vnet_feature_enable_disable("ip4-unicast", "fwapp-input-ip4", src_sw_if_index, 0, NULL, 0);
  }
}

fwapp_application_t* fwapp_get_app_by_name (u8* name)
{
  u32* p = (u32*)hash_get_mem (fwapp_main.app_by_name, name);
  if (p)
    return pool_elt_at_index(fwapp_main.apps, p[0]);
  return NULL;
}

static inline fwapp_application_t* fwapp_get_app_by_buffer(vlib_buffer_t* b0)
{
  fwapp_main_t* fam = &fwapp_main;

  u32 sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
  if (sw_if_index0 == INDEX_INVALID || sw_if_index0 > vec_len(fam->app_by_app_sw_if_index))
    return NULL;
  u32 ai = fam->app_by_app_sw_if_index[sw_if_index0];
  if (pool_is_free_index(fam->apps, ai))
    return NULL;
  return pool_elt_at_index(fam->apps, ai);
}

static inline u32 fwapp_app_send(vlib_main_t * vm, fwapp_application_t* app, vlib_buffer_t* b0)
{
  u32                next = INDEX_INVALID;
  fwapp_interface_t* iface;
  vlib_buffer_t*     c0;
  vlib_frame_t*      mirror_frame;
  u32*               to_mirror_next = 0;
  vnet_main_t*       vnm = vnet_get_main();

  // // nnoww - implement
  // if (app->type == FWAPP_APP_TYPE_MONITOR && app->iface.type == FWAPP_INTERFACE_DPDK)
  // {
  //   // nnoww - implement - copy buffer
  //   // b0 = clone buffer(b0);
  // }
  // // nnoww - implement - multiple interfaces
  // // nnoww - implement - take in account src_sw_if_index

  // nnoww - optimize - use mirror_frame for all buffers??? For all interfaces???
  vec_foreach (iface, app->ifaces) {
    if (app->type == FWAPP_APP_TYPE_DIVERT) {
      next = iface->pfn_send(iface, b0);
      return next;
    }

    /* if (app->type == FWAPP_APP_TYPE_MONITOR) {
    */
    mirror_frame   = vnet_get_frame_to_sw_interface (vnm, iface->app_sw_if_index);
    to_mirror_next = vlib_frame_vector_args (mirror_frame);
    to_mirror_next += mirror_frame->n_vectors;

    c0 = vlib_buffer_copy (vm, b0);
    if (PREDICT_FALSE(c0 == 0)) {
      clib_error ("failed to clone buffer");
      continue;
    }

    next = iface->pfn_send(iface, c0);
    to_mirror_next[0] = vlib_get_buffer_index (vm, c0);
    mirror_frame->n_vectors++;
    vnet_put_frame_to_sw_interface (vnm, iface->app_sw_if_index, mirror_frame);
    mirror_frame = 0;

    if (next == INDEX_INVALID)
      vnet_feature_next (&next, b0);
  }
  return next;
}

u32 static fwapp_tap_send(fwapp_interface_t* iface, vlib_buffer_t* b0)
{
  // nnoww - observation - it looks like we have no DROP counters for the TAP interface here !!!
  vnet_buffer(b0)->sw_if_index[VLIB_TX] = iface->app_sw_if_index;
  return FWAPP_NODE_NEXT_INTERFACE_OUTPUT;
}

u32 static fwapp_dpdk_send(fwapp_interface_t* iface, vlib_buffer_t* b0)
{
  // nnoww - implement - move packet to ip4-rewrite while enforcing in some way!!! But before this try the output and see what happens :)
  vnet_buffer(b0)->sw_if_index[VLIB_TX] = iface->app_sw_if_index;
  return FWAPP_NODE_NEXT_INTERFACE_OUTPUT;
}

static inline u32 fwapp_app_match_buffer(fwapp_application_t* app, vlib_buffer_t* b0, int is_ip6)
{
  fwapp_main_t* fam = &fwapp_main;
  int           match;
  u8            acl_action;     /*permit/deny*/     /*not used, but should be provided to ACL*/
  u32           trace_bitmap;   /*fragmented, etc*/ /*not used, but should be provided to ACL*/
  fa_5tuple_t   pkt_5tuple;

  if (PREDICT_FALSE(app->acl == INDEX_INVALID))
    return 1; /*no acl - match all*/

  acl_fill_5tuple (fam->acl_main, 0 /*sw_if_index0*/, b0, is_ip6,
                    1 /*is_input*/, 0 /*is_l2_path*/, &pkt_5tuple);
  match = single_acl_match_5tuple (fam->acl_main, app->acl, &pkt_5tuple, is_ip6,
                    &acl_action, NULL /*r_acl_match_p*/, NULL /*r_rule_match_p*/, &trace_bitmap);
  return match;
}

// nnoww - implement - make proper trace for fwapp!!!
typedef struct _fwapp_input_trace_t
{
  ip_lookup_next_t  next;     /* next node */
  index_t           adj;      /* resolved adjacency index */
  u32               match;    /* ACL match & Resolved by Policy */
  index_t           policy;   /* Policy index or UNDEFINED */
} fwapp_input_trace_t;

// nnoww - test - ntop tap interface per WAN/LAN to collect statistics per interface?

static inline uword
fwapp_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * from_frame, int is_ip6)
{
  u32 n_left_from, *from, *to_next, next_index;
  fwapp_main_t* fam = &fwapp_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index  = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          vlib_buffer_t*       b0;
          u32                  bi0;
       	  fwapp_node_next_t    next0;
          fwapp_application_t* curr_app, *next_app;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);

          // nnoww - implement - counters

          curr_app = fwapp_get_app_by_buffer(b0);
          next_app = (curr_app != NULL) ? curr_app->next : fam->graph_head.next;
          while (next_app->anchor != 1)
          {
            if (PREDICT_FALSE(fwapp_app_match_buffer (next_app, b0, is_ip6)))
            {
              next0 = fwapp_app_send (vm, next_app, b0);
              if (next0 == FWAPP_NODE_NEXT_ERROR_DROP && next_app->fallback == FWAPP_FALLBACK_DROP)
                break;
              if (next_app->type == FWAPP_APP_TYPE_DIVERT)
                break;
            }
            next_app = next_app->next;
          }
          if (next_app->anchor == 1) {  /* no more applications in graph, go to next default node */
	          vnet_feature_next (&next0, b0);
          }

          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              // nnoww - implement
              // fwapp_input_trace_t *tr;
              // tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
              // tr->next   = next0;
              // tr->adj    = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
              // tr->match  = match0;
              // tr->policy = fia0 ? fia0->fia_policy : -1;
            }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
        } /*while (n_left_from > 0 && n_left_to_next > 0)*/

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    } /*while (n_left_from > 0)*/

  // nnoww - implement - node counters - see   .n_errors = FWAPP_N_ERROR, .error_strings = fwapp_error_strings,
  //
  // vlib_node_increment_counter (vm, fwapp_ip4_node.index, FWAPP_ERROR_MATCHED, matches);
  return from_frame->n_vectors;
}

static uword
fwapp_input_ip4 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return fwapp_input_inline(vm, node, frame, 0 /*is_ip6*/);
}

static uword
fwapp_input_ip6 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return fwapp_input_inline(vm, node, frame, 1 /*is_ip6*/);
}

static u8 *
format_fwapp_input_trace (u8 * s, va_list * args)
{
// nnoww - implement - add proper trace here
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  // fwapp_input_trace_t *t = va_arg (*args, fwapp_input_trace_t *);
  // s = format (s, " next %d adj %d match %d policy %d",
  //               t->next, t->adj, t->match, t->policy);
  //return s;
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (fwapp_ip4_node) =
{
  .function = fwapp_input_ip4,
  .name = "fwapp-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_fwapp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  // nnoww - implement - node counters - see   .n_errors = FWAPP_N_ERROR, .error_strings = fwapp_error_strings,
  // .n_errors = FWAPP_N_ERROR,
  // .error_strings = fwapp_error_strings,
  .n_next_nodes = FWAPP_NODE_N_NEXT,
  .next_nodes = {
      [FWAPP_NODE_NEXT_DROP]              = "drop",
      [FWAPP_NODE_NEXT_ERROR_DROP]        = "error-drop",
      [FWAPP_NODE_NEXT_INTERFACE_OUTPUT]  = "interface-output",
  },
};

VNET_FEATURE_INIT (fwapp_ip4_feature, static) =
{
  .arc_name     = "ip4-unicast",
  .node_name    = "fwapp-input-ip4",
  .runs_after   = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
  .runs_before  = VNET_FEATURES ("fwabf-input-ip4", "ip4-lookup"),
};

VLIB_REGISTER_NODE (fwapp_ip6_node) =
{
  .function = fwapp_input_ip6,
  .name = "fwapp-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_fwapp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = FWAPP_NODE_N_NEXT,
  .next_nodes = {
      [FWAPP_NODE_NEXT_DROP]              = "drop",
      [FWAPP_NODE_NEXT_ERROR_DROP]        = "error-drop",
      [FWAPP_NODE_NEXT_INTERFACE_OUTPUT]  = "interface-output",
  },
};

VNET_FEATURE_INIT (fwapp_ip6_feature, static) =
{
  .arc_name     = "ip6-unicast",
  .node_name    = "fwapp-input-ip6",
  .runs_after   = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
  .runs_before  = VNET_FEATURES ("fwabf-input-ip6", "ip6-lookup"),
};
/* *INDENT-ON* */

static clib_error_t *
fwapp_init (vlib_main_t * vm)
{
  fwapp_main_t*   fam = &fwapp_main;
  clib_error_t*   acl_init_res;

  memset(fam, 0, sizeof(*fam));
  fam->graph_head.next = &fam->graph_tail;
  fam->graph_tail.prev = &fam->graph_head;
  fam->graph_head.name = (u8*)"start";
  fam->graph_tail.name = (u8*)"end";
  fam->graph_head.anchor = fam->graph_tail.anchor = 1;

  fam->app_by_name = hash_create_string (0, sizeof (uword));

  acl_init_res = acl_plugin_exports_init (&fam->acl_plugin);
  if (acl_init_res)
    return acl_init_res;
  fam->acl_main = fam->acl_plugin.p_acl_main;

  return (NULL);
}

// nnoww - implement - use ai with vppctl fwapp add

VLIB_INIT_FUNCTION (fwapp_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Flexiwan Application Dispatcher",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
