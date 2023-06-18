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

// nnoww - document - copy from fwapp_main.c

/*
 *  Copyright (C) 2022 flexiWAN Ltd.
 *  This file is part of the FWAPP plugin.
 *  The FWAPP plugin is fork of the FDIO VPP ABF plugin.
 *  It enhances ABF with functionality required for Flexiwan Multi-Link feature.
 *  For more details see official documentation on the Flexiwan Multi-Link.
 */

#ifndef __FWAPP_TYPES_H__
#define __FWAPP_TYPES_H__

#define FWAPP_PLUGIN_VERSION_MAJOR 1
#define FWAPP_PLUGIN_VERSION_MINOR 0

#include <plugins/acl/exports.h>

// nnoww - document

/**
 * An Flexiwan ACL Based Forwarding 'policy'.
 * This comprises the ACL index to match against and the forwarding
 * path to take if the match is successful.
 *
 * In comparison to original ABF plugin where the FWAPP was forked of,
 * the FWAPP policy uses flexiwan path labels and other criteria to choose link
 * for packet forwarding. The link can be either WAN interface if Direct Internet
 * Access (DIA) is wanted by user for this packet, of VXLAN/GRE tunnel.
 * To use flexiwan path labels user has to label Tunnel and WAN interfaces.
 * The links might be grouped, so user can prioritize groups of links to choose
 * link from.
 * FWAPP policy consist of packet class against which packet should be matched,
 * and action to be performed on match. The packet class is implemented by ACL
 * rule and is referenced by ACL index. The action is specified in this module.
 *
 * ABF policies are then 'attached' to interfaces onto unicast-ip4/6 arcs.
 * When vlib buffer is received by FWAPP vlib graph node, it is matched against
 * ACL database. If match was found, the packet will be routed by policy.
 * If no match was found, the buffer will be routed according original
 * ip4-lookup/ip6-lookup logic.
 */

#define foreach_fwapp_interface_type  \
  _(UNDEFINED,      "undefined")      \
  _(DPDK,           "dpdk")           \
  _(TAP,            "tap")

typedef enum _fwapp_interface_type_t
{
#define _(t,descr) FWAPP_INTERFACE_##t,
  foreach_fwapp_interface_type
#undef _
} fwapp_interface_type_t;

struct _fwapp_interface_t;
typedef u32 (*fwapp_interface_send_fn_t)(struct _fwapp_interface_t*, vlib_buffer_t*);

typedef struct _fwapp_interface_t {
    fwapp_interface_type_t      type;
    u32                         app_sw_if_index;
    u32                         src_sw_if_index;
    fwapp_interface_send_fn_t   pfn_send;
// nnoww - implement - add interface counters
} fwapp_interface_t;

#define foreach_fwapp_app_type  \
  _(MONITOR,    "monitor")      \
  _(DIVERT,     "divert")

typedef enum _fwapp_app_type_t
{
#define _(t,descr) FWAPP_APP_TYPE_##t,
  foreach_fwapp_app_type
#undef _
} fwapp_app_type_t;


#define foreach_fwapp_fallback  \
  _(CONTINUE, "continue")       \
  _(DROP,     "drop")

typedef enum _fwapp_fallback_t
{
#define _(f,descr) FWAPP_FALLBACK_##f,
  foreach_fwapp_fallback
#undef _
} fwapp_fallback_t;


typedef struct _fwapp_application_t {
    // configurable stuff
    u8*                           name;
    u8*                           description;
    fwapp_app_type_t              type;
    fwapp_fallback_t              fallback;
    u32                           acl;
    fwapp_interface_t*            ifaces;

    // internal stuff
    u32 anchor;

    // app graph
    struct _fwapp_application_t*  next;
    struct _fwapp_application_t*  prev;

    /**
     * Counters.
     */
    u32 counter_rcvd;         // ACL lookup hit for rx packets
    u32 counter_sent;         // sent to application packets
    u32 counter_dropped;      // not sent to application due to link down
    u32 counter_lost;         // not sent to application due to no bandwidth at the application interface

} fwapp_application_t;

typedef struct _fwapp_interface_cfg_t {
    fwapp_interface_type_t type;
    u32                    app_sw_if_index;
    u32                    src_sw_if_index;
} fwapp_interface_cfg_t;

typedef struct _fwapp_application_cfg_t {
    u8*                           name;
    u8*                           next_name;
    u8*                           description;
    fwapp_app_type_t              type;
    fwapp_fallback_t              fallback;
    u32                           acl;
    fwapp_interface_cfg_t*        ifaces;
} fwapp_application_cfg_t;

u32 fwapp_add_app (fwapp_application_cfg_t* cfg);
u32 fwapp_del_app (fwapp_application_t* app);
u32 fwapp_app_attach (fwapp_application_t* app, fwapp_interface_cfg_t* cfgs);
u32 fwapp_app_detach (fwapp_application_t* app, fwapp_interface_cfg_t* cfgs);

fwapp_application_t* fwapp_get_app_by_name (u8* name);


typedef struct _fwapp_main_t
{
  fwapp_application_t*  apps;
  u32*                  app_by_app_sw_if_index; /*vector*/
  uword*                app_by_name;        /*hash*/
  u32*                  src_if_indexes;

  fwapp_application_t graph_head;
  fwapp_application_t graph_tail;

  acl_plugin_methods_t acl_plugin;
  acl_main_t*          acl_main;

} fwapp_main_t;

extern fwapp_main_t fwapp_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /*#ifndef __FWAPP_TYPES_H__*/
