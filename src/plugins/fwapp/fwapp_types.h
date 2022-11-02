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

#ifndef __FWAPP_TYPES_H__
#define __FWAPP_TYPES_H__

#define FWAPP_PLUGIN_VERSION_MAJOR 1
#define FWAPP_PLUGIN_VERSION_MINOR 0


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

#define FWAPP_MAX_NUM_APPLICATIONS  0xF

typedef enum fwapp_interface_type_t_ {
    FWAPP_INTERFACE_UNDEFINED,
    FWAPP_INTERFACE_TAP
} fwapp_interface_type_t;

typedef struct fwapp_interface_t_ {
    fwapp_interface_type_t type;
    union {
        fwapp_tap_t tap;
    }
} fwapp_interface_t;

#define fwapp_interface_create(_iface, _args, _res) {   \
  switch(_args->type)                                   \
  {                                                     \
    case FWAPP_INTERFACE_TAP:                           \
      res = fwapp_tap_create(_args, _iface);            \
      break;                                            \
    default:                                            \
      res = VNET_API_ERROR_INVALID_ARGUMENT;            \
  }                                                     \
}

#define fwapp_interface_destroy(_iface) {   \
  if (_iface->type == FWAPP_INTERFACE_TAP)  \
      fwapp_tap_destroy( _iface);           \
}


typedef struct fwapp_interface_arg_t_ {
    fwapp_interface_type_t type;
} fwapp_interface_arg_t;



  if (res) {
    curr->allocated = 0;
    clib_error ("failed to create interface %d: res=%d", iface_args->type, res);
    return res;
  }



inline u32 vft_get_sw_if_index (fwapp_interface_t* iface)
{
// nnoww - implement
    return 0;
}

inline u32 vft_get_dpo (fwapp_interface_t* iface, dpo_id_t* dpo)
{
// nnoww - implement
    return 0;
}


typedef enum fwapp_app_type_t_ {
    FWAPP_APP_TYPE_MONITOR,
    FWAPP_APP_TYPE_DIVERT
} fwapp_app_type_t;

// what to do if link to application (either local or remote) is not available
typedef enum fwapp_fallback_t_ {
    FWAPP_FALLBACK_CONTINUE,
    FWAPP_FALLBACK_DROP
} fwapp_fallback_t;

typedef struct fwapp_application_t_ {
    // configurable stuff
    u8*                           name;
    u8*                           description;
    fwapp_app_type_t              type;
    fwapp_fallback_t              fallback;
    u32                           acl;
    fwapp_interface_t             iface;

    // internal stuff

    u32 allocated;

    // app graph
    struct fwapp_application_t_*  next;
    struct fwapp_application_t_*  prev;

    /**
     * Counters.
     */
    u32 counter_rcvd;         // ACL lookup hit for rx packets
    u32 counter_sent;         // sent to application packets
    u32 counter_dropped;      // not sent to application due to link down
    u32 counter_lost;         // not sent to application due to no bandwidth at the application interface

} fwapp_application_t;


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
