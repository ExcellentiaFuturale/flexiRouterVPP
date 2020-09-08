/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *   - enable enforcement of interface, where VXLAN tunnel should send unicast
 *     packets from. This is need for the FlexiWAN Multi-link feature.
 *   - Add destination port for vxlan tunnle, if remote device is behind NAT. Port is
 *     provisioned by fleximanage when creating the tunnel.
 */

#ifndef included_vnet_vxlan_h
#define included_vnet_vxlan_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan/vxlan_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#ifdef FLEXIWAN_FEATURE
#include <vnet/fib/fib_path_list.h>
#endif

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;	/* 20 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_header_t vxlan;	/* 8 bytes */
}) ip4_vxlan_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;	/* 40 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_header_t vxlan;	/* 8 bytes */
}) ip6_vxlan_header_t;
/* *INDENT-ON* */

/*
* Key fields: remote ip, vni on incoming VXLAN packet
* all fields in NET byte order
*/
typedef clib_bihash_kv_16_8_t vxlan4_tunnel_key_t;

/*
* Key fields: remote ip, vni and fib index on incoming VXLAN packet
* ip, vni fields in NET byte order
* fib index field in host byte order
*/
typedef clib_bihash_kv_24_8_t vxlan6_tunnel_key_t;

typedef union
{
  struct
  {
    u32 sw_if_index;		/* unicast - input interface / mcast - stats interface */
    union
    {
      struct			/* unicast action */
      {
	u16 next_index;
	u8 error;
      };
      ip4_address_t local_ip;	/* used as dst ip for mcast pkts to assign them to unicast tunnel */
    };
  };
  u64 as_u64;
} vxlan_decap_info_t;

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* FIB DPO for IP forwarding of VXLAN encap packet */
  dpo_id_t next_dpo;

  /* vxlan VNI in HOST byte order */
  u32 vni;

  /* tunnel src and dst addresses */
  ip46_address_t src;
  ip46_address_t dst;

  /* mcast packet output intfc index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u16 decap_next_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on VXLAN tunnel is unicast or mcast)
   * sending unicast VXLAN encap packets or receiving mcast VXLAN packets
   */
  fib_node_index_t fib_entry_index;
  adj_index_t mcast_adj_index;

#ifdef FLEXIWAN_FEATURE
  /*
   * Enforce specific tx interface for tunnel packets, if next hop for tunnel
   * was provided by user on tunnel creation. In this case no FIB LOOKUP is
   * needed. Just use the path of attached-next-hop type to get the adjacency
   * to be used for forwarding.
   */
  fib_node_index_t      fib_pl_index;
  fib_path_list_flags_t pl_flags;
  fib_route_path_t      rpath;
#endif
#ifdef FLEXIWAN_FEATURE
  u16 dest_port;
#endif

  /**
   * The tunnel is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

  u32 flow_index;		/* infra flow index */
  u32 dev_instance;		/* Real device instance in tunnel vector */
  u32 user_instance;		/* Instance name being shown to user */

    vnet_declare_rewrite (VLIB_BUFFER_PRE_DATA_SIZE);
} vxlan_tunnel_t;

#define foreach_vxlan_input_next        \
_(DROP, "error-drop")                   \
_(L2_INPUT, "l2-input")                 \
_(PUNT4, "ip4-punt")                    \
_(PUNT6, "ip6-punt")

typedef enum
{
#define _(s,n) VXLAN_INPUT_NEXT_##s,
  foreach_vxlan_input_next
#undef _
    VXLAN_INPUT_N_NEXT,
} vxlan_input_next_t;

typedef enum
{
#define vxlan_error(n,s) VXLAN_ERROR_##n,
#include <vnet/vxlan/vxlan_error.def>
#undef vxlan_error
  VXLAN_N_ERROR,
} vxlan_input_error_t;

typedef struct
{
  /* vector of encap tunnel instances */
  vxlan_tunnel_t *tunnels;

  /* lookup tunnel by key */
  clib_bihash_16_8_t vxlan4_tunnel_by_key;	/* keyed on ipv4.dst + fib + vni */
  clib_bihash_24_8_t vxlan6_tunnel_by_key;	/* keyed on ipv6.dst + fib + vni */

  /* local VTEP IPs ref count used by vxlan-bypass node to check if
     received VXLAN packet DIP matches any local VTEP address */
  uword *vtep4;			/* local ip4 VTEPs keyed on their ip4 addr */
  uword *vtep6;			/* local ip6 VTEPs keyed on their ip6 addr */

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /* graph node state */
  uword *bm_ip4_bypass_enabled_by_sw_if;
  uword *bm_ip6_bypass_enabled_by_sw_if;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Record used instances */
  uword *instance_used;
  u32 flow_id_start;
} vxlan_main_t;

extern vxlan_main_t vxlan_main;

extern vlib_node_registration_t vxlan4_input_node;
extern vlib_node_registration_t vxlan6_input_node;
extern vlib_node_registration_t vxlan4_encap_node;
extern vlib_node_registration_t vxlan6_encap_node;
extern vlib_node_registration_t vxlan4_flow_input_node;

u8 *format_vxlan_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;

  /* we normally use is_ip4, but since this adds to the
   * structure, this seems less of a breaking change */
  u8 is_ip6;
  u32 instance;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 vni;
#ifdef FLEXIWAN_FEATURE
  fib_route_path_t next_hop;
#endif
#ifdef FLEXIWAN_FEATURE
  /* adding dest port for vxlan tunnel in case destination behind NAT */
  u16 dest_port;
#endif
} vnet_vxlan_add_del_tunnel_args_t;

int vnet_vxlan_add_del_tunnel
  (vnet_vxlan_add_del_tunnel_args_t * a, u32 * sw_if_indexp);

void vnet_int_vxlan_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);

int vnet_vxlan_add_del_rx_flow (u32 hw_if_index, u32 t_imdex, int is_add);

u32 vnet_vxlan_get_tunnel_index (u32 sw_if_index);
#endif /* included_vnet_vxlan_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
