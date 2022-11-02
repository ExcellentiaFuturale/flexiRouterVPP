/*
 * flexiWAN SD-WAN software - flexiEdge, flexiManage.
 * For more information go to https://flexiwan.com
 *
 * Copyright (C) 2019  flexiWAN Ltd.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "fwapp_tap.h"

#include <vnet/dpo/dpo.h>
#include <vnet/interface_funcs.h>

/**
 * An extension of the 'vnet_sw_interface_t' interface:
 * binds tunnel or WAN interface into FIB.
 * The 'via' of tunnel is remote peer address, e.g. 10.100.0.4,
 * the 'via' of WAN interface is default GW, e.g. 192.168.1.1.
 *
 * The FWAPP uses path labels to route packets. User can assign labels to WAN
 * interfaces or to tunnel loopback interfaces. Than he can add FWAPP policy
 * rule with packet classification and labels. The FWAPP will check if packet
 * matches the policy classification. If there is match, it will choose
 * interface for packet forwarding by policy label.
 */
typedef struct fwapp_tap_t_
{
  // nnoww - check if needed
  /**
   * The DPO actually used for forwarding
   */
  dpo_id_t dpo;

  // nnoww - check if needed
  /**
   * ip4/ip6/whatever.
   * For now (March 2022) we don't enable mixed IPv4/6 tunnels and WAN-s.
   */
  dpo_proto_t dpo_proto;

  // nnoww - check if needed
  /*
   * The index of vnet_sw_interface_t interface served by this object.
   */
  u32 sw_if_index;

} fwapp_tap_t;


u32 fwapp_tap_create (tap_create_if_args_t* args, fwapp_interface_t* iface)
{
  fwapp_tap_t *t = (fwapp_tap_t*)iface->tap;
  // nnoww - implement
  return 1;
}

u32 fwapp_tap_destroy (fwapp_interface_t* iface)
{
  fwapp_tap_t *t = (fwapp_tap_t*)iface->tap;
  // nnoww - implement
  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
