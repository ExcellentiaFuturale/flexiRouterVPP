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

/*
 * This file implements database of FWAPP Links.
 * The FWAPP Link object is abstraction of interface, either FlexiWAN tunnel
 * interface or WAN interface in case of Direct Internet Access, that holds data
 * needed for the FlexiWAN multi-link policy feature, e.g. labels, DPO-s, etc.
 * Actually Link is a structure that extends the VPP software interface object.
 * It just keeps all FlexiWAN related logic separated of core VPP code.
 *
 * The main API function of this file is fwapp_links_get_intersected_dpo().
 * Once the FWAPP Link database is filled with interfaces, labels, etc,
 * this API can be used to retrieve DPO object by FWAPP label.
 * This DPO object then is used for forwarding packet to the labeled tunnel/WAN
 * interface.
 */

#ifndef __FWAPP_IFACE_TAP_H__
#define __FWAPP_IFACE_TAP_H__

#include "fwapp_types.h"

#include <vnet/devices/tap/tap.h>

/**
 * Creates FWAPP Link object that holds interface <-> label mapping and other
 * data needed for FWAPP Policy feature. See fwapp_link_t for details.
 *
 * @param sw_if_index   index of VPP software interface used by tunnel or by WAN interface.
 * @param fwlabel       FWAPP label for that tunnel/WAN interface.
 * @param rpath         the remote end of tunnel / gateway of WAN interface.
 *                      It is needed to track reachability of tunnel remote end/gateway.
 * @return 1 on success, 0 otherwise.
 */
extern u32 fwapp_tap_create (tap_create_if_args_t* args, fwapp_interface_t* iface);

extern u32 fwapp_tap_destroy (fwapp_interface_t* iface);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /*__FWAPP_IFACE_TAP_H__*/
