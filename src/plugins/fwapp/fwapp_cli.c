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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/interface.h>
#include <vnet/interface_funcs.h>
#include <vnet/devices/virtio/virtio.h>
#include <vppinfra/format.h>

#include "fwapp_types.h"

extern vnet_hw_interface_class_t tun_device_hw_interface_class;

uword
unformat_fwapp_interface (unformat_input_t * input, va_list * args)
{
  fwapp_interface_cfg_t*  cfg = va_arg (*args, fwapp_interface_cfg_t*);
  vnet_main_t*            vnm = vnet_get_main ();
  vnet_hw_interface_t*    hw;

  memset(cfg, 0, sizeof(*cfg));
  cfg->app_sw_if_index = INDEX_INVALID;
  cfg->src_sw_if_index = INDEX_INVALID;

  if (unformat (input, "app %d", &cfg->app_sw_if_index))
    ;
  if (unformat (input, "app %U", unformat_vnet_sw_interface, vnm, &cfg->app_sw_if_index))
    ;
  if (unformat (input, "src %d", &cfg->src_sw_if_index))
    ;
  if (unformat (input, "src %U", unformat_vnet_sw_interface, vnm, &cfg->src_sw_if_index))
    ;
  else {
    clib_error ("unknown input '%U'", format_unformat_error, input);
    return 0; /*0 means error here*/
  }

  // nnoww - check - if need cfg->type at all !!!

  /* Deduce type of interface */
  hw = vnet_get_sup_hw_interface (vnm, cfg->app_sw_if_index);
  if (!hw) {
    clib_error ("app_sw_if_index=%d not found", format_unformat_error, input, cfg->app_sw_if_index);
    return 0; /*0 means error here*/
  }
  if (hw->dev_class_index == virtio_device_class.index)
    cfg->type = (hw->hw_class_index == tun_device_hw_interface_class.index) ?
                FWAPP_INTERFACE_TUN : FWAPP_INTERFACE_TAP;
  else
  /*if (hw->dev_class_index == dpdk_device_class.index)*/ // I failed to make this working - too smart-ass code in dpdk plugin
    cfg->type = FWAPP_INTERFACE_DPDK;
  /*
  {
    clib_error ("app_sw_if_index=%d - not supported device class: %d",
      format_unformat_error, input, cfg->app_sw_if_index, hw->dev_class_index);
    return 0;
  }
  */
  return 1;
}

static clib_error_t *
fwapp_add_app_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t*           ret = NULL;
  u32                     res;
  fwapp_application_cfg_t cfg;
  fwapp_interface_cfg_t   if_cfg;

  memset(&cfg, 0, sizeof(cfg));
  cfg.type     = FWAPP_APP_TYPE_MONITOR;
  cfg.fallback = FWAPP_FALLBACK_CONTINUE;
  cfg.acl      = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &cfg.name))
        ;
      else if (unformat (input, "descr '%s'", &cfg.description))
	      ;
      else if (unformat (input, "monitor"))
	      cfg.type = FWAPP_APP_TYPE_MONITOR;
      else if (unformat (input, "divert"))
	      cfg.type = FWAPP_APP_TYPE_DIVERT;
      else if (unformat (input, "fallback drop"))
	      cfg.fallback = FWAPP_FALLBACK_DROP;
      else if (unformat (input, "next %s", &cfg.next_name))
	      ;
      else if (unformat (input, "acl %d", &cfg.acl))
	      ;
      else if (unformat (input, "interface %U", unformat_fwapp_interface, &if_cfg))
        vec_add1(cfg.ifaces, if_cfg);
      else {
        ret = (clib_error_return (0, "unknown input '%U'", format_unformat_error, input));
        goto done;
      }
    }

  res = fwapp_add_app (&cfg);
  if (res != 0)
  {
      ret = clib_error_return (0, "failed to add app %s: %u", cfg.name, res);
      goto done;
  }

done:
  if (cfg.name)
    vec_free(cfg.name);
  if (cfg.next_name)
    vec_free(cfg.next_name);
  if (cfg.description)
    vec_free(cfg.description);
  if (cfg.ifaces)
    vec_free(cfg.ifaces);
  return ret;
}

static clib_error_t *
fwapp_del_app_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t*   ret = NULL;
  u32             res;
  u8*             app_name = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &app_name))
        ;
      else {
        ret = (clib_error_return (0, "app name was not provided"));
        goto done;
      }
    }

  res = fwapp_del_app(app_name);
  if (res)
  {
      ret = (clib_error_return (0, "failed to delete app %s: %u", app_name, res));
      goto done;
  }

done:
  if (app_name)
    vec_free(app_name);
  return ret;
}

/* *INDENT-OFF* */
/**
 * Attach an ABF policy to an interface.
 */
VLIB_CLI_COMMAND (fwapp_add_app_command, static) = {
  .path       = "fwapp add app",
  .function   = fwapp_add_app_cmd,
  .short_help = "fwapp add app name <name> [descr '<value>'] <monitor|divert> [fallback <drop>] "
                "[next <name>] [acl <index>] [interface app <vpp_if_name>|<sw_if_index> [src <vpp_if_name>|<sw_if_index>]] "
                "[interface ...] "
};
VLIB_CLI_COMMAND (fwapp_del_app_command, static) = {
  .path       = "fwapp del app",
  .function   = fwapp_del_app_cmd,
  .short_help = "fwapp del app name <name>"
};
/* *INDENT-ON* */

// nnoww - test - fwapp app add with one or multiple interfaces with and without src_sw_if_index
// nnoww - test - fwapp app attach with one or multiple interfaces with and without app_sw_if_index / src_sw_if_index

static clib_error_t *
fwapp_attach_detach_app_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd, u32 is_attach)
{
  clib_error_t*           ret = NULL;
  u32                     res;
  u8*                     app_name = 0;
  fwapp_application_t*    app;
  fwapp_interface_t*      iface;
  fwapp_interface_cfg_t*  ifaces, *p_cfg;
  fwapp_interface_cfg_t   if_cfg;
  u32                     default_app_sw_if_index = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%s", &app_name))
        vec_add1(ifaces, if_cfg);
      else if (unformat (input, "%U", unformat_fwapp_interface, &if_cfg))
        vec_add1(ifaces, if_cfg);
      else {
        ret = (clib_error_return (0, "unknown input '%U'", format_unformat_error, input));
        goto done;
      }
    }

  app = fwapp_get_app_by_name (app_name);
  if (!app)
  {
      ret = (clib_error_return (0, "app %s was not found", app_name));
      goto done;
  }

  /* If app sw_if_index was not provided, use the first from the current
     application interfaces.
  */
  vec_foreach (p_cfg, ifaces) {
    if (p_cfg->app_sw_if_index != INDEX_INVALID)
      continue;
    if (default_app_sw_if_index == INDEX_INVALID) {
      vec_foreach (iface, app->ifaces)
        if (iface->app_sw_if_index != INDEX_INVALID) {
          default_app_sw_if_index = iface->app_sw_if_index;
          break;
        }
      if (default_app_sw_if_index == INDEX_INVALID) {
        ret = (clib_error_return (0, "no app sw_if_index was found"));
        goto done;
      }
    }
    p_cfg->app_sw_if_index = default_app_sw_if_index;
  }

  if (is_attach)
    res = fwapp_app_attach (app, ifaces);
  else
    res = fwapp_app_detach (app, ifaces);
  if (res)
  {
      ret = clib_error_return (0, "failed to %s app %s: %u",
                               (is_attach?"attach":"detach"), app_name, res);
      goto done;
  }

done:
  if (app_name)
    vec_free(app_name);
  if (ifaces)
    vec_free(ifaces);
  return ret;
}

static clib_error_t *
fwapp_attach_app_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return fwapp_attach_detach_app_cmd (vm, input, cmd, 1 /*is_attach*/);
}
static clib_error_t *
fwapp_detach_app_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return fwapp_attach_detach_app_cmd (vm, input, cmd, 0 /*is_attach*/);
}

/* *INDENT-OFF* */
/**
 * Attach an application to one or few interfaces.
 */
VLIB_CLI_COMMAND (fwapp_attach_app_command, static) = {
  .path = "fwapp attach app",
  .function = fwapp_attach_app_cmd,
  .short_help = "fwapp attach app <name> [app <vpp_if_name>|<sw_if_index>] src <vpp_if_name>|<sw_if_index> "
                "[[app <vpp_if_name>|<sw_if_index>] src <vpp_if_name>|<sw_if_index>  ...] "
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
/**
 * Detach an application from one or few interfaces.
 */
VLIB_CLI_COMMAND (fwapp_detach_app_command, static) = {
  .path = "fwapp detach app",
  .function = fwapp_detach_app_cmd,
  .short_help = "fwapp detach app <name> [app <vpp_if_name>|<sw_if_index>] src <vpp_if_name>|<sw_if_index> "
                "[[app <vpp_if_name>|<sw_if_index>] src <vpp_if_name>|<sw_if_index>  ...] "
};
/* *INDENT-ON* */


static char *app_type_strings[] = {
#define _(t,s) s,
  foreach_fwapp_app_type
#undef _
};

static char *app_fallback_strings[] = {
#define _(t,s) s,
  foreach_fwapp_fallback
#undef _
};

static char *app_interface_type_strings[] = {
#define _(t,s) s,
  foreach_fwapp_interface_type
#undef _
};

u8 *format_fwapp_interface (u8 * s, va_list * args)
{
  fwapp_interface_t*    iface   = va_arg (*args, fwapp_interface_t*);
  u32                   indent  = va_arg (*args, u32);
  vnet_main_t*          vnm     = vnet_get_main ();
  vnet_sw_interface_t*  sw;

  s = format (s, "\n%U type:%s, app_sw_if_index:%d, src_sw_if_index:%d",
        format_white_space, indent, app_interface_type_strings[iface->type],
        iface->app_sw_if_index, iface->src_sw_if_index);

  sw = vnet_get_sw_interface (vnm, iface->app_sw_if_index);
  s = format (s, "\n%U [%d] %U", format_white_space, indent, iface->app_sw_if_index,
        format_vnet_sw_interface, vnm, sw);
  sw = vnet_get_sw_interface (vnm, iface->src_sw_if_index);
  s = format (s, "\n%U [%d] %U", format_white_space, indent, iface->src_sw_if_index,
        format_vnet_sw_interface, vnm, sw);
  return s;
}

u8 *format_fwapp_app (u8 * s, va_list * args)
{
  fwapp_application_t*  app     = va_arg (*args, fwapp_application_t*);
  fwapp_interface_t*    iface;
  u32                   verbose = va_arg (*args, u32);
  u32                   indent  = format_get_indent (s) + 1;

  if (app->anchor)
    return s;   /*hide head and tail anchor elements*/

	s = format (s, "%s", app->name);
  if (!verbose)
    return s;

  // nnoww - implement - add counters

  if (app->description)
    s = format (s, "\n%U %s", format_white_space, indent, app->description);
  s = format (s, "\n%U type:%s, fallback:%s, acl:%d", format_white_space, indent,
        app_type_strings[app->type], app_fallback_strings[app->fallback], app->acl);
  s = format (s, "\n%U interfaces:%d", format_white_space, indent, vec_len(app->ifaces));
  vec_foreach (iface, app->ifaces)
    s = format (s, "%U %U", format_white_space, indent, format_fwapp_interface, iface, indent+2);
  return s;
}

static clib_error_t *
fwapp_show_graph_cmd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32                   verbose = 0;
  fwapp_main_t*         fam     = &fwapp_main;
  fwapp_application_t*  app     = fam->graph_head.next;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	      verbose = 1;
      else
	      return (clib_error_return (0, "unknown input '%U'", format_unformat_error, input));
    }

  while (app->anchor == 0)
  {
    vlib_cli_output(vm, "%U", format_fwapp_app, app, verbose);
    app = app->next;
  }
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (fwapp_show_graph_command, static) = {
  .path = "show fwapp graph",
  .function = fwapp_show_graph_cmd,
  .short_help = "show fwapp graph [verbose]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
