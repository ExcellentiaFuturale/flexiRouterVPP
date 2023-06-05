/*
 * Copyright (c) 2022 FlexiWAN
 *
 * List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *  - acl_based_classification: Feature to provide traffic classification using
 *  ACL plugin. Matching ACLs provide the service class and importance
 *  attribute. The classification result is marked in the packet and can be
 *  made use of in other functions like scheduling, policing, marking etc.
 *
 * This file is added by the Flexiwan feature: acl_based_classification.
 */

/*
 * The plugin provides support to create a set of acl-lists that can be
 * identified by an unique integer index. The acl-list can then be attached to
 * an interface by passing the acl-list ID. This method limits the acl plugin
 * lookup context to a small configured count. This reduces the memory usage as
 * multiple interface attachments can reuse the same acl-list (i.e acl plugin
 * context)
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <classifier_acls/classifier_acls.h>
#include <classifier_acls/inlines.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <classifier_acls/classifier_acls.api_enum.h>
#include <classifier_acls/classifier_acls.api_types.h>

#define REPLY_MSG_ID_BASE cmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

classifier_acls_main_t classifier_acls_main;


/* enable_disable function shared between message handler and debug CLI */
static int
classifier_acls_enable_disable (classifier_acls_main_t * cmp, u32 sw_if_index,
				int enable_disable)
{
  int rv = 0;

  if (pool_is_free_index (cmp->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vec_validate_init_empty (cmp->acl_list_id_by_sw_if_index, sw_if_index, ~0);

  vnet_feature_enable_disable ("ip4-unicast", "ip4-classifier-acls",
                               sw_if_index, enable_disable, 0, 0);

  vnet_feature_enable_disable ("ip6-unicast", "ip6-classifier-acls",
                               sw_if_index, enable_disable, 0, 0);

  return rv;
}


static clib_error_t *
classifier_acls_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
                         cmp->vnet_main, &sw_if_index))
        ;
      else
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify a valid interface");

  rv = classifier_acls_enable_disable (cmp, sw_if_index, enable_disable);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface -  Unsupported interface type");
    break;

  default:
    return clib_error_return (0, "classifier_acls_enable_disable returned %d",
                              rv);
    }
  return 0;
}

/* *INDENT-OFF* */
/*
 * Command to enable or disable classification on the interface. The
 * configuration on the interface stays as is and this command only enables or
 * disables the feature from the interface. It can also help in quick debugging
 * of the packet path with and without this feature
 */
VLIB_CLI_COMMAND (classifier_acls_enable_disable_command, static) =
{
  .path = "classifier-acls enable",
  .short_help = "classifier-acls enable <interface-name> [del]",
  .function = classifier_acls_enable_disable_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
classifier_acls_set_interface_command_fn (vlib_main_t * vm,
                                          unformat_input_t * input,
                                          vlib_cli_command_t * cmd)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  u32 sw_if_index = ~0;
  u8 is_add = 1;
  u32 acl_list_id = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
                         cmp->vnet_main, &sw_if_index))
        ;
      else if (unformat (input, "acl-list-id %u", &acl_list_id))
        ;
      else if (unformat (input, "del"))
        is_add = 0;
      else
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify a valid interface");

  if (acl_list_id >= CLASSIFIER_MAX_ACL_SETS)
    return clib_error_return (0, "Max supported acl_list_id range is 0 to %u",
                              (CLASSIFIER_MAX_ACL_SETS - 1));

  vec_validate_init_empty (cmp->acl_list_id_by_sw_if_index, sw_if_index, ~0);
  if (is_add)
    cmp->acl_list_id_by_sw_if_index[sw_if_index] = acl_list_id;
  else
    cmp->acl_list_id_by_sw_if_index[sw_if_index] = ~0;

  return NULL;
}

/* *INDENT-OFF* */
/*
 * Command to set classification rules identified by the given acl-list-id on
 * the given interface
 */
VLIB_CLI_COMMAND (classifier_acls_set_interface_command, static) =
{
  .path = "classifier-acls set-interface",
  .short_help = "classifier-acls set-interface <interface-name> acl-list-id <acl-list-id> [del]",
  .function = classifier_acls_set_interface_command_fn,
};
/* *INDENT-ON* */


/*
 * Function that sets up ACL plugin context for the ACLs identified using the
 * given unique acl_list_id
 */
static i32
classifier_acls_setup_lc_index (classifier_acls_main_t * cmp, u32 acl_list_id,
                                u32 * acls)
{
  i32 rv = 0;
  if (cmp->acl_lc_index_by_acl_list_id[acl_list_id] == ~0)
    {
      rv = cmp->acl_plugin.get_lookup_context_index (cmp->acl_user_id,
                                                     acl_list_id, 0);
      if (rv < 0)
        clib_warning("Classifier acl lookup setup failed: %d", rv);
      else
        cmp->acl_lc_index_by_acl_list_id[acl_list_id] = rv;
    }
  if (rv >= 0)
    {
      rv = cmp->acl_plugin.set_acl_vec_for_context
        (cmp->acl_lc_index_by_acl_list_id[acl_list_id], acls);
      if (rv < 0)
        clib_warning("Classifier acl list setup failed: %d", rv);
    }
  return rv;
}

/*
 * Function that releases the ACL plugin context corresponding to the
 * acl_list_id
 */
static void
classifier_acls_release_lc_index (classifier_acls_main_t * cmp,
                                  u32 acl_list_id)
{
  u32 lc_index = cmp->acl_lc_index_by_acl_list_id[acl_list_id];
  if (lc_index != ~0)
    {
      cmp->acl_plugin.put_lookup_context_index (lc_index);
      cmp->acl_lc_index_by_acl_list_id[acl_list_id] = ~0;
    }
}


static clib_error_t *
classifier_acls_show_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;

  vlib_cli_output (vm, "sw_if_index   acl_list_id\n");
  for (int i = 0; i < vec_len (cmp->acl_list_id_by_sw_if_index); i++)
    {
      if (cmp->acl_list_id_by_sw_if_index[i] != ~0)
        vlib_cli_output (vm, "     %u               %u\n", i,
                         cmp->acl_list_id_by_sw_if_index[i]);
    }
  return NULL;
}

/* *INDENT-OFF* */
/*
 * Command to show the config of the classification feature.
 */
VLIB_CLI_COMMAND (classifier_acls_show_command, static) =
{
  .path = "show classifier-acls",
  .short_help = "show classifier-acls",
  .function = classifier_acls_show_command_fn,
};
/* *INDENT-ON* */


/* API message handler */
static void vl_api_classifier_acls_enable_disable_t_handler
(vl_api_classifier_acls_enable_disable_t * mp)
{
  vl_api_classifier_acls_enable_disable_reply_t * rmp;
  classifier_acls_main_t * cmp = &classifier_acls_main;
  int rv;

  rv = classifier_acls_enable_disable (cmp,
                                       clib_net_to_host_u32(mp->sw_if_index),
                                       (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_CLASSIFIER_ACLS_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_classifier_acls_set_interface_t_handler
  (vl_api_classifier_acls_set_interface_t * mp)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  vl_api_classifier_acls_set_interface_reply_t *rmp;
  vnet_interface_main_t *im = &cmp->vnet_main->interface_main;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u32 acl_list_id = clib_net_to_host_u32 (mp->acl_list_id);
  int rv = 0;

  if (acl_list_id >= CLASSIFIER_MAX_ACL_SETS)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto end_return;
    }

  if (!pool_is_free_index (im->sw_interfaces, sw_if_index))
    {
      vec_validate_init_empty (cmp->acl_list_id_by_sw_if_index,
                               sw_if_index, ~0);
      cmp->acl_list_id_by_sw_if_index[sw_if_index] = acl_list_id;
    }
  else
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;

end_return:
  REPLY_MACRO (VL_API_CLASSIFIER_ACLS_SET_INTERFACE_REPLY);
}


static void
  vl_api_classifier_acls_set_acls_t_handler
  (vl_api_classifier_acls_set_acls_t * mp)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  vl_api_classifier_acls_set_acls_reply_t *rmp;
  u32 acl_count = clib_net_to_host_u32 (mp->count);
  u32 acl_list_id = clib_net_to_host_u32 (mp->acl_list_id);
  int rv = 0;

  if (acl_list_id >= CLASSIFIER_MAX_ACL_SETS)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto end_return;
    }

  if (acl_count)
    {
      uword *seen_acl_bitmap = 0;
      u32 * acls = NULL;
      u32 acl_index;
      for (u32 i = 0; i < acl_count; i++)
        {
          acl_index = clib_net_to_host_u32 (mp->acls[i]);
          /* Check if ACLs exist */
          if (!cmp->acl_plugin.acl_exists (acl_index))
            {
              rv = VNET_API_ERROR_NO_SUCH_ENTRY;
              break;
            }
          /* Check if any ACL is being applied twice */
          if (clib_bitmap_get (seen_acl_bitmap, acl_index))
            {
              rv = VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
              break;
            }
          seen_acl_bitmap = clib_bitmap_set (seen_acl_bitmap, acl_index, 1);
          vec_add1 (acls, acl_index);
        }
      if (!rv)
        rv = classifier_acls_setup_lc_index (cmp, acl_list_id, acls);
      clib_bitmap_free (seen_acl_bitmap);
      vec_free (acls);
    }
  else
    classifier_acls_release_lc_index (cmp, acl_list_id);

end_return:
  REPLY_MACRO (VL_API_CLASSIFIER_ACLS_SET_ACLS_REPLY);
}

/* API definitions */
#include <classifier_acls/classifier_acls.api.c>

static clib_error_t * classifier_acls_init (vlib_main_t * vm)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  clib_error_t * error = 0;

  cmp->vlib_main = vm;
  cmp->vnet_main = vnet_get_main();
  cmp->acl_list_id_by_sw_if_index = 0;
  for (int i = 0; i < CLASSIFIER_MAX_ACL_SETS; i++)
    cmp->acl_lc_index_by_acl_list_id[i] = ~0;

  /* Add our API messages to the global name_crc hash table */
  cmp->msg_id_base = setup_message_id_table ();

  clib_error_t *rv = acl_plugin_exports_init (&cmp->acl_plugin);
  if (rv)
    return (rv);
  cmp->acl_user_id = cmp->acl_plugin.register_user_module
    ("Classifier ACLs plugin", "acl_list_id", NULL);

  return error;
}

static clib_error_t *
classifier_acls_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index,
				      u32 is_add)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  if (0 == is_add)
    {
      if (vec_len (cmp->acl_list_id_by_sw_if_index) > sw_if_index)
        /* Reset acl_list_id of the interface */
        cmp->acl_list_id_by_sw_if_index[sw_if_index] = ~0;
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (classifier_acls_sw_interface_add_del);

VLIB_INIT_FUNCTION (classifier_acls_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_classifier_acls, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-classifier-acls",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
  .runs_before = VNET_FEATURES ("abf-input-ip4","fwabf-input-ip4"),
};

VNET_FEATURE_INIT (ip6_classifier_acls, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-classifier-acls",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
  .runs_before = VNET_FEATURES ("abf-input-ip6","fwabf-input-ip6"),
};


VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "classifier_acls plugin - ACL based traffic classifier",
};
/* *INDENT-ON* */


__clib_export u32
classifier_acls_classify_packet_api (vlib_buffer_t *b, u32 sw_if_index,
				     u8 is_ip6, u32 *out_acl_index,
                                     u32 *out_acl_rule_index)
{
  return classifier_acls_classify_packet (b, sw_if_index, is_ip6,
                                          out_acl_index, out_acl_rule_index);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
