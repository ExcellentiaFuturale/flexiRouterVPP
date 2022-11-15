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
  vnet_sw_interface_t * sw;
  int rv = 0;

  if (pool_is_free_index (cmp->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  sw = vnet_get_sw_interface (cmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vec_validate_init_empty (cmp->acl_lc_index_by_sw_if_index, sw_if_index, ~0);

  vnet_feature_enable_disable ("ip4-unicast", "ip4-classifier-acls",
                               sw_if_index, enable_disable, 0, 0);

  vnet_feature_enable_disable ("ip6-unicast", "ip6-classifier-acls",
                               sw_if_index, enable_disable, 0, 0);

  return rv;
}

/* 
 * The function attaches the provided ACL vector to the given interface.
 * Internally uses the ACL plugin APIs
 */
static int
classifier_acls_set_interface_acl_list (classifier_acls_main_t * cmp,
					u32 sw_if_index, u32 * acl_vec)
{
  vec_validate_init_empty (cmp->acl_lc_index_by_sw_if_index, sw_if_index, ~0);
  if (vec_len (acl_vec) > 0)
    {
      u32 lc_index = (cmp->acl_lc_index_by_sw_if_index)[sw_if_index];
      if (~0 == lc_index)
	{
	  lc_index =
	    cmp->acl_plugin.get_lookup_context_index (cmp->acl_user_id,
						      sw_if_index, 1);
	  cmp->acl_lc_index_by_sw_if_index[sw_if_index] = lc_index;
	}
      cmp->acl_plugin.set_acl_vec_for_context (lc_index, acl_vec);
    }
  else
    {
      if (~0 != cmp->acl_lc_index_by_sw_if_index[sw_if_index])
	{
	  cmp->acl_plugin.put_lookup_context_index
	    (cmp->acl_lc_index_by_sw_if_index[sw_if_index]);
	  cmp->acl_lc_index_by_sw_if_index[sw_if_index] = ~0;
	}
    }
  return 0;
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
VLIB_CLI_COMMAND (classifier_acls_enable_disable_command, static) =
{
  .path = "classifier-acls set",
  .short_help =
  "classifier-acls set <interface-name> [del]",
  .function = classifier_acls_enable_disable_command_fn,
};
/* *INDENT-ON* */


/* API message handler */
static void vl_api_classifier_acls_enable_disable_t_handler
(vl_api_classifier_acls_enable_disable_t * mp)
{
  vl_api_classifier_acls_enable_disable_reply_t * rmp;
  classifier_acls_main_t * cmp = &classifier_acls_main;
  int rv;

  rv = classifier_acls_enable_disable (cmp, ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_CLASSIFIER_ACLS_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_classifier_acls_set_interface_acl_list_t_handler
  (vl_api_classifier_acls_set_interface_acl_list_t * mp)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  vl_api_classifier_acls_set_interface_acl_list_reply_t *rmp;
  vnet_interface_main_t *im = &cmp->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;
  int i;
  uword *seen_acl_bitmap = 0;

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      for (i = 0; i < mp->count; i++)
	{
	  u32 acl_index = clib_net_to_host_u32 (mp->acls[i]);
          /* Check if ACLs exist */
	  if (!cmp->acl_plugin.acl_exists (acl_index))
	    {
	      clib_warning ("ERROR: ACL %d not defined", acl_index);
	      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	      break;
	    }
	  /* Check if any ACL is being applied twice */
	  if (clib_bitmap_get (seen_acl_bitmap, acl_index))
	    {
	      clib_warning ("ERROR: ACL %d being applied twice", acl_index);
	      rv = VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	      break;
	    }
	  seen_acl_bitmap = clib_bitmap_set (seen_acl_bitmap, acl_index, 1);
	}
      if (0 == rv)
	{
	  u32 *acl_vec = 0;
	  for (i = 0; i < mp->count; i++)
	    vec_add1 (acl_vec, clib_net_to_host_u32 (mp->acls[i]));

	  rv = classifier_acls_set_interface_acl_list (cmp, sw_if_index,
						       acl_vec);
	  vec_free (acl_vec);
	}
    }

  clib_bitmap_free (seen_acl_bitmap);
  REPLY_MACRO (VL_API_CLASSIFIER_ACLS_SET_INTERFACE_ACL_LIST_REPLY);
}


static void
  vl_api_classifier_acls_set_acl_list_t_handler
  (vl_api_classifier_acls_set_acl_list_t * mp)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  vl_api_classifier_acls_set_acl_list_reply_t *rmp;
  int rv = 0;
  int i;
  uword *seen_acl_bitmap = 0;

  for (i = 0; i < mp->count; i++)
    {
      u32 acl_index = clib_net_to_host_u32 (mp->acls[i]);
      /* Check if ACLs exist */
      if (!cmp->acl_plugin.acl_exists (acl_index))
	{
	  clib_warning ("ERROR: ACL %d not defined", acl_index);
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  break;
	}
      /* Check if any ACL is being applied twice */
      if (clib_bitmap_get (seen_acl_bitmap, acl_index))
	{
	  clib_warning ("ERROR: ACL %d being applied twice", acl_index);
	  rv = VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	  break;
	}
      seen_acl_bitmap = clib_bitmap_set (seen_acl_bitmap, acl_index, 1);
    }
  if (0 == rv)
    {
      u32 *acl_vec = 0;
      for (i = 0; i < mp->count; i++)
	{
	  vec_add1 (acl_vec, clib_net_to_host_u32 (mp->acls[i]));
	}
      vec_free (cmp->acls);
      cmp->acls = acl_vec;
      vec_foreach_index (i, cmp->intfs_indexed_by_sw_if_index)
	{
	  if (cmp->intfs_indexed_by_sw_if_index[i])
	    {
	      rv = classifier_acls_set_interface_acl_list (cmp, i, acl_vec);
	      if (rv)
		{
		  clib_warning ("ERROR: Attaching ACL on sw_if_index %u", i);
		  break;
		}
	    }
	}
    }

  clib_bitmap_free (seen_acl_bitmap);
  REPLY_MACRO (VL_API_CLASSIFIER_ACLS_SET_ACL_LIST_REPLY);
}


static void
  vl_api_classifier_acls_set_interface_t_handler
  (vl_api_classifier_acls_set_interface_t * mp)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  vl_api_classifier_acls_set_interface_reply_t *rmp;
  vnet_interface_main_t *im = &cmp->vnet_main->interface_main;
  int rv = 0;
  u32 sw_if_index = ntohl(mp->sw_if_index);

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }
  if (0 == rv)
    {
      vec_validate_init_empty
	(cmp->intfs_indexed_by_sw_if_index, sw_if_index, 0);
      if (mp->is_add)
	{
	  rv = classifier_acls_set_interface_acl_list (cmp, sw_if_index,
						       cmp->acls);
	  cmp->intfs_indexed_by_sw_if_index[sw_if_index] = 1;
	}
      else
	{
	  rv = classifier_acls_set_interface_acl_list (cmp, sw_if_index, NULL);
	  cmp->intfs_indexed_by_sw_if_index[sw_if_index] = 0;
	}
    }

  REPLY_MACRO (VL_API_CLASSIFIER_ACLS_SET_INTERFACE_REPLY);
}

/* API definitions */
#include <classifier_acls/classifier_acls.api.c>

static clib_error_t * classifier_acls_init (vlib_main_t * vm)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  clib_error_t * error = 0;

  cmp->vlib_main = vm;
  cmp->vnet_main = vnet_get_main();
  cmp->acls = 0;
  cmp->intfs_indexed_by_sw_if_index = 0;

  /* Add our API messages to the global name_crc hash table */
  cmp->msg_id_base = setup_message_id_table ();

  clib_error_t *rv = acl_plugin_exports_init (&cmp->acl_plugin);
  if (rv)
    return (rv);
  cmp->acl_user_id =
    cmp->acl_plugin.register_user_module ("Classifier ACLs plugin",
					  "sw_if_index", "ip");

  return error;
}

static clib_error_t *
classifier_acls_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index,
				      u32 is_add)
{
  classifier_acls_main_t * cmp = &classifier_acls_main;
  if (0 == is_add)
    {
      /* Remove ACLs if any attached to the deleted interface */
      classifier_acls_set_interface_acl_list (cmp, sw_if_index, 0);
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
  .runs_after = VNET_FEATURES ("abf-input-ip4","fwabf-input-ip4"),
};

VNET_FEATURE_INIT (ip6_classifier_acls, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-classifier-acls",
  .runs_after = VNET_FEATURES ("abf-input-ip6","fwabf-input-ip6"),
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
