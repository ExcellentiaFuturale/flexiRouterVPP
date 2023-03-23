/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *  - acl_based_classification: Feature to provide traffic classification using
 *  ACL plugin. Matching ACLs provide the service class and importance
 *  attribute. The classification result is marked in the packet and can be
 *  made use of in other functions like scheduling, policing, marking etc.
 *
 *  - qos_mark_buffer_metadata_map : It adds a map that can used to update
 *  packet's QoS metadata values. The map uses the packet's QoS ID as the
 *  key and the result shall be the value to be marked. One use case
 *  for use of this support is, select QoS scheduler hierarchy based on the
 *  packet's QoS ID value.
 */

#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>
#include <vnet/qos/qos_egress_map.h>
#include <vnet/qos/qos_mark.h>

/**
 * per-interface vector of which MAP is used by which interface
 * for each output source
 */
index_t *qos_mark_configs[QOS_N_SOURCES];
#ifdef FLEXIWAN_FEATURE /* qos_mark_buffer_metadata_map */
/* Map to maintain key-value pairs (buffer-qos-metadata ID, configured value)*/
uword *qos_mark_buffer_metadata_map;
#endif /* FLEXIWAN_FEATURE - qos_mark_buffer_metadata_map */

void
qos_mark_ip_enable_disable (u32 sw_if_index, u8 enable)
{
  vnet_feature_enable_disable ("ip6-output", "ip6-qos-mark",
			       sw_if_index, enable, NULL, 0);
  vnet_feature_enable_disable ("ip4-output", "ip4-qos-mark",
			       sw_if_index, enable, NULL, 0);
}

void
qos_mark_vlan_enable_disable (u32 sw_if_index, u8 enable)
{
  /*
   * one cannot run a feature on a sub-interface, so we need
   * to enable a feature on all the L3 output paths
   */
  vnet_feature_enable_disable ("ip6-output", "vlan-ip6-qos-mark",
			       sw_if_index, enable, NULL, 0);
  vnet_feature_enable_disable ("ip4-output", "vlan-ip4-qos-mark",
			       sw_if_index, enable, NULL, 0);
  vnet_feature_enable_disable ("mpls-output", "vlan-mpls-qos-mark",
			       sw_if_index, enable, NULL, 0);
}

void
qos_mark_mpls_enable_disable (u32 sw_if_index, u8 enable)
{
  vnet_feature_enable_disable ("mpls-output", "mpls-qos-mark",
			       sw_if_index, enable, NULL, 0);
}

static void
qos_egress_map_feature_config (u32 sw_if_index, qos_source_t qs, u8 enable)
{
  switch (qs)
    {
    case QOS_SOURCE_EXT:
      ASSERT (0);
      break;
    case QOS_SOURCE_VLAN:
      qos_mark_vlan_enable_disable (sw_if_index, enable);
      break;
    case QOS_SOURCE_MPLS:
      qos_mark_mpls_enable_disable (sw_if_index, enable);
      break;
    case QOS_SOURCE_IP:
      qos_mark_ip_enable_disable (sw_if_index, enable);
      break;
    }
}

int
qos_mark_enable (u32 sw_if_index,
		 qos_source_t output_source, qos_egress_map_id_t mid)
{
  index_t qemi;

  vec_validate_init_empty (qos_mark_configs[output_source],
			   sw_if_index, INDEX_INVALID);

  qemi = qos_egress_map_find (mid);

  if (INDEX_INVALID == qemi)
    return VNET_API_ERROR_NO_SUCH_TABLE;

  if (INDEX_INVALID == qos_mark_configs[output_source][sw_if_index])
    {
      qos_egress_map_feature_config (sw_if_index, output_source, 1);
    }

  qos_mark_configs[output_source][sw_if_index] = qemi;

  return (0);
}

int
qos_mark_disable (u32 sw_if_index, qos_source_t output_source)
{
  if (vec_len (qos_mark_configs[output_source]) <= sw_if_index)
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;
  if (INDEX_INVALID == qos_mark_configs[output_source][sw_if_index])
    return VNET_API_ERROR_VALUE_EXIST;

  if (INDEX_INVALID != qos_mark_configs[output_source][sw_if_index])
    {
      qos_egress_map_feature_config (sw_if_index, output_source, 0);
    }

  qos_mark_configs[output_source][sw_if_index] = INDEX_INVALID;

  return (0);
}

void
qos_mark_walk (qos_mark_walk_cb_t fn, void *c)
{
  qos_source_t qs;

  FOR_EACH_QOS_SOURCE (qs)
  {
    u32 sw_if_index;

    vec_foreach_index (sw_if_index, qos_mark_configs[qs])
    {
      if (INDEX_INVALID != qos_mark_configs[qs][sw_if_index])
	fn (sw_if_index,
	    qos_egress_map_get_id (qos_mark_configs[qs][sw_if_index]), qs, c);
    }
  }
}

static clib_error_t *
qos_mark_cli (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  qos_egress_map_id_t map_id;
  u32 sw_if_index, qs;
  vnet_main_t *vnm;
  int rv, enable;

  vnm = vnet_get_main ();
  map_id = ~0;
  qs = 0xff;
  enable = 1;
#ifdef FLEXIWAN_FEATURE /* acl_based_classification */
  /* To prevent crash on invalid sw_if_index */
  sw_if_index = ~0;
#endif /* FLEXIWAN_FEATURE - acl_based_classification */

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "id %d", &map_id))
	;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "%U", unformat_qos_source, &qs))
	;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (0xff == qs)
    return clib_error_return (0, "output location must be specified");

  if (enable)
    rv = qos_mark_enable (sw_if_index, qs, map_id);
  else
    rv = qos_mark_disable (sw_if_index, qs);

  if (0 == rv)
    return (NULL);

  return clib_error_return (0, "Failed to map interface");
}

/*?
 * Apply a QoS egress mapping table to an interface for QoS marking packets
 * at the given output protocol.
 *
 * @cliexpar
 * @cliexcmd{qos egress interface GigEthernet0/9/0 id 0 output ip}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_egress_map_interface_command, static) = {
  .path = "qos mark",
  .short_help = "qos mark <SOURCE> <INTERFACE> id <MAP>",
  .function = qos_mark_cli,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static void
qos_mark_show_one_interface (vlib_main_t * vm, u32 sw_if_index)
{
  index_t qemis[QOS_N_SOURCES];
  qos_source_t qs;
  bool set;

  set = false;
  clib_memset_u32 (qemis, INDEX_INVALID, QOS_N_SOURCES);

  FOR_EACH_QOS_SOURCE (qs)
  {
    if (vec_len (qos_mark_configs[qs]) <= sw_if_index)
      continue;
    if (INDEX_INVALID != (qemis[qs] = qos_mark_configs[qs][sw_if_index]))
      set = true;
  }

  if (set)
    {
      vlib_cli_output (vm, " %U:", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);

      FOR_EACH_QOS_SOURCE (qs)
      {
	if (qemis[qs] != INDEX_INVALID)
	  vlib_cli_output (vm, "  %U: map:%d", format_qos_source, qs,
			   qemis[qs]);
      }
    }
}

static clib_error_t *
qos_mark_show (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  qos_source_t qs;
  u32 sw_if_index;

  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
    }

  if (~0 == sw_if_index)
    {
      u32 ii, n_ints = 0;

      FOR_EACH_QOS_SOURCE (qs)
      {
	n_ints = clib_max (n_ints, vec_len (qos_mark_configs[qs]));
      }

      for (ii = 0; ii < n_ints; ii++)
	{
	  qos_mark_show_one_interface (vm, ii);
	}
    }
  else
    qos_mark_show_one_interface (vm, sw_if_index);

  return (NULL);
}

/*?
 * Show Egress Qos Maps
 *
 * @cliexpar
 * @cliexcmd{show qos egress map}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_mark_show_command, static) = {
  .path = "show qos mark",
  .short_help = "show qos mark [interface]",
  .function = qos_mark_show,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */


#ifdef FLEXIWAN_FEATURE /* qos_mark_buffer_metadata_map */
static clib_error_t *
qos_mark_buffer_metadata_map_cli (vlib_main_t * vm, unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u32 delete = 0;
  u32 key;
  u32 value;
  u8 key_value_input = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (input, "key %u", &key))
        key_value_input |= 1;
      else if (unformat (input, "value %u", &value))
        key_value_input |= 2;
      else if (unformat (input, "del"))
	delete = 1;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "valid interface must be specified");
  if ((!delete) && (key_value_input != 3))
    return clib_error_return (0, "valid key and value must be specified");
  if (delete)
    {
      if (!key_value_input)
        return clib_error_return (0, "valid key must be specified");
      else if (key_value_input != 1)
        return clib_error_return (0, "delete should only specify the key");
    }

  if (delete)
    {
      if (vec_len (qos_mark_buffer_metadata_map) >= sw_if_index)
        {
          /* delete the entry using the key input */
          void * map = (void *) qos_mark_buffer_metadata_map[sw_if_index];
          hash_unset (map, key);
        }
    }
  else
    {
      vec_validate_init_empty (qos_mark_buffer_metadata_map, sw_if_index, 0);
      if (!qos_mark_buffer_metadata_map[sw_if_index])
        {
          /* create new map if not exist for the sw_if_index */
          qos_mark_buffer_metadata_map[sw_if_index] =
            (uword) hash_create (0, sizeof (uword));
        }
      /* add key value pair to the map */
      void * map = (void *) qos_mark_buffer_metadata_map[sw_if_index];
      hash_set (map, key, value);
    }

  return (NULL);
}

/*?
 * Configure packet buffer-metadata-map
 * The key is the value carried in the packet buffer's QoS metadata ID
 * The set value provides additional context that can be used by QoS scheduling
 * to identify a service-group, class or level in hierarchy
 *
 * @cliexpar
 * @cliexcmd{qos mark-buffer-metadata-map <intf> key <integer> value <integer>}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_mark_buffer_metadata_map_command, static) = {
  .path = "qos mark-buffer-metadata-map",
  .short_help =
    "qos mark-buffer-metadata-map <intf> key [integer] value [integer] del",
  .function = qos_mark_buffer_metadata_map_cli,
};

/* *INDENT-ON* */


static clib_error_t *
qos_mark_buffer_metadata_map_show_cli (vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "valid interface must be specified");

  if (vec_len (qos_mark_buffer_metadata_map) >= sw_if_index)
    {
      void *map = (void *) qos_mark_buffer_metadata_map[sw_if_index];
      if (map)
        {
          u32 key;
          u32 value;
          /* Iterate and print the configured map of key-value pairs */
          vlib_cli_output(vm, "Key         Value \n");
          /* *INDENT-OFF* */
          hash_foreach
            (key, value, map,
             ({vlib_cli_output(vm, "%08X    %08X\n", key, value);}));
          /* *INDENT-ON* */
        }
    }
  return (NULL);
}

/*?
 * Show the buffer-metadata-map configuration
 *
 * @cliexpar
 * @cliexcmd{show qos mark buffer-metadata-map <interface>}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_mark_buffer_metadata_map_show_command, static) = {
  .path = "show qos mark-buffer-metadata-map",
  .short_help = "show qos mark-buffer-metadata-map <interface>",
  .function = qos_mark_buffer_metadata_map_show_cli,
};

/* *INDENT-ON* */


static clib_error_t *
qos_mark_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  if ((!is_add) && (vec_len (qos_mark_buffer_metadata_map) >= sw_if_index))
    {
      /* Delete the buffer-metadata-map on interface delete */
      void * map = (void *) qos_mark_buffer_metadata_map[sw_if_index];
      hash_free (map);
      qos_mark_buffer_metadata_map[sw_if_index] = 0;
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (qos_mark_interface_add_del);

#endif /* FLEXIWAN_FEATURE - qos_mark_buffer_metadata_map */

/*
 * fd.io coding-style-patch-verification: ON
 *
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*
*/
