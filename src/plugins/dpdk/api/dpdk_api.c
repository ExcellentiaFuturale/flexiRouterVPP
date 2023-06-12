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
 * List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *  - integrating_dpdk_qos_sched : The DPDK QoS scheduler integration in VPP is
 *    currently in deprecated state. It is likely deprecated as changes
 *    in DPDK scheduler APIs required corresponding changes from VPP side.
 *    The FlexiWAN commit makes the required corresponding changes and brings
 *    back the feature to working state. Additionaly made enhancements in the
 *    context of WAN QoS needs.
 *
 * This deprecated file is enhanced and added as part of the
 * flexiwan feature - integrating_dpdk_qos_sched
 * Location of deprecated file: extras/deprecated/dpdk-hqos/api/dpdk_api.c
 *
 */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>
#include <vlib/pci/pci.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>

#include <dpdk/device/dpdk_priv.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <dpdk/api/dpdk.api_enum.h>
#include <dpdk/api/dpdk.api_types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

#define REPLY_MSG_ID_BASE dm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_sw_interface_set_dpdk_hqos_pipe_profile_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_pipe_profile_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_pipe_profile_reply_t *rmp;
  dpdk_main_t *dm = &dpdk_main;
  int rv = 0;
  int i;
  clib_error_t *error = NULL;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  struct rte_sched_pipe_params p;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport_id = ntohl (mp->subport_id);
  u32 profile = ntohl (mp->profile);
  u32 tb_rate = ntohl (mp->tb_rate);
  u32 tb_size = ntohl (mp->tb_size);
  u32 tc_period = ntohl (mp->tc_period);
  u32 tc_rate[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
  u32 wrr_weights[RTE_SCHED_BE_QUEUES_PER_PIPE];

  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      tc_rate[i] = ntohl(mp->tc_rate[i]);
    }
  for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++)
    {
      wrr_weights[i] = ntohl (mp->wrr[i]);
    }

  VALIDATE_SW_IF_INDEX (mp);

  error = dpdk_hqos_get_intf_context (sw_if_index, &xd, &devconf);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      clib_warning ("hqos not enabled on interface");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  error = dpdk_hqos_get_pipe_profile (&devconf->hqos, subport_id, profile, &p);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if (tb_rate != 0)
    {
      p.tb_rate = tb_rate;
      for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
	{
	  p.tc_rate[i] = tb_rate;
	}
      p.tb_size = MAX((HQOS_DEFAULT_SCHED_TB_SIZE_MS * (p.tb_rate / 1000)),
		      HQOS_MIN_SCHED_TB_SIZE_BYTES);
    }

  if (tb_size != 0)
    {
      p.tb_size = tb_size;
    }
  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      if (tc_rate[i] != 0)
	{
	  p.tc_rate[i] = tc_rate[i];
	}
    }
  if (tc_period != 0)
    {
      p.tc_period = tc_period;
    }
  for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++)
    {
      if (wrr_weights[i] != 0)
	{
	  p.wrr_weights[i] = wrr_weights[i];
	}
    }

  // Apply changes to profile
  error = dpdk_hqos_setup_pipe_profile (xd, &devconf->hqos, subport_id,
					profile, &p);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  BAD_SW_IF_INDEX_LABEL;

done:
  if (error)
    clib_error_free(error);
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_PIPE_PROFILE_REPLY);
}

static void
  vl_api_sw_interface_set_dpdk_hqos_pipe_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_pipe_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_pipe_reply_t *rmp;
  dpdk_main_t *dm = &dpdk_main;
  int rv = 0;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  clib_error_t *error = NULL;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport_id = ntohl (mp->subport_id);
  u32 pipe_id = ntohl (mp->pipe_id);
  u32 profile = ntohl (mp->profile);

  VALIDATE_SW_IF_INDEX (mp);

  error = dpdk_hqos_get_intf_context (sw_if_index, &xd, &devconf);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      clib_warning ("hqos not enabled on interface");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  error = dpdk_hqos_setup_pipe (xd, &devconf->hqos, subport_id, pipe_id,
				profile);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  BAD_SW_IF_INDEX_LABEL;

done:
  if (error)
    clib_error_free(error);
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_PIPE_REPLY);
}

static void
  vl_api_sw_interface_set_dpdk_hqos_subport_profile_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_subport_profile_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_subport_profile_reply_t *rmp;
  dpdk_main_t *dm = &dpdk_main;
  int rv = 0;
  int i;
  clib_error_t *error = NULL;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  struct rte_sched_subport_profile_params p;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 profile = ntohl (mp->profile);
  u32 tb_rate = ntohl (mp->tb_rate);
  u32 tb_size = ntohl (mp->tb_size);
  u32 tc_period = ntohl (mp->tc_period);
  u32 tc_rate[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];

  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      tc_rate[i] = ntohl(mp->tc_rate[i]);
    }

  VALIDATE_SW_IF_INDEX (mp);

  error = dpdk_hqos_get_intf_context (sw_if_index, &xd, &devconf);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      clib_warning ("hqos not enabled on interface");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  error = dpdk_hqos_get_subport_profile (&devconf->hqos, profile, &p);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if (tb_rate != 0)
    {
      p.tb_rate = tb_rate;
      for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
	{
	  p.tc_rate[i] = tb_rate;
	}
      p.tb_size = MAX((HQOS_DEFAULT_SCHED_TB_SIZE_MS * (p.tb_rate / 1000)),
		      HQOS_MIN_SCHED_TB_SIZE_BYTES);
    }

  if (tb_size != 0)
    {
      p.tb_size = tb_size;
    }
  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      if (tc_rate[i] != 0)
	{
	  p.tc_rate[i] = tc_rate[i];
	}
    }
  if (tc_period != 0)
    {
      p.tc_period = tc_period;
    }
  // Apply changes to profile
  error = dpdk_hqos_setup_subport_profile (xd, &devconf->hqos, profile, &p);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  BAD_SW_IF_INDEX_LABEL;

done:
  if (error)
    clib_error_free(error);
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_SUBPORT_PROFILE_REPLY);
}


static void
  vl_api_sw_interface_set_dpdk_hqos_subport_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_subport_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_subport_reply_t *rmp;
  dpdk_main_t *dm = &dpdk_main;
  int rv = 0;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  clib_error_t *error = NULL;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 subport_id = ntohl (mp->subport_id);
  u32 profile = ntohl (mp->profile);

  VALIDATE_SW_IF_INDEX (mp);

  error = dpdk_hqos_get_intf_context (sw_if_index, &xd, &devconf);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      clib_warning ("hqos not enabled on interface");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  error = dpdk_hqos_setup_subport (xd, &devconf->hqos, subport_id, profile);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  BAD_SW_IF_INDEX_LABEL;

done:
  if (error)
    clib_error_free(error);
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_SUBPORT_REPLY);
}


static void
  vl_api_sw_interface_set_dpdk_if_hqos_pktfield_t_handler
  (vl_api_sw_interface_set_dpdk_if_hqos_pktfield_t * mp)
{
  vl_api_sw_interface_set_dpdk_if_hqos_pktfield_reply_t *rmp;
  int rv = 0;
  int i;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  clib_error_t *error = NULL;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 id = ntohl (mp->id);
  u32 offset = ntohl (mp->offset);
  u64 mask = clib_net_to_host_u64 (mp->mask);

  VALIDATE_SW_IF_INDEX (mp);

  error = dpdk_hqos_get_intf_context (sw_if_index, &xd, &devconf);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      clib_warning ("hqos not enabled on interface");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if (id >= 3)
    {
      clib_warning ("invalid id : %u (0 - subport, 1 - pipe, 2 - tc)", id);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  u32 n_subports_per_port = devconf->hqos.port_params.n_subports_per_port;
  u32 n_pipes_per_subport = devconf->hqos.port_params.n_pipes_per_subport;
  u32 tctbl_size = RTE_DIM (devconf->hqos.tc_table);

  switch (id)
    {
    case 0:
      if (mask && dpdk_hqos_validate_mask (mask, n_subports_per_port) != 0)
       {
         clib_warning ("invalid subport ID mask (n_subports_per_port = %u)",
                       n_subports_per_port);
         rv = VNET_API_ERROR_INVALID_VALUE;
         goto done;
       }
      break;
    case 1:
      if (mask && dpdk_hqos_validate_mask (mask, n_pipes_per_subport) != 0)
       {
         clib_warning ("invalid pipe ID mask (n_pipes_per_subport = %u)",
                       n_pipes_per_subport);
         rv = VNET_API_ERROR_INVALID_VALUE;
         goto done;
       }
      break;
    case 2:
    default:
      if (mask && dpdk_hqos_validate_mask (mask, tctbl_size) != 0)
       {
         clib_warning ("invalid TC table index mask (TC table size = %u)",
		       tctbl_size);
         rv = VNET_API_ERROR_INVALID_VALUE;
         goto done;
       }
    }
  /* Detect the set of worker threads */
  u32 worker_thread_count, worker_thread_first;
  vlib_get_core_worker_count_and_first_index (&worker_thread_count,
                                              &worker_thread_first);

  // set value to all worker and main-thread-0 context
  dpdk_hqos_setup_pktfield(xd, id, offset, mask, 0);
  for (i = worker_thread_first;
       i < (worker_thread_first + worker_thread_count); i++)
    {
      dpdk_hqos_setup_pktfield(xd, id, offset, mask, i);
    }

  BAD_SW_IF_INDEX_LABEL;
done:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_IF_HQOS_PKTFIELD_REPLY);
}


static void
  vl_api_sw_interface_set_dpdk_hqos_tctbl_t_handler
  (vl_api_sw_interface_set_dpdk_hqos_tctbl_t * mp)
{
  vl_api_sw_interface_set_dpdk_hqos_tctbl_reply_t *rmp;
  int rv = 0;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  clib_error_t *error = NULL;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 entry = ntohl (mp->entry);
  u32 tc = ntohl (mp->tc);
  u32 queue = ntohl (mp->queue);
  u32 val, i;

  VALIDATE_SW_IF_INDEX (mp);

  error = dpdk_hqos_get_intf_context (sw_if_index, &xd, NULL);
  if (error)
    {
      clib_warning ("%U", format_clib_error, error);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      clib_warning ("hqos not enabled on interface");
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  if (entry >= 64)
    {
      clib_warning ("invalid entry : %u (has to be between 0 to 63)", entry);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
      clib_warning ("invalid traffic class : %u (has to be between 0 to 12)",
		    tc);
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }
  if (tc == RTE_SCHED_TRAFFIC_CLASS_BE)
    {
      if ((queue < 0) || (queue >= RTE_SCHED_BE_QUEUES_PER_PIPE))
	{
	  clib_warning ("invalid queue value for BE TC : %u (valid b/n 0-3)",
			queue);
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto done;
	}
    }
  else
    {
      if (queue != 0)
        {
	  clib_warning ("invalid queue value for non BE TC : %u (valid is 0)",
			queue);
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto done;
        }
    }

  // Detect the set of worker threads
  u32 worker_thread_count, worker_thread_first;
  vlib_get_core_worker_count_and_first_index (&worker_thread_count,
                                              &worker_thread_first);

  val = (tc << 2) + queue;
  // set value to all worker and main-thread-0 context
  xd->hqos_wt[0].hqos_tc_table[entry] = val;
  for (i = worker_thread_first;
       i < (worker_thread_first + worker_thread_count); i++)
    {
      xd->hqos_wt[i].hqos_tc_table[entry] = val;
    }

  BAD_SW_IF_INDEX_LABEL;
done:
  if (error)
    clib_error_free(error);
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_DPDK_HQOS_TCTBL_REPLY);
}

#include <dpdk/api/dpdk.api.c>
static clib_error_t *
dpdk_api_init (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;

  /* Ask for a correctly-sized block of API message decode slots */
  dm->msg_id_base = setup_message_id_table ();

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (dpdk_api_init) =
{
  .runs_after = VLIB_INITS ("dpdk_init"),
};
/* *INDENT-OFF* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
