/*
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
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
 * List of features and fixes made for FlexiWAN (denoted by FLEXIWAN_FEATURE and FLEXIWAN_FIX flags):
 *  - integrating_dpdk_qos_sched : The DPDK QoS scheduler integration in VPP is
 *    currently in deprecated state. It is likely deprecated as changes
 *    in DPDK scheduler APIs required corresponding changes from VPP side.
 *    The FlexiWAN commit makes the required corresponding changes and brings
 *    back the feature to working state. Additionaly made enhancements in the
 *    context of WAN QoS needs.
 *
 *  - acl_based_classification: Feature to provide traffic classification using
 *    ACL plugin. Matching ACLs provide the service class and importance
 *    attribute. The classification result is marked in the packet and can be
 *    made use of in other functions like scheduling, policing, marking etc.
 *
 *  - enable_dpdk_tun_init : The VPP's DPDK plugin currently does not expose
 *    DPDK capability to initialize TUN interface. This set of changes enable
 *    VPP to initialize TUN interfaces using DPDK. This sets up TUN interfaces
 *    to make use of DPDK interface feature like QoS.
 *
 *  - call vlib_buffer_worker_init : if VPP is configured to use cores, and HQoS is enabled,
 *    there will be no worker threads, as one core will be used for main thread and other - for HQoS.
 *    In this case, the multi-threading data structures will be not initialized. But some of them,
 *    like per thread buffer pools, are used by the HQoS thread. So we have to initialize them manually.
 *  
 * This deprecated file is enhanced and added as part of the
 * flexiwan feature - integrating_dpdk_qos_sched
 * Location of deprecated file: extras/deprecated/dpdk-hqos/hqos.c 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <string.h>
#include <fcntl.h>
//#ifdef FLEXIWAN_FEATURE /* enable_dpdk_tun_init */
#include <net/if.h>
//#endif /* FLEXIWAN_FEATURE - enable_dpdk_tun_init */

#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/clib.h>

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/buffer.h>

#include <vlib/pci/pci.h>
#include <vlibmemory/api.h>
#include <vlibmemory/vl_memory_msg_enum.h>	/* enumerate all vlib messages */

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

#include <dpdk/device/dpdk_priv.h>

/*
  Values set based on typical dpdk qos guideline
  https://doc.dpdk.org/guides/prog_guide/qos_framework.html
  */
#define HQOS_SCHED_QUEUE_SIZE                64
#define HQOS_RED_QUEUE_MAX_THR               (HQOS_SCHED_QUEUE_SIZE / 2)
#define HQOS_RED_QUEUE_MIN_THR_GREEN         28
#define HQOS_RED_QUEUE_MIN_THR_YELLOW        22
#define HQOS_RED_QUEUE_MIN_THR_RED           16
#define HQOS_RED_INV_MARK_PROBABILITY        10
#define HQOS_RED_EWMA_FILTER_WEIGHT          9


/***
 *
 * HQoS init default configuration values
 *
 ***/

void 
dpdk_hqos_init_default_port_params (struct rte_sched_port_params * port_params,
                                    u32 max_subports, u32 max_pipes)
{
  /* Init hqos default port params */
  port_params->n_subports_per_port =
    (max_subports) ? max_subports : HQOS_DEFAULT_SCHED_SUBPORTS;
  port_params->n_pipes_per_subport =
    (max_pipes) ? max_pipes : HQOS_DEFAULT_SCHED_PIPES;
  port_params->name = NULL; /* Set at port init */
  port_params->socket = 0;  /* Set at port init */
  port_params->rate = HQOS_DEFAULT_SCHED_PORT_RATE;
  port_params->mtu = HQOS_DEFAULT_SCHED_MTU_BYTES;
  port_params->frame_overhead = RTE_SCHED_FRAME_OVERHEAD_DEFAULT;
  port_params->subport_profiles = NULL;/* Set at port init*/
  port_params->n_subport_profiles = 0; /* Set at port init*/
  port_params->n_max_subport_profiles = port_params->n_subports_per_port;
}


static void 
dpdk_hqos_init_default_pipe_params (struct rte_sched_pipe_params * pipe_params)
{
  /* Init hqos default pipe params */
  u32 i;
  pipe_params->tb_rate = HQOS_DEFAULT_SCHED_PORT_RATE;
  pipe_params->tb_size =
    MAX(((HQOS_DEFAULT_SCHED_TB_SIZE_MS * pipe_params->tb_rate) / 1000),
        HQOS_MIN_SCHED_TB_SIZE_BYTES);
  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    pipe_params->tc_rate[i] = pipe_params->tb_rate;
  pipe_params->tc_period = HQOS_DEFAULT_SCHED_PIPE_TC_PERIOD_MS;
  pipe_params->tc_ov_weight = 1;
  // Default weights Q0 : 4, Q1: 3, Q2: 2, Q3: 1
  for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++)
    pipe_params->wrr_weights[i] = RTE_SCHED_BE_QUEUES_PER_PIPE - i;
}


static void
dpdk_hqos_init_default_subport_params
(struct rte_sched_subport_params * subport_params, u32 max_pipes)
{
  /* Init hqos default subport params */
  u32 i;
  subport_params->n_pipes_per_subport_enabled =
    (max_pipes) ? max_pipes : HQOS_DEFAULT_SCHED_PIPES;
  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    subport_params->qsize[i] = HQOS_SCHED_QUEUE_SIZE;
  subport_params->pipe_profiles = NULL; /* Set at subport init */
  subport_params->n_pipe_profiles = 0;  /* Set at subport init */
  subport_params->n_max_pipe_profiles =
    subport_params->n_pipes_per_subport_enabled;

#ifdef RTE_SCHED_RED
  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      subport_params->red_params[i][RTE_COLOR_GREEN].min_th =
	HQOS_RED_QUEUE_MIN_THR_GREEN;
      subport_params->red_params[i][RTE_COLOR_GREEN].max_th =
	HQOS_RED_QUEUE_MAX_THR;
      subport_params->red_params[i][RTE_COLOR_GREEN].maxp_inv =
	HQOS_RED_INV_MARK_PROBABILITY;
      subport_params->red_params[i][RTE_COLOR_GREEN].wq_log2 =
	HQOS_RED_EWMA_FILTER_WEIGHT;

      subport_params->red_params[i][RTE_COLOR_YELLOW].min_th =
	HQOS_RED_QUEUE_MIN_THR_YELLOW;
      subport_params->red_params[i][RTE_COLOR_YELLOW].max_th =
	HQOS_RED_QUEUE_MAX_THR;
      subport_params->red_params[i][RTE_COLOR_YELLOW].maxp_inv =
	HQOS_RED_INV_MARK_PROBABILITY;
      subport_params->red_params[i][RTE_COLOR_YELLOW].wq_log2 =
	HQOS_RED_EWMA_FILTER_WEIGHT;

      subport_params->red_params[i][RTE_COLOR_RED].min_th =
	HQOS_RED_QUEUE_MIN_THR_RED;
      subport_params->red_params[i][RTE_COLOR_RED].max_th =
	HQOS_RED_QUEUE_MAX_THR;
      subport_params->red_params[i][RTE_COLOR_RED].maxp_inv =
	HQOS_RED_INV_MARK_PROBABILITY;
      subport_params->red_params[i][RTE_COLOR_RED].wq_log2 =
	HQOS_RED_EWMA_FILTER_WEIGHT;
    }
#endif
}


static void 
dpdk_hqos_init_default_subport_profile_params
(struct rte_sched_subport_profile_params * subport_profile_params)
{
  /* Init hqos default subport profile params */
  subport_profile_params->tb_rate = HQOS_DEFAULT_SCHED_PORT_RATE;
  subport_profile_params->tb_size =
    MAX((HQOS_DEFAULT_SCHED_TB_SIZE_MS *
	 (HQOS_DEFAULT_SCHED_PORT_RATE / 1000)), HQOS_MIN_SCHED_TB_SIZE_BYTES);
  for (u32 i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    subport_profile_params->tc_rate[i] = HQOS_DEFAULT_SCHED_PORT_RATE;
  subport_profile_params->tc_period = HQOS_DEFAULT_SCHED_SUBPORT_TC_PERIOD_MS;
}


static clib_error_t *
dpdk_hqos_init_port (dpdk_device_t * xd, dpdk_device_config_hqos_t * hqos)
{
  clib_error_t *error = NULL;

  struct rte_sched_subport_profile_params *subport_profile_params;
  vec_add2 (hqos->port_params.subport_profiles, subport_profile_params, 1);
  dpdk_hqos_init_default_subport_profile_params (subport_profile_params);
  hqos->port_params.n_subport_profiles = 1;

  xd->hqos_ht->hqos = rte_sched_port_config (&hqos->port_params);
  if (xd->hqos_ht->hqos == NULL)
    {
      error =  clib_error_return (0, "hqos port init failed %u", xd->port_id);
      vec_delete (hqos->port_params.subport_profiles, 1, 0);
      hqos->port_params.n_subport_profiles = 0;
    }
  return error;
}


static clib_error_t *
dpdk_hqos_add_subport (dpdk_device_t * xd, dpdk_device_config_hqos_t * hqos,
		       u32 subport_id, u32 profile_id)
{
  clib_error_t * error = NULL;
  u32 n_subports = vec_len (hqos->subport_params);

  if (subport_id >= hqos->port_params.n_subports_per_port)
    {
      error = clib_error_return
        (0, "subport id higher than max - allowed range (%u to %u)", 0,
         (hqos->port_params.n_subports_per_port - 1));
      return error;
    }
  if (subport_id != n_subports)
    {
      /* subport id need to continuous - skipping id not allowed */
      error = clib_error_return
        (0, "configuration skips subport id - next subport id to use: %u",
         n_subports);
      return error;
    }
  if (profile_id >= hqos->port_params.n_subport_profiles)
    {
      error = clib_error_return (0, "profile not found");
      return error;
    }

  /* Add to subport params vector */
  struct rte_sched_subport_params *subport_params;
  vec_add2 (hqos->subport_params, subport_params, 1);
  dpdk_hqos_init_default_subport_params
    (subport_params, hqos->port_params.n_pipes_per_subport);

  /* Setup pipe params */
  struct rte_sched_pipe_params *pipe_params;
  vec_add2 (hqos->subport_params[subport_id].pipe_profiles, pipe_params, 1);
  dpdk_hqos_init_default_pipe_params (pipe_params); 
  hqos->subport_params[subport_id].n_pipe_profiles = 1;

  /* Add new subport */
  int rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport_id,
				     &hqos->subport_params[subport_id],
				     profile_id);
  if (rv)
    {
      error = clib_error_return (0, "Subport config failed %d", rv);
      hqos->subport_params[subport_id].n_pipe_profiles--;
      vec_delete (hqos->subport_params[subport_id].pipe_profiles, 1,
		  hqos->subport_params[subport_id].n_pipe_profiles);
      vec_delete (hqos->subport_params, 1, subport_id);
    }
  else
    {
      /* Set subport profile id at subport id index */
      u32 * subport_profile_id;
      vec_add2 (hqos->subport_profile_id_map, subport_profile_id, 1);
      *subport_profile_id = profile_id;
    }
  return error;
}


static clib_error_t *
dpdk_hqos_add_pipe (dpdk_device_t * xd, dpdk_device_config_hqos_t * hqos,
		    u32 subport_id, u32 pipe_id, u32 profile_id)
{
  clib_error_t * error = NULL;
  u32 n_subports = vec_len (hqos->subport_params);
  if (subport_id >= n_subports)
    {
      error = clib_error_return (0, "subport not found");
      return error;
    }

  if (pipe_id >= hqos->port_params.n_pipes_per_subport)
    {
      error = clib_error_return
        (0, "pipe id higher than max - allowed range (%u to %u)", 0,
         (hqos->port_params.n_pipes_per_subport - 1));
      return error;
    }
  vec_validate_init_empty (hqos->pipes, subport_id, 0);
  if (pipe_id != hqos->pipes[subport_id])
    {
      /* subport id need to continuous - skipping id not allowed */
      error = clib_error_return
        (0, "configuration skips pipe id - next pipe id to use: %u",
         hqos->pipes[subport_id]);
      return error;
    }
  if (profile_id >= hqos->subport_params[subport_id].n_pipe_profiles)
    {
      error = clib_error_return (0, "pipe profile not found");
      return error;
    }

  /* Add new pipe */
  int rv = rte_sched_pipe_config (xd->hqos_ht->hqos, subport_id, pipe_id,
			          profile_id);
  if (rv)
    {
      error = clib_error_return (0, "pipe create failed");
    }
  else
    {
      hqos->pipes[subport_id]++;
      /* Set pipe profile id at (subport, pipe) id index */
      vec_validate_init_empty (hqos->pipe_profile_id_map, subport_id, 0);
      vec_validate (hqos->pipe_profile_id_map[subport_id], pipe_id);
      hqos->pipe_profile_id_map[subport_id][pipe_id] = profile_id;
    }
  return error;
}


int
dpdk_hqos_validate_mask (u64 mask, u32 n)
{
  int count = __builtin_popcountll (mask);
  int pos_lead = sizeof (u64) * 8 - count_leading_zeros (mask);
  int pos_trail = count_trailing_zeros (mask);
  int count_expected = __builtin_popcount (n - 1);

  /* Handle the exceptions */
  if (n == 0)
    return -1;			/* Error */

  if ((mask == 0) && (n == 1))
    return 0;			/* OK */

  if (((mask == 0) && (n != 1)) || ((mask != 0) && (n == 1)))
    return -2;			/* Error */

  /* Check that mask is contiguous */
  if ((pos_lead - pos_trail) != count)
    return -3;			/* Error */

  /* Check that mask contains the expected number of bits set */
  if (count != count_expected)
    return -4;			/* Error */

  return 0;			/* OK */
}


clib_error_t *
dpdk_hqos_get_intf_context (u32 sw_if_index, dpdk_device_t ** xd,
                            dpdk_device_config_t ** devconf)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw;
  struct rte_eth_dev_info dev_info;
  struct rte_pci_device *pci_dev;
  uword *p = 0;
  clib_error_t *error = NULL;

  if (sw_if_index == (u32) ~ 0)
    {
      error = clib_error_return (0, "please specify valid interface");
      goto done;
    }

  hw = vnet_get_hw_interface_or_null (dm->vnet_main, sw_if_index);
  if (hw == NULL)
    {
      error = clib_error_return (0, "interface not found");
      goto done;
    }
  *xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rte_eth_dev_info_get ((*xd)->port_id, &dev_info);
  pci_dev = dpdk_get_pci_device (&dev_info);
  if (pci_dev)
    {
      vlib_pci_addr_t pci_addr;

      pci_addr.domain = pci_dev->addr.domain;
      pci_addr.bus = pci_dev->addr.bus;
      pci_addr.slot = pci_dev->addr.devid;
      pci_addr.function = pci_dev->addr.function;

      p =
       hash_get (dm->conf->device_config_index_by_pci_addr, pci_addr.as_u32);
    }
#ifdef FLEXIWAN_FEATURE /* enable_dpdk_tun_init */
  else
    {
      char ifname[IFNAMSIZ];
      if (if_indextoname (dev_info.if_index, ifname))
	{
	  p = hash_get_mem (dm->conf->device_config_index_by_ifname, ifname);
	}
    }
#endif /* FLEXIWAN_FEATURE - enable_dpdk_tun_init */

  if (devconf)
    {
      if (p)
	(*devconf) = pool_elt_at_index (dm->conf->dev_confs, p[0]);
      else
#ifdef FLEXIWAN_FEATURE /* enable_dpdk_tun_init */
	/*
	 * With the changes, it is always true that every interface will own
	 * a device config
	 */
	error = clib_error_return (0, "interface config not found");
#else /* FLEXIWAN_FEATURE - enable_dpdk_tun_init */
        (*devconf) = &dm->conf->default_devconf;
#endif /* FLEXIWAN_FEATURE - enable_dpdk_tun_init */
    }

done:
  return error;
}


clib_error_t *
dpdk_hqos_get_subport_profile (dpdk_device_config_hqos_t * hqos,
			       u32 profile_id,
                               struct rte_sched_subport_profile_params * p_out)
{
  clib_error_t *error = NULL;
  if (profile_id >= hqos->port_params.n_max_subport_profiles)
    {
      error = clib_error_return (0, "profile id higher than max - allowed "
				 "range (%u to %u)", 0,
                                 (hqos->port_params.n_max_subport_profiles-1));
      return error;
    }
  if (profile_id < hqos->port_params.n_subport_profiles)
    {
      memcpy (p_out, &hqos->port_params.subport_profiles[profile_id],
	      sizeof (struct rte_sched_subport_profile_params));
    }
  else
    {
      dpdk_hqos_init_default_subport_profile_params (p_out);
    }
  return error;
}


clib_error_t *
dpdk_hqos_setup_subport_profile (dpdk_device_t * xd,
				 dpdk_device_config_hqos_t * hqos,
				 u32 profile_id,
                                 struct rte_sched_subport_profile_params *
				 params)
{
  clib_error_t *error = NULL;
  int rv;
  if (profile_id >= hqos->port_params.n_max_subport_profiles)
    {
      error = clib_error_return
        (0, "profile id higher than max - allowed range (%u to %u)", 0,
         (hqos->port_params.n_max_subport_profiles-1));
      return error;
    }

  struct rte_sched_subport_profile_params * subport_profiles =
    hqos->port_params.subport_profiles;
  if (profile_id < hqos->port_params.n_subport_profiles)
    {
      /* Update existing profile */
      memcpy (&subport_profiles[profile_id], params,
	      sizeof (struct rte_sched_subport_profile_params));
      rv = rte_sched_port_subport_profile_update
        (xd->hqos_ht->hqos, profile_id, &subport_profiles[profile_id]);
      if (rv)
        error = clib_error_return (0, "subport profile update failed %d", rv);
    }
  else if (profile_id == hqos->port_params.n_subport_profiles)
    {
      /* case of new profile add */
      struct rte_sched_subport_profile_params *subport_profile_params;
      vec_add2 (hqos->port_params.subport_profiles,
				   subport_profile_params, 1);
      memcpy (subport_profile_params, params,
	      sizeof (struct rte_sched_subport_profile_params));
      subport_profiles = hqos->port_params.subport_profiles;
      rv = rte_sched_port_subport_profile_add (xd->hqos_ht->hqos,
					       &subport_profiles[profile_id],
					       &profile_id);
      if (rv)
	{
	  error = clib_error_return (0, "subport profile add failed %d", rv);
	  vec_delete (hqos->port_params.subport_profiles, 1, profile_id);
	}
      else
	{
	  hqos->port_params.n_subport_profiles++;
	}
    }
  else
    {
      /* subport profile id need to continuous - skipping id not allowed */
      error = clib_error_return
        (0, "configuration skips profile id - next "
				 "subport profile id to use: %u",
				 hqos->port_params.n_subport_profiles);
    }
  return error;
}


clib_error_t *
dpdk_hqos_get_pipe_profile (dpdk_device_config_hqos_t * hqos,
			    u32 subport_id, u32 profile_id,
			    struct rte_sched_pipe_params * p_out)
{
  clib_error_t *error = NULL;
  u32 n_subports = vec_len (hqos->subport_params);
  if (subport_id >= n_subports)
    {
      error = clib_error_return (0, "subport not found");
      return error;
    }
  if (profile_id >= hqos->port_params.n_pipes_per_subport)
    {
      error = clib_error_return
        (0, "profile id higher than max - allowed range (%u to %u)", 0,
         (hqos->port_params.n_pipes_per_subport - 1));
      return error;
    }

  if (profile_id < hqos->subport_params[subport_id].n_pipe_profiles)
    {
      memcpy (p_out,
	      &hqos->subport_params[subport_id].pipe_profiles[profile_id],
	      sizeof (struct rte_sched_pipe_params));
    }
  else
    {
      dpdk_hqos_init_default_pipe_params (p_out);
    }
  return error;
}


clib_error_t *
dpdk_hqos_setup_pipe_profile (dpdk_device_t * xd,
			      dpdk_device_config_hqos_t * hqos, u32 subport_id,
			      u32 profile_id,
                              struct rte_sched_pipe_params * params)
{
  clib_error_t *error = NULL;
  int rv;
  u32 n_subports = vec_len (hqos->subport_params);
  if (subport_id >= n_subports)
    {
      error = clib_error_return (0, "subport not found");
      return error;
    }
  if (profile_id >= hqos->port_params.n_pipes_per_subport)
    {
      error = clib_error_return (0, "profile id higher than max - allowed "
				 "range (%u to %u)", 0,
				 (hqos->port_params.n_pipes_per_subport - 1));
      return error;
    }

  if (profile_id < hqos->subport_params[subport_id].n_pipe_profiles)
    {
      /* Update existing profile */
      struct rte_sched_pipe_params * pipe_params =
	&hqos->subport_params[subport_id].pipe_profiles[profile_id];
      memcpy (pipe_params, params, sizeof (struct rte_sched_pipe_params));
      rv = rte_sched_subport_pipe_profile_update (xd->hqos_ht->hqos,
						  subport_id, profile_id,
						  pipe_params);
      if (rv)
	{
	  error = clib_error_return (0, "pipe profile update failed %d", rv);
	}
    }
  else if (profile_id == hqos->subport_params[subport_id].n_pipe_profiles)
    {
      /* case of new profile add */
      /* Setup pipe params */
      struct rte_sched_pipe_params *pipe_params;
      vec_add2 (hqos->subport_params[subport_id].pipe_profiles,
		pipe_params, 1);
      memcpy (pipe_params, params, sizeof (struct rte_sched_pipe_params));

      rv = rte_sched_subport_pipe_profile_add (xd->hqos_ht->hqos, subport_id,
					       params, &profile_id);
      if (rv)
	{
	  error = clib_error_return (0, "pipe profile add failed %d", rv);
	  vec_delete (hqos->subport_params[subport_id].pipe_profiles, 1,
		      profile_id);
	}
      else
	{
	  hqos->subport_params[subport_id].n_pipe_profiles++;
	}
    }
  else
    {
      /* subport profile id need to continuous - skipping id not allowed */
      error = clib_error_return (0, "configuration skips profile id - next "
				 "pipe profile id to use: %u",
				 hqos->port_params.n_subport_profiles);
    }
  return error;
}


clib_error_t *
dpdk_hqos_setup_subport (dpdk_device_t * xd, dpdk_device_config_hqos_t * hqos,
			 u32 subport_id, u32 profile_id)
{
  clib_error_t *error = NULL;
  int rv;

  if (profile_id >= hqos->port_params.n_subport_profiles)
    {
      error = clib_error_return (0, "subport profile is not found");
      return error;
    }

  u32 n_subports = vec_len (hqos->subport_params);
  if (subport_id < n_subports)
    {
      /* Update existing subport to pickeup new profile params */
      rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport_id, NULL,
				     profile_id);
      if (rv)
	error = clib_error_return (0, "subport profile update failed %d", rv);
      else
        hqos->subport_profile_id_map[subport_id] = profile_id;
    }
  else if (subport_id == n_subports)
    {
      error = dpdk_hqos_add_subport (xd, hqos, subport_id, profile_id);
    }
  else
    {
      /* subport id need to continuous - skipping id not allowed */
      error = clib_error_return (0, "subport id skipped - next id to use : %u",
				 n_subports);
    }

  return error;
}


clib_error_t *
dpdk_hqos_setup_pipe (dpdk_device_t * xd, dpdk_device_config_hqos_t * hqos,
                      u32 subport_id, u32 pipe_id, u32 profile_id)
{
  clib_error_t *error = NULL;
  u32 n_subports = vec_len (hqos->subport_params);
  if (subport_id >= n_subports)
    {
      error = clib_error_return (0, "subport not found");
      goto done;
    }
  if (profile_id >= hqos->subport_params[subport_id].n_pipe_profiles)
    {
      error = clib_error_return
	(0, "pipe profile %u not found(%u) in subport: %u", profile_id,
	 hqos->subport_params[subport_id].n_pipe_profiles, subport_id);
      goto done;
    }

  u32 n_pipes = hqos->pipes[subport_id];
  if (pipe_id < n_pipes)
    {
      /* Update existing pipe to reload profile */
      int rv = rte_sched_pipe_config (xd->hqos_ht->hqos, subport_id, pipe_id,
				      profile_id);
      if (rv)
	{
	  error = clib_error_return (0, "pipe profile update failed %u", rv);
	}
      else
        {
          hqos->pipe_profile_id_map[subport_id][pipe_id] = profile_id;
        }
    }
  else if (pipe_id == n_pipes)
    {
      error = dpdk_hqos_add_pipe (xd, hqos, subport_id, pipe_id, profile_id);
    }
  else
    {
      /* subport id need to continuous - skipping id not allowed */
      error = clib_error_return (0, "configuration skips id - next free: %u",
				 n_pipes);
    }

done:
  return error;
}

clib_error_t *
dpdk_hqos_get_queue_stats (dpdk_device_t * xd,
			   dpdk_device_config_hqos_t * hqos, u32 subport_id,
			   u32 pipe_id, u32 tc, u32 tc_q, 
			   struct rte_sched_queue_stats * stats)
{
  u32 n_subports = vec_len (hqos->subport_params);
  if (subport_id >= n_subports)
    {
      return clib_error_return (0, "Invalid subport - Max configured %u",
                                n_subports);
    }
  if (pipe_id >= hqos->pipes[subport_id])
    {
      return clib_error_return (0, "Invalid pipe - Max configured %u",
		                hqos->pipes[subport_id]);
    }
  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
      return clib_error_return (0, "Invalid traffic class - Max configured %u",
                                 RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE);
    }
  if (tc < RTE_SCHED_TRAFFIC_CLASS_BE)
    {
      if (tc_q != 0)
        {
          return clib_error_return (0, "Invalid queue id - Max configured 0");
        }
    }
  else
    {
      if (tc_q >= RTE_SCHED_BE_QUEUES_PER_PIPE)
        {
          return clib_error_return (0,
				    "Invalid queue id - Max configured 0 - 3");
        }
    }

  u32 qindex = subport_id * hqos->port_params.n_pipes_per_subport *
    RTE_SCHED_QUEUES_PER_PIPE;
  if (tc < RTE_SCHED_TRAFFIC_CLASS_BE)
    qindex += pipe_id * RTE_SCHED_QUEUES_PER_PIPE + tc;
  else
    qindex += pipe_id * RTE_SCHED_QUEUES_PER_PIPE + tc + tc_q;

  u16 qlen;
  int rv =rte_sched_queue_read_stats (xd->hqos_ht->hqos, qindex, stats,
				      &qlen);
  if (rv)
    {
      return clib_error_return (0, "failed to read stats %d", rv);
    }
  return 0;
}


void
dpdk_hqos_setup_pktfield (dpdk_device_t *xd, u32 id, u32 offset, u64 mask,
			  u32 thread_index)
{
  switch (id)
    {
    case 0:
      xd->hqos_wt[thread_index].hqos_field0_slabpos = offset;
      xd->hqos_wt[thread_index].hqos_field0_slabmask = mask;
      xd->hqos_wt[thread_index].hqos_field0_slabshr =
	count_trailing_zeros (mask);
      break;
    case 1:
      xd->hqos_wt[thread_index].hqos_field1_slabpos = offset;
      xd->hqos_wt[thread_index].hqos_field1_slabmask = mask;
      xd->hqos_wt[thread_index].hqos_field1_slabshr =
	count_trailing_zeros (mask);
      break;
    case 2:
      xd->hqos_wt[thread_index].hqos_field2_slabpos = offset;
      xd->hqos_wt[thread_index].hqos_field2_slabmask = mask;
      xd->hqos_wt[thread_index].hqos_field2_slabshr =
	count_trailing_zeros (mask);
    }
}


static void
dpdk_hqos_setup_pktfield_default (dpdk_device_t *xd,
				  dpdk_device_config_hqos_t * hqos,
				  u32 thread_index)
{
  dpdk_hqos_setup_pktfield (xd, 0, hqos->pktfield0_slabpos,
			    hqos->pktfield0_slabmask, thread_index);
  dpdk_hqos_setup_pktfield (xd, 1, hqos->pktfield1_slabpos,
			    hqos->pktfield1_slabmask, thread_index);
  dpdk_hqos_setup_pktfield (xd, 2, hqos->pktfield2_slabpos,
			    hqos->pktfield2_slabmask, thread_index);
}

/***
 *
 * HQoS init
 *
 ***/

clib_error_t *
dpdk_port_setup_hqos (dpdk_device_t * xd, dpdk_device_config_hqos_t * hqos)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  char name[32];
  u32 i;
  //int rv;
  clib_error_t * error = NULL;

  /* Detect the set of worker threads */
  u32 worker_thread_count, worker_thread_first;
  vlib_get_core_worker_count_and_first_index (&worker_thread_count,
                                              &worker_thread_first);

  /* Allocate the per-thread device data array */
  vec_validate_aligned (xd->hqos_wt, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  clib_memset (xd->hqos_wt, 0, tm->n_vlib_mains * sizeof (xd->hqos_wt[0]));

  vec_validate_aligned (xd->hqos_ht, 0, CLIB_CACHE_LINE_BYTES);
  clib_memset (xd->hqos_ht, 0, sizeof (xd->hqos_ht[0]));

  /* Allocate space for one SWQ per worker thread in the I/O TX thread data structure */
  vec_validate (xd->hqos_ht->swq, worker_thread_count);

  /* SWQ */
  for (i = 0; i < worker_thread_count + 1; i++)
    {
      u32 swq_flags = RING_F_SP_ENQ | RING_F_SC_DEQ;

      snprintf (name, sizeof (name), "SWQ-worker%u-to-device%hu", i,
		xd->port_id);
      xd->hqos_ht->swq[i] =
	rte_ring_create (name, hqos->swq_size, xd->cpu_socket, swq_flags);
      if (xd->hqos_ht->swq[i] == NULL)
	return clib_error_return (0,
				  "SWQ-worker%u-to-device%u: rte_ring_create err",
				  i, xd->port_id);
    }

  /*
   * HQoS
   */
  /* Setup port params */

  snprintf (name, sizeof (name), "HQoS%u", xd->port_id);
  hqos->port_params.name = strdup (name);
  if (hqos->port_params.name == NULL)
    return clib_error_return (0, "HQoS%u: strdup err", xd->port_id);

  hqos->port_params.socket = rte_eth_dev_socket_id (xd->port_id);
  if (hqos->port_params.socket == SOCKET_ID_ANY)
    hqos->port_params.socket = 0;

  /* Setup default port/subport/pipe */
  error = dpdk_hqos_init_port (xd, hqos);
  if (error == NULL)
    {
      for (i = 0; i < hqos->port_params.n_subports_per_port; i++)
	{
	  error = dpdk_hqos_add_subport (xd, hqos, i, 0);
	  if (error == NULL)
	    {
	      error = dpdk_hqos_add_pipe (xd, hqos, i, 0, 0);
	    }
	  if (error)
	    {
	      break;
	    }
	}
    }
  if (error)
    return error;

  /* Set up per-thread device data for the I/O TX thread */
  xd->hqos_ht->hqos_burst_enq = hqos->burst_enq;
  xd->hqos_ht->hqos_burst_deq = hqos->burst_deq;
  vec_validate (xd->hqos_ht->pkts_enq, 2 * hqos->burst_enq - 1);
  vec_validate (xd->hqos_ht->pkts_deq, hqos->burst_deq - 1);
  xd->hqos_ht->pkts_enq_len = 0;
  xd->hqos_ht->swq_pos = 0;
  xd->hqos_ht->flush_count = 0;

  /* Set up per-thread device data for each worker thread and main-thread-0 */
  dpdk_hqos_setup_pktfield_default (xd, hqos, 0);
  memcpy (xd->hqos_wt[0].hqos_tc_table, hqos->tc_table,
          sizeof (hqos->tc_table));
  u32 count = 0;
  xd->hqos_wt[0].swq = xd->hqos_ht->swq[count++];
  for (i = worker_thread_first;
       i < (worker_thread_first + worker_thread_count); i++)
    {
      xd->hqos_wt[i].swq = xd->hqos_ht->swq[count++];
      dpdk_hqos_setup_pktfield_default (xd, hqos, i);
      memcpy (xd->hqos_wt[i].hqos_tc_table, hqos->tc_table,
              sizeof (hqos->tc_table));
    }

  return error;
}

/***
 *
 * HQoS run-time
 *
 ***/
/*
 * dpdk_hqos_thread - Contains the main loop of an HQoS thread.
 *
 * w
 *     Information for the current thread
 */
static_always_inline void
dpdk_hqos_thread_internal_hqos_dbg_bypass (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;
  u32 thread_index = vm->thread_index;
  u32 dev_pos;

  dev_pos = 0;
  while (1)
    {
      vlib_worker_thread_barrier_check ();

      u32 n_devs = vec_len (dm->devices_by_hqos_cpu[thread_index]);
      if (PREDICT_FALSE (n_devs == 0))
	{
	  dev_pos = 0;
	  sleep (1);
	  continue;
	}
      if (dev_pos >= n_devs)
	dev_pos = 0;

      dpdk_device_and_queue_t *dq =
	vec_elt_at_index (dm->devices_by_hqos_cpu[thread_index], dev_pos);
      dpdk_device_t *xd = vec_elt_at_index (dm->devices, dq->device);

      dpdk_device_hqos_per_hqos_thread_t *hqos = xd->hqos_ht;
      u32 device_index = xd->port_id;
      u16 queue_id = dq->queue_id;

      struct rte_mbuf **pkts_enq = hqos->pkts_enq;
      u32 pkts_enq_len = hqos->pkts_enq_len;
      u32 swq_pos = hqos->swq_pos;
      u32 n_swq = vec_len (hqos->swq), i;
      u32 flush_count = hqos->flush_count;

      for (i = 0; i < n_swq; i++)
	{
	  /* Get current SWQ for this device */
	  struct rte_ring *swq = hqos->swq[swq_pos];

	  /* Read SWQ burst to packet buffer of this device */
	  pkts_enq_len += rte_ring_sc_dequeue_burst (swq,
						     (void **)
						     &pkts_enq[pkts_enq_len],
						     hqos->hqos_burst_enq, 0);

	  /* Get next SWQ for this device */
	  swq_pos++;
	  if (swq_pos >= n_swq)
	    swq_pos = 0;
	  hqos->swq_pos = swq_pos;

	  /* HWQ TX enqueue when burst available */
	  if (pkts_enq_len >= hqos->hqos_burst_enq)
	    {
	      u32 n_pkts = rte_eth_tx_burst (device_index,
					     (uint16_t) queue_id,
					     pkts_enq,
					     (uint16_t) pkts_enq_len);

	      for (; n_pkts < pkts_enq_len; n_pkts++)
		rte_pktmbuf_free (pkts_enq[n_pkts]);

	      pkts_enq_len = 0;
	      flush_count = 0;
	      break;
	    }
	}
      if (pkts_enq_len)
	{
	  flush_count++;
	  if (PREDICT_FALSE (flush_count == HQOS_FLUSH_COUNT_THRESHOLD))
	    {
	      rte_sched_port_enqueue (hqos->hqos, pkts_enq, pkts_enq_len);

	      pkts_enq_len = 0;
	      flush_count = 0;
	    }
	}
      hqos->pkts_enq_len = pkts_enq_len;
      hqos->flush_count = flush_count;

      /* Advance to next device */
      dev_pos++;
    }
}

static_always_inline void
dpdk_hqos_thread_internal (vlib_main_t * vm)
{
  dpdk_main_t *dm = &dpdk_main;
  u32 thread_index = vm->thread_index;
  u32 dev_pos;

  dev_pos = 0;
  while (1)
    {
      vlib_worker_thread_barrier_check ();

      u32 n_devs = vec_len (dm->devices_by_hqos_cpu[thread_index]);
      if (PREDICT_FALSE (n_devs == 0))
	{
	  dev_pos = 0;
	  sleep (1);
	  continue;
	}
      if (dev_pos >= n_devs)
	dev_pos = 0;

      dpdk_device_and_queue_t *dq =
	vec_elt_at_index (dm->devices_by_hqos_cpu[thread_index], dev_pos);
      dpdk_device_t *xd = vec_elt_at_index (dm->devices, dq->device);

      dpdk_device_hqos_per_hqos_thread_t *hqos = xd->hqos_ht;
      u32 device_index = xd->port_id;
      u16 queue_id = dq->queue_id;

      struct rte_mbuf **pkts_enq = hqos->pkts_enq;
      struct rte_mbuf **pkts_deq = hqos->pkts_deq;
      u32 pkts_enq_len = hqos->pkts_enq_len;
      u32 swq_pos = hqos->swq_pos;
      u32 n_swq = vec_len (hqos->swq), i;
      u32 flush_count = hqos->flush_count;

      /*
       * SWQ dequeue and HQoS enqueue for current device
       */
      for (i = 0; i < n_swq; i++)
	{
	  /* Get current SWQ for this device */
	  struct rte_ring *swq = hqos->swq[swq_pos];

	  /* Read SWQ burst to packet buffer of this device */
	  pkts_enq_len += rte_ring_sc_dequeue_burst (swq,
						     (void **)
						     &pkts_enq[pkts_enq_len],
						     hqos->hqos_burst_enq, 0);

	  /* Get next SWQ for this device */
	  swq_pos++;
	  if (swq_pos >= n_swq)
	    swq_pos = 0;
	  hqos->swq_pos = swq_pos;

	  /* HQoS enqueue when burst available */
	  if (pkts_enq_len >= hqos->hqos_burst_enq)
	    {
	      rte_sched_port_enqueue (hqos->hqos, pkts_enq, pkts_enq_len);

	      pkts_enq_len = 0;
	      flush_count = 0;
	      break;
	    }
	}
      if (pkts_enq_len)
	{
	  flush_count++;
	  if (PREDICT_FALSE (flush_count == HQOS_FLUSH_COUNT_THRESHOLD))
	    {
	      rte_sched_port_enqueue (hqos->hqos, pkts_enq, pkts_enq_len);

	      pkts_enq_len = 0;
	      flush_count = 0;
	    }
	}
      hqos->pkts_enq_len = pkts_enq_len;
      hqos->flush_count = flush_count;

      /*
       * HQoS dequeue and HWQ TX enqueue for current device
       */
      {
	u32 pkts_deq_len, n_pkts;

	pkts_deq_len = rte_sched_port_dequeue (hqos->hqos,
					       pkts_deq,
					       hqos->hqos_burst_deq);

	for (n_pkts = 0; n_pkts < pkts_deq_len;)
	  n_pkts += rte_eth_tx_burst (device_index,
				      (uint16_t) queue_id,
				      &pkts_deq[n_pkts],
				      (uint16_t) (pkts_deq_len - n_pkts));
      }

      /* Advance to next device */
      dev_pos++;
    }
}

void
dpdk_hqos_thread (vlib_worker_thread_t * w)
{
  vlib_main_t *vm;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vm = vlib_get_main ();

  ASSERT (vm->thread_index == vlib_get_thread_index ());

  clib_time_init (&vm->clib_time);
  clib_mem_set_heap (w->thread_mheap);

  /* Wait until the dpdk init sequence is complete */
  while (tm->worker_thread_release == 0)
    vlib_worker_thread_barrier_check ();

  if (DPDK_HQOS_DBG_BYPASS)
    dpdk_hqos_thread_internal_hqos_dbg_bypass (vm);
  else
    dpdk_hqos_thread_internal (vm);
}

void
dpdk_hqos_thread_fn (void *arg)
{
  vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
  vlib_worker_thread_init (w);
#ifdef FLEXIWAN_FIX /* call vlib_buffer_worker_init */
  {
    clib_error_t* vlib_buffer_worker_init (vlib_main_t * vm);
    vlib_main_t *vm;
    vm = vlib_get_main ();
    vlib_buffer_worker_init(vm);
  }
#endif /* FLEXIWAN_FIX call vlib_buffer_worker_init */
  dpdk_hqos_thread (w);
}

/* *INDENT-OFF* */
VLIB_REGISTER_THREAD (hqos_thread_reg, static) =
{
  .name = "hqos-threads",
  .short_name = "hqos-threads",
  .function = dpdk_hqos_thread_fn,
};
/* *INDENT-ON* */

/*
 * HQoS run-time code to be called by the worker threads
 */
#define BITFIELD(byte_array, slab_pos, slab_mask, slab_shr)     \
({                                                              \
  u64 slab = *((u64 *) &byte_array[slab_pos]);                  \
  u64 val = (rte_be_to_cpu_64(slab) & slab_mask) >> slab_shr;   \
  val;                                                          \
})


void
dpdk_hqos_metadata_set (dpdk_device_hqos_per_worker_thread_t * hqos,
			struct rte_sched_port * port,
			struct rte_mbuf **pkts, u32 n_pkts)
{
#ifdef FLEXIWAN_FEATURE /* acl_based_classification */
  /*
   * If hqos_field based classification is not set, then look if
   * classified-flag is set on the packet
   */
  if (PREDICT_TRUE((hqos->hqos_field0_slabmask == 0) &&
		   (hqos->hqos_field1_slabmask == 0) &&
		   (hqos->hqos_field2_slabmask == 0)))
    {
      vlib_buffer_t * b;
      struct rte_mbuf * pkt;
      u8 tc_q;
      u16 subport_id;
      u16 pipe_id;

      for (u32 i = 0; i < n_pkts; i++)
	{
	  pkt = pkts[i];
	  b = vlib_buffer_from_rte_mbuf (pkt);
	  if (b->flags & VNET_BUFFER_F_IS_CLASSIFIED)
	    {
	      /* 
	       * Classified packet : Make use of the marking 
	       * 
	       * Lookup hqos_tc_table to map the qos.bits to one of the
	       * scheduler class and queue. tc_q returns a 6 bit value with 2
	       * bits indicating the scheduler queue and 4 bits indicating the
	       * scheduler class
	       */
	      tc_q = hqos->hqos_tc_table[vnet_buffer2 (b)->qos.bits];
	    }
	  else
	    {
	      /* Unclassified packet : Use default class and queue */
	      tc_q = (RTE_SCHED_TRAFFIC_CLASS_BE << 2) |
		(RTE_SCHED_BE_QUEUES_PER_PIPE - 1);
	    }
	  /*
	   * DPDK HQoS uses buffer metadata(qos.id) as below:
	   * The lower 16 bits represent the pipe id and the higher 16 bits
	   * represent the subport id.
	   */
	  subport_id = vnet_buffer2 (b)->qos.id >> 16;
	  pipe_id = vnet_buffer2 (b)->qos.id & 0xFFFF;

	  rte_sched_port_pkt_write (port, pkt, subport_id, pipe_id,
				    (tc_q >> 2), (tc_q & 0x3), 0);

	  /* Reset QoS the identifier field */
	  vnet_buffer2 (b)->qos.id = 0;
	}
      return;
    }
#endif /* FLEXIWAN_FEATURE - acl_based_classification */

  u32 i;

  for (i = 0; i < (n_pkts & (~0x3)); i += 4)
    {
      struct rte_mbuf *pkt0 = pkts[i];
      struct rte_mbuf *pkt1 = pkts[i + 1];
      struct rte_mbuf *pkt2 = pkts[i + 2];
      struct rte_mbuf *pkt3 = pkts[i + 3];

      u8 *pkt0_data = rte_pktmbuf_mtod (pkt0, u8 *);
      u8 *pkt1_data = rte_pktmbuf_mtod (pkt1, u8 *);
      u8 *pkt2_data = rte_pktmbuf_mtod (pkt2, u8 *);
      u8 *pkt3_data = rte_pktmbuf_mtod (pkt3, u8 *);

      u64 pkt0_subport = BITFIELD (pkt0_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt0_pipe = BITFIELD (pkt0_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt0_tc_q = BITFIELD (pkt0_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      pkt0_tc_q = hqos->hqos_tc_table[pkt0_tc_q];

      u64 pkt1_subport = BITFIELD (pkt1_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt1_pipe = BITFIELD (pkt1_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt1_tc_q = BITFIELD (pkt1_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      pkt1_tc_q = hqos->hqos_tc_table[pkt1_tc_q];

      u64 pkt2_subport = BITFIELD (pkt2_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt2_pipe = BITFIELD (pkt2_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt2_tc_q = BITFIELD (pkt2_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      pkt2_tc_q = hqos->hqos_tc_table[pkt2_tc_q];

      u64 pkt3_subport = BITFIELD (pkt3_data, hqos->hqos_field0_slabpos,
				   hqos->hqos_field0_slabmask,
				   hqos->hqos_field0_slabshr);
      u64 pkt3_pipe = BITFIELD (pkt3_data, hqos->hqos_field1_slabpos,
				hqos->hqos_field1_slabmask,
				hqos->hqos_field1_slabshr);
      u64 pkt3_tc_q = BITFIELD (pkt3_data, hqos->hqos_field2_slabpos,
				hqos->hqos_field2_slabmask,
				hqos->hqos_field2_slabshr);
      pkt3_tc_q = hqos->hqos_tc_table[pkt3_tc_q];

      rte_sched_port_pkt_write (port, pkt0, pkt0_subport, pkt0_pipe,
				(pkt0_tc_q >> 2), (pkt0_tc_q & 0x3), 0);
      rte_sched_port_pkt_write (port, pkt1, pkt1_subport, pkt1_pipe,
				(pkt1_tc_q >> 2), (pkt1_tc_q & 0x3), 0);
      rte_sched_port_pkt_write (port, pkt2, pkt2_subport, pkt2_pipe,
				(pkt2_tc_q >> 2), (pkt2_tc_q & 0x3), 0);
      rte_sched_port_pkt_write (port, pkt3, pkt3_subport, pkt3_pipe,
				(pkt3_tc_q >> 2), (pkt3_tc_q & 0x3), 0);
    }

  for (; i < n_pkts; i++)
    {
      struct rte_mbuf *pkt = pkts[i];

      u8 *pkt_data = rte_pktmbuf_mtod (pkt, u8 *);

      u64 pkt_subport = BITFIELD (pkt_data, hqos->hqos_field0_slabpos,
				  hqos->hqos_field0_slabmask,
				  hqos->hqos_field0_slabshr);
      u64 pkt_pipe = BITFIELD (pkt_data, hqos->hqos_field1_slabpos,
			       hqos->hqos_field1_slabmask,
			       hqos->hqos_field1_slabshr);
      u64 pkt_tc_q = BITFIELD (pkt_data, hqos->hqos_field2_slabpos,
			       hqos->hqos_field2_slabmask,
			       hqos->hqos_field2_slabshr);

      /* Use TC table translation */
      pkt_tc_q = hqos->hqos_tc_table[pkt_tc_q];
      rte_sched_port_pkt_write (port, pkt, pkt_subport, pkt_pipe,
				(pkt_tc_q >> 2), (pkt_tc_q & 0x3), 0);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
