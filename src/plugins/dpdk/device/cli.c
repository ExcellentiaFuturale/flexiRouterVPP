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
 * List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *  - integrating_dpdk_qos_sched : The DPDK QoS scheduler integration in VPP is
 *    currently in deprecated state. It is likely deprecated as changes
 *    in DPDK scheduler APIs required corresponding changes from VPP side.
 *    The FlexiWAN commit makes the required corresponding changes and brings
 *    back the feature to working state. Additionaly made enhancements in the
 *    context of WAN QoS needs.
 */

#include <unistd.h>
#include <fcntl.h>

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/linux/sysfs.c>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/mpls/packet.h>

#include <dpdk/device/dpdk_priv.h>

/**
 * @file
 * @brief CLI for DPDK Abstraction Layer and pcap Tx Trace.
 *
 * This file contains the source code for CLI for DPDK
 * Abstraction Layer and pcap Tx Trace.
 */


static clib_error_t *
show_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, bm->buffer_pools)
  {
    struct rte_mempool *rmp = dpdk_mempool_by_buffer_pool_index[bp->index];
    if (rmp)
      {
	unsigned count = rte_mempool_avail_count (rmp);
	unsigned free_count = rte_mempool_in_use_count (rmp);

	vlib_cli_output (vm,
			 "name=\"%s\"  available = %7d allocated = %7d total = %7d\n",
			 rmp->name, (u32) count, (u32) free_count,
			 (u32) (count + free_count));
      }
    else
      {
	vlib_cli_output (vm, "rte_mempool is NULL (!)\n");
      }
  }
  return 0;
}

/*?
 * This command displays statistics of each DPDK mempool.
 *
 * @cliexpar
 * Example of how to display DPDK buffer data:
 * @cliexstart{show dpdk buffer}
 * name="mbuf_pool_socket0"  available =   15104 allocated =    1280 total =   16384
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_buffer,static) = {
    .path = "show dpdk buffer",
    .short_help = "show dpdk buffer",
    .function = show_dpdk_buffer,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
show_dpdk_physmem (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  clib_error_t *err = 0;
  u32 pipe_max_size;
  int fds[2];
  u8 *s = 0;
  int n, n_try;
  FILE *f;

  err = clib_sysfs_read ("/proc/sys/fs/pipe-max-size", "%u", &pipe_max_size);

  if (err)
    return err;

  if (pipe (fds) == -1)
    return clib_error_return_unix (0, "pipe");

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	(1024 + 7)
#endif

  if (fcntl (fds[1], F_SETPIPE_SZ, pipe_max_size) == -1)
    {
      err = clib_error_return_unix (0, "fcntl(F_SETPIPE_SZ)");
      goto error;
    }

  if (fcntl (fds[0], F_SETFL, O_NONBLOCK) == -1)
    {
      err = clib_error_return_unix (0, "fcntl(F_SETFL)");
      goto error;
    }

  if ((f = fdopen (fds[1], "a")) == 0)
    {
      err = clib_error_return_unix (0, "fdopen");
      goto error;
    }

  rte_dump_physmem_layout (f);
  fflush (f);

  n = n_try = 4096;
  while (n == n_try)
    {
      uword len = vec_len (s);
      vec_resize (s, len + n_try);

      n = read (fds[0], s + len, n_try);
      if (n < 0 && errno != EAGAIN)
	{
	  err = clib_error_return_unix (0, "read");
	  goto error;
	}
      _vec_len (s) = len + (n < 0 ? 0 : n);
    }

  vlib_cli_output (vm, "%v", s);

error:
  close (fds[0]);
  close (fds[1]);
  vec_free (s);
  return err;
}

/*?
 * This command displays DPDK physmem layout
 *
 * @cliexpar
 * Example of how to display DPDK physmem layout:
 * @cliexstart{show dpdk physmem}
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_physmem,static) = {
    .path = "show dpdk physmem",
    .short_help = "show dpdk physmem",
    .function = show_dpdk_physmem,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
test_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  static u32 *allocated_buffers;
  u32 n_alloc = 0;
  u32 n_free = 0;
  u32 first, actual_alloc;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "allocate %d", &n_alloc))
	;
      else if (unformat (input, "free %d", &n_free))
	;
      else
	break;
    }

  if (n_free)
    {
      if (vec_len (allocated_buffers) < n_free)
	return clib_error_return (0, "Can't free %d, only %d allocated",
				  n_free, vec_len (allocated_buffers));

      first = vec_len (allocated_buffers) - n_free;
      vlib_buffer_free (vm, allocated_buffers + first, n_free);
      _vec_len (allocated_buffers) = first;
    }
  if (n_alloc)
    {
      first = vec_len (allocated_buffers);
      vec_validate (allocated_buffers,
		    vec_len (allocated_buffers) + n_alloc - 1);

      actual_alloc = vlib_buffer_alloc (vm, allocated_buffers + first,
					n_alloc);
      _vec_len (allocated_buffers) = first + actual_alloc;

      if (actual_alloc < n_alloc)
	vlib_cli_output (vm, "WARNING: only allocated %d buffers",
			 actual_alloc);
    }

  vlib_cli_output (vm, "Currently %d buffers allocated",
		   vec_len (allocated_buffers));

  if (allocated_buffers && vec_len (allocated_buffers) == 0)
    vec_free (allocated_buffers);

  return 0;
}

/*?
 * This command tests the allocation and freeing of DPDK buffers.
 * If both '<em>allocate</em>' and '<em>free</em>' are entered on the
 * same command, the '<em>free</em>' is executed first. If no
 * parameters are provided, this command display how many DPDK buffers
 * the test command has allocated.
 *
 * @cliexpar
 * @parblock
 *
 * Example of how to display how many DPDK buffer test command has allocated:
 * @cliexstart{test dpdk buffer}
 * Currently 0 buffers allocated
 * @cliexend
 *
 * Example of how to allocate DPDK buffers using the test command:
 * @cliexstart{test dpdk buffer allocate 10}
 * Currently 10 buffers allocated
 * @cliexend
 *
 * Example of how to free DPDK buffers allocated by the test command:
 * @cliexstart{test dpdk buffer free 10}
 * Currently 0 buffers allocated
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_test_dpdk_buffer,static) = {
    .path = "test dpdk buffer",
    .short_help = "test dpdk buffer [allocate <nn>] [free <nn>]",
    .function = test_dpdk_buffer,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_desc (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 nb_rx_desc = (u32) ~ 0;
  u32 nb_tx_desc = (u32) ~ 0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "tx %d", &nb_tx_desc))
	;
      else if (unformat (line_input, "rx %d", &nb_rx_desc))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (hw_if_index == (u32) ~ 0)
    {
      error = clib_error_return (0, "please specify valid interface name");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if ((xd->flags & DPDK_DEVICE_FLAG_PMD) == 0)
    {
      error =
	clib_error_return (0,
			   "number of descriptors can be set only for "
			   "physical devices");
      goto done;
    }

  if ((nb_rx_desc == (u32) ~ 0 || nb_rx_desc == xd->nb_rx_desc) &&
      (nb_tx_desc == (u32) ~ 0 || nb_tx_desc == xd->nb_tx_desc))
    {
      error = clib_error_return (0, "nothing changed");
      goto done;
    }

  if (nb_rx_desc != (u32) ~ 0)
    xd->nb_rx_desc = nb_rx_desc;

  if (nb_tx_desc != (u32) ~ 0)
    xd->nb_tx_desc = nb_tx_desc;

  dpdk_device_setup (xd);

  if (vec_len (xd->errors))
    return clib_error_return (0, "%U", format_dpdk_device_errors, xd);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command sets the number of DPDK '<em>rx</em>' and
 * '<em>tx</em>' descriptors for the given physical interface. Use
 * the command '<em>show hardware-interface</em>' to display the
 * current descriptor allocation.
 *
 * @cliexpar
 * Example of how to set the DPDK interface descriptors:
 * @cliexcmd{set dpdk interface descriptors GigabitEthernet0/8/0 rx 512 tx 512}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_desc,static) = {
    .path = "set dpdk interface descriptors",
    .short_help = "set dpdk interface descriptors <interface> [rx <nn>] [tx <nn>]",
    .function = set_dpdk_if_desc,
};
/* *INDENT-ON* */


#ifdef FLEXIWAN_FEATURE /* integrating_dpdk_qos_sched */
static int
dpdk_device_queue_sort (void *a1, void *a2)
{
  dpdk_device_and_queue_t *dq1 = a1;
  dpdk_device_and_queue_t *dq2 = a2;

  if (dq1->device > dq2->device)
    return 1;
  else if (dq1->device < dq2->device)
    return -1;
  else if (dq1->queue_id > dq2->queue_id)
    return 1;
  else if (dq1->queue_id < dq2->queue_id)
    return -1;
  else
    return 0;
}


static clib_error_t *
show_dpdk_if_hqos_placement (vlib_main_t * vm, unformat_input_t * input,
                            vlib_cli_command_t * cmd)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_and_queue_t *dq;
  int cpu;

  if (tm->n_vlib_mains == 1)
    vlib_cli_output (vm, "All interfaces are handled by main thread");

  for (cpu = 0; cpu < vec_len (dm->devices_by_hqos_cpu); cpu++)
    {
      if (cpu >= dm->hqos_cpu_first_index &&
         cpu < (dm->hqos_cpu_first_index + dm->hqos_cpu_count))
       vlib_cli_output (vm, "Thread %u (%s at lcore %u):", cpu,
                        vlib_worker_threads[cpu].name,
                        vlib_worker_threads[cpu].cpu_id);

      vec_foreach (dq, dm->devices_by_hqos_cpu[cpu])
      {
       u32 hw_if_index = dm->devices[dq->device].hw_if_index;
       vnet_hw_interface_t *hi =
         vnet_get_hw_interface (dm->vnet_main, hw_if_index);
       vlib_cli_output (vm, "  %v queue %u", hi->name, dq->queue_id);
      }
    }
  return 0;
}

/*?
 * This command is used to display the thread and core each
 * DPDK output interface and HQoS queue is assigned too.
 *
 * @cliexpar
 * Example of how to display the DPDK output interface and HQoS queue placement:
 * @cliexstart{show dpdk interface hqos placement}
 * Thread 1 (vpp_hqos-threads_0 at lcore 3):
 *   GigabitEthernet0/8/0 queue 0
 * Thread 2 (vpp_hqos-threads_1 at lcore 4):
 *   GigabitEthernet0/9/0 queue 0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_if_hqos_placement, static) = {
  .path = "show dpdk interface hqos placement",
  .short_help = "show dpdk interface hqos placement",
  .function = show_dpdk_if_hqos_placement,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_placement (vlib_main_t * vm, unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_and_queue_t *dq;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 cpu = (u32) ~ 0;
  int i;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
         (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
          &hw_if_index))
       ;
      else if (unformat (line_input, "thread %d", &cpu))
       ;
      else
       {
         error = clib_error_return (0, "parse error: '%U'",
                                    format_unformat_error, line_input);
         goto done;
       }
    }

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  if (cpu < dm->hqos_cpu_first_index ||
      cpu >= (dm->hqos_cpu_first_index + dm->hqos_cpu_count))
    {
      error = clib_error_return (0, "please specify valid thread id");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  for (i = 0; i < vec_len (dm->devices_by_hqos_cpu); i++)
    {
      vec_foreach (dq, dm->devices_by_hqos_cpu[i])
      {
       if (hw_if_index == dm->devices[dq->device].hw_if_index)
         {
           if (cpu == i)       /* nothing to do */
             goto done;

           vec_del1 (dm->devices_by_hqos_cpu[i],
                     dq - dm->devices_by_hqos_cpu[i]);
           vec_add2 (dm->devices_by_hqos_cpu[cpu], dq, 1);
           dq->queue_id = 0;
           dq->device = xd->device_index;

           vec_sort_with_function (dm->devices_by_hqos_cpu[i],
                                   dpdk_device_queue_sort);

           vec_sort_with_function (dm->devices_by_hqos_cpu[cpu],
                                   dpdk_device_queue_sort);

           goto done;
         }
      }
    }

  error = clib_error_return (0, "not found");

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to assign a given DPDK output interface and
 * HQoS queue to a different thread. This will not create a thread,
 * so the thread must already exist. Use '<em>/etc/vpp/startup.conf</em>'
 * for the initial thread creation. See @ref qos_doc for more details.
 *
 * @cliexpar
 * Example of how to display the DPDK output interface and HQoS queue placement:
 * @cliexstart{show dpdk interface hqos placement}
 * Thread 1 (vpp_hqos-threads_0 at lcore 3):
 *   GigabitEthernet0/8/0 queue 0
 * Thread 2 (vpp_hqos-threads_1 at lcore 4):
 *   GigabitEthernet0/9/0 queue 0
 * @cliexend
 * Example of how to assign a DPDK output interface and HQoS queue to a thread:
 * @cliexcmd{set dpdk interface hqos placement GigabitEthernet0/8/0 thread 2}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_placement, static) = {
  .path = "set dpdk interface hqos placement",
  .short_help = "set dpdk interface hqos placement <interface> thread <n>",
  .function = set_dpdk_if_hqos_placement,
};
/* *INDENT-ON* */


static clib_error_t *
set_dpdk_if_hqos_pipe_profile (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  int i;

  u32 hw_if_index = ~0;
  u32 subport_id = ~0;
  u32 profile_id = ~0;
  clib_error_t *error = NULL;
  u32 tb_rate =  0;
  u32 tb_size =  0;
  u32 tc_rate[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
  u32 tc_period = 0;
  dpdk_device_config_t *devconf = NULL;
  u32 wrr_weights[RTE_SCHED_BE_QUEUES_PER_PIPE];
  struct rte_sched_pipe_params p;

  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      tc_rate[i] = 0;
    }
  for (i = 0; i < RTE_SCHED_BE_QUEUES_PER_PIPE; i++)
    {
      wrr_weights[i] = 0;
    }

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "subport %d", &subport_id))
	;
      else if (unformat (line_input, "profile %d", &profile_id))
	;
      else if (unformat (line_input, "rate %d", &tb_rate))
	;
      else if (unformat (line_input, "bktsize %d", &tb_size))
	;
      else if (unformat (line_input, "tc0-rate %d", &tc_rate[0]))
	;
      else if (unformat (line_input, "tc1-rate %d", &tc_rate[1]))
	;
      else if (unformat (line_input, "tc2-rate %d", &tc_rate[2]))
	;
      else if (unformat (line_input, "tc3-rate %d", &tc_rate[3]))
	;
      else if (unformat (line_input, "tc4-rate %d", &tc_rate[4]))
	;
      else if (unformat (line_input, "tc5-rate %d", &tc_rate[5]))
	;
      else if (unformat (line_input, "tc6-rate %d", &tc_rate[6]))
	;
      else if (unformat (line_input, "tc7-rate %d", &tc_rate[7]))
	;
      else if (unformat (line_input, "tc8-rate %d", &tc_rate[8]))
	;
      else if (unformat (line_input, "tc9-rate %d", &tc_rate[9]))
	;
      else if (unformat (line_input, "tc10-rate %d", &tc_rate[10]))
	;
      else if (unformat (line_input, "tc11-rate %d", &tc_rate[11]))
	;
      else if (unformat (line_input, "tc12-rate %d", &tc_rate[12]))
	;
      else if (unformat (line_input, "tc-period %d", &tc_period))
	;
      else if (unformat (line_input, "wrr0 %d", &wrr_weights[0]))
	;
      else if (unformat (line_input, "wrr1 %d", &wrr_weights[1]))
	;
      else if (unformat (line_input, "wrr2 %d", &wrr_weights[2]))
	;
      else if (unformat (line_input, "wrr3 %d", &wrr_weights[3]))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  error = dpdk_hqos_get_intf_context (hw_if_index, &xd, &devconf);
  if (error)
    {
      goto done;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      error = clib_error_return (0, "hqos not enabled on interface");
      goto done;
    }
  error = dpdk_hqos_get_pipe_profile (&devconf->hqos, subport_id,
				      profile_id, &p);
  if (error)
    {
      goto done;
    }

  // Update local structure with input values.
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
					profile_id, &p);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to create or change pipe profile parameters
 *
 * @cliexpar
 * Example of how to assign a new profile to a HQoS pipe:
 * @cliexcmd{set dpdk interface hqos pipe GigabitEthernet0/8/0 subport 0 pipe 2 profile 1 rate 1250000}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_pipe_profile, static) =
{
  .path = "set dpdk interface hqos pipe-profile",
  .short_help = "set dpdk interface hqos pipe-profile <interface>"
                 "subport <subport_id> profile <profile_id> "
                 "[rate <n>] [bktsize <n>] "
		 "[tc0-rate <n>] [tc1-rate <n>] ... [tc12-rate <n>] "
                 "[tc-period <n>] [wrr0 <n>] [wrr1 <n> [wrr2 <n>] [wrr3 <n>]",
  .function = set_dpdk_if_hqos_pipe_profile,
};
/* *INDENT-ON* */


static clib_error_t *
set_dpdk_if_hqos_pipe (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;

  u32 hw_if_index = ~0;
  u32 subport_id = ~0;
  u32 pipe_id = ~0;
  u32 profile_id = ~0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "subport %d", &subport_id))
	;
      else if (unformat (line_input, "pipe %d", &pipe_id))
	;
      else if (unformat (line_input, "profile %d", &profile_id))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  error = dpdk_hqos_get_intf_context (hw_if_index, &xd, &devconf);
  if (error)
    {
      goto done;
    }
  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      error = clib_error_return (0, "hqos not enabled on interface");
      goto done;
    }
  error = dpdk_hqos_setup_pipe (xd, &devconf->hqos, subport_id,
				pipe_id, profile_id);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to change the profile associate with a HQoS pipe. The
 * '<em><profile_id></em>' is zero based. Use the command
 * '<em>show dpdk interface hqos</em>' to display the content of each profile.
 * See @ref qos_doc for more details.
 *
 * @cliexpar
 * Example of how to assign a new profile to a HQoS pipe:
 * @cliexcmd{set dpdk interface hqos pipe GigabitEthernet0/8/0 subport 0 pipe 2 profile 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_pipe, static) =
{
  .path = "set dpdk interface hqos pipe",
  .short_help = "set dpdk interface hqos pipe <interface> subport <subport_id>"
                  "pipe <pipe_id> profile <profile_id>",
  .function = set_dpdk_if_hqos_pipe,
};
/* *INDENT-ON* */


static clib_error_t *
set_dpdk_if_hqos_subport_profile (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  int i;

  u32 hw_if_index = ~0;
  u32 profile_id = ~0;
  clib_error_t *error = NULL;
  u32 tb_rate = 0;
  u32 tb_size = 0;
  u32 tc_rate[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
  u32 tc_period = 0;
  struct rte_sched_subport_profile_params p;

  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      tc_rate[i] = 0;
    }

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "profile %d", &profile_id))
	;
      else if (unformat (line_input, "rate %d", &tb_rate))
	;
      else if (unformat (line_input, "bktsize %d", &tb_size))
	;
      else if (unformat (line_input, "tc0-rate %d", &tc_rate[0]))
	;
      else if (unformat (line_input, "tc1-rate %d", &tc_rate[1]))
	;
      else if (unformat (line_input, "tc2-rate %d", &tc_rate[2]))
	;
      else if (unformat (line_input, "tc3-rate %d", &tc_rate[3]))
	;
      else if (unformat (line_input, "tc4-rate %d", &tc_rate[4]))
	;
      else if (unformat (line_input, "tc5-rate %d", &tc_rate[5]))
	;
      else if (unformat (line_input, "tc6-rate %d", &tc_rate[6]))
	;
      else if (unformat (line_input, "tc7-rate %d", &tc_rate[7]))
	;
      else if (unformat (line_input, "tc8-rate %d", &tc_rate[8]))
	;
      else if (unformat (line_input, "tc9-rate %d", &tc_rate[9]))
	;
      else if (unformat (line_input, "tc10-rate %d", &tc_rate[10]))
	;
      else if (unformat (line_input, "tc11-rate %d", &tc_rate[11]))
	;
      else if (unformat (line_input, "tc12-rate %d", &tc_rate[12]))
	;
      else if (unformat (line_input, "tc-period %d", &tc_period))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  error = dpdk_hqos_get_intf_context (hw_if_index, &xd, &devconf);
  if (error)
    {
      goto done;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      error = clib_error_return (0, "hqos not enabled on interface");
      goto done;
    }
  error = dpdk_hqos_get_subport_profile (&devconf->hqos, profile_id, &p);
  if (error)
    {
      goto done;
    }

  // Update local structure with input values.
  if (tb_rate !=  0)
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
  // Apply changes.
  error = dpdk_hqos_setup_subport_profile (xd, &devconf->hqos, profile_id, &p);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to create or update an existing subport profile. The
 * profile params include  subport rate rate (bytes per second),
 * token bucket size (bytes), traffic class rates (bytes per second) and
 * token update period (Milliseconds).
 *
 * @cliexpar
 * Example of how modify the subport profile attributes  -set rate as 1GbE link:
 * @cliexcmd{set dpdk interface hqos subport-profile GigabitEthernet0/8/0 subport 0 profile 0 rate 125000000}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_subport_profile, static) = {
  .path = "set dpdk interface hqos subport-profile",
  .short_help = "set dpdk interface hqos subport-profile <interface> "
                 "profile <profile_id> "
                 "[rate <n>] [bktsize <n>] "
		 "[tc0-rate <n>] [tc1-rate <n>] ... [tc12-rate <n>] "
                 "[tc-period <n>]",
  .function = set_dpdk_if_hqos_subport_profile,
};
/* *INDENT-ON* */


static clib_error_t *
set_dpdk_if_hqos_subport (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  clib_error_t *error = NULL;

  u32 hw_if_index = ~0;
  u32 subport_id = ~0;
  u32 profile_id = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "subport %d", &subport_id))
	;
      else if (unformat (line_input, "profile %d", &profile_id))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  error = dpdk_hqos_get_intf_context (hw_if_index, &xd, &devconf);
  if (error == NULL)
    {
      goto done;
    }
  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      error = clib_error_return (0, "hqos not enabled on interface");
      goto done;
    }
  error = dpdk_hqos_setup_subport (xd, &devconf->hqos, subport_id, profile_id);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to create or update a subport. The configuration of the
 * subport will be set to the profile id provided in the input
 *
 * @cliexpar
 * Example of how modify the subport attributes for a 1GbE link:
 * @cliexcmd{set dpdk interface hqos subport GigabitEthernet0/8/0 subport 0 profile 0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_subport, static) = {
  .path = "set dpdk interface hqos subport",
  .short_help = "set dpdk interface hqos subport <interface>"
                  "subport <subport_id> profile <profile_id>",
  .function = set_dpdk_if_hqos_subport,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_tctbl (vlib_main_t * vm, unformat_input_t * input,
                       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  clib_error_t *error = NULL;
  u32 val, i;

  u32 hw_if_index = ~0;
  u32 tc = ~0;
  u32 queue = ~0;
  u32 entry = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "entry %d", &entry))
	;
      else if (unformat (line_input, "tc %d", &tc))
	;
      else if (unformat (line_input, "queue %d", &queue))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (entry >= 64)
    {
      error = clib_error_return (0, "invalid entry");
      goto done;
    }
  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
      error = clib_error_return (0, "invalid traffic class");
      goto done;
    }
  if (tc == RTE_SCHED_TRAFFIC_CLASS_BE)
    {
      if ((queue < 0) || (queue >= RTE_SCHED_BE_QUEUES_PER_PIPE))
	{
	  error = clib_error_return (0, "invalid traffic class queue");
	  goto done;
	}
    }
  else
    {
      if (queue != 0)
	{
	  error = clib_error_return (0, "invalid traffic class queue");
	  goto done;
	}
    }

  error = dpdk_hqos_get_intf_context (hw_if_index, &xd, NULL); 
  if (error)
    {
      goto done;
    }
  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      error = clib_error_return (0, "hqos not enabled on interface");
      goto done;
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

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to set the traffic class translation table. The
 * traffic class translation table is used to map 64 values (0-63) to one of
 * thirteen traffic class and a corresponding input queue. Use the '<em>show
 * dpdk interface hqos</em>' command to display the traffic class translation
 * table. See @ref qos_doc for more details.
 *
 * This command has the following parameters:
 *
 * - <b><interface></b> - Used to specify the output interface.
 *
 * - <b>entry <map_val></b> - Mapped value (0-63) to assign traffic class and queue to.
 *
 * - <b>tc <tc_id></b> - Traffic class (0-3) to be used by the provided mapped value.
 *
 * - <b>queue <queue_id></b> - HQoS input queue (0-3) to be used by the provided mapped value.
 *
 * @cliexpar
 * Example of how modify the traffic class translation table:
 * @cliexcmd{set dpdk interface hqos tctbl GigabitEthernet0/8/0 entry 16 tc 2 queue 2}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_tctbl, static) = {
  .path = "set dpdk interface hqos tctbl",
  .short_help = "set dpdk interface hqos tctbl <interface> entry <map_val>"
                   "tc <tc_id> queue <queue_id>",
  .function = set_dpdk_if_hqos_tctbl,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_pktfield (vlib_main_t * vm, unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_config_t *devconf;
  dpdk_device_t *xd;
  clib_error_t *error = NULL;
  u32 i;

  u32 hw_if_index = ~0;
  // Packet field configuration
  u32 id = ~0;
  u32 offset = 0;
  u64 mask = 0;

  // Parse input arguments
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "id subport"))
	id = 0;
      else if (unformat (line_input, "id pipe"))
	id = 1;
      else if (unformat (line_input, "id tc"))
	id = 2;
      else if (unformat (line_input, "id %d", &id))
	;
      else if (unformat (line_input, "offset %d", &offset))
	;
      else if (unformat (line_input, "mask %llx", &mask))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  error = dpdk_hqos_get_intf_context (hw_if_index, &xd, &devconf);
  if (error)
    {
      goto done;
    }

  if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
    {
      error = clib_error_return (0, "hqos not enabled on interface");
      goto done;
    }

  u32 n_subports_per_port = devconf->hqos.port_params.n_subports_per_port;
  u32 n_pipes_per_subport = devconf->hqos.port_params.n_pipes_per_subport;
  u32 tctbl_size = RTE_DIM (devconf->hqos.tc_table);

  // Validate packet field configuration: id, offset and mask
  if (id >= 3)
    {
      error = clib_error_return (0, "invalid packet field id");
      goto done;
    }

  switch (id)
    {
    case 0:
      if (mask && dpdk_hqos_validate_mask (mask, n_subports_per_port) != 0)
	{
	  error = clib_error_return (0, "invalid subport ID mask "
				     "(n_subports_per_port = %u)",
				     n_subports_per_port);
	  goto done;
	}
      break;
    case 1:
      if (mask && dpdk_hqos_validate_mask (mask, n_pipes_per_subport) != 0)
	{
	  error = clib_error_return (0, "invalid pipe ID mask "
				     "(n_pipes_per_subport = %u)",
				     n_pipes_per_subport);
	  goto done;
	}
      break;
    case 2:
    default:
      if (mask && dpdk_hqos_validate_mask (mask, tctbl_size) != 0)
	{
	  error = clib_error_return (0, "invalid TC table index mask "
				     "(TC table size = %u)", tctbl_size);
	  goto done;
	}
    }

  // Detect the set of worker threads
  u32 worker_thread_count, worker_thread_first;
  vlib_get_core_worker_count_and_first_index (&worker_thread_count,
                                              &worker_thread_first);

  // set value to all worker and main-thread-0 context
  dpdk_hqos_setup_pktfield (xd, id, offset, mask, 0);
  for (i = worker_thread_first;
       i < (worker_thread_first + worker_thread_count); i++)
    {
      dpdk_hqos_setup_pktfield (xd, id, offset, mask, i);
    }
done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to set the packet fields required for classifying the
 * incoming packet. As a result of classification process, packet field
 * information will be mapped to 5 tuples (subport, pipe, traffic class, pipe,
 * color) and stored in packet mbuf.
 *
 * This command has the following parameters:
 *
 * - <b><interface></b> - Used to specify the output interface.
 *
 * - <b>id subport|pipe|tc</b> - Classification occurs across three fields.
 * This parameter indicates which of the three masks are being configured. Legacy
 * code used 0-2 to represent these three fields, so 0-2 is still accepted.
 *   - <b>subport|0</b> - Currently only one subport is supported, so only
 * an empty mask is supported for the subport classification.
 *   - <b>pipe|1</b> - Currently, 4096 pipes per subport are supported, so a
 * 12-bit mask should be configure to map to the 0-4095 pipes.
 *   - <b>tc|2</b> - The translation table (see '<em>set dpdk interface hqos
 * tctbl</em>' command) maps each value (0-63) into one of the 4 traffic classes
 * per pipe. A 6-bit mask should be configure to map this field to a traffic class.
 *
 * - <b>offset <n></b> - Offset in the packet to apply the 64-bit mask for classification.
 * The offset should be on an 8-byte boundary (0,8,16,24..).
 *
 * - <b>mask <hex-mask></b> - 64-bit mask to apply to packet at the given '<em>offset</em>'.
 * Bits must be contiguous and should not include '<em>0x</em>'.
 *
 * The default values for the '<em>pktfield</em>' assumes Ethernet/IPv4/UDP packets with
 * no VLAN. Adjust based on expected packet format and desired classification field.
 * - '<em>subport</em>' is always empty (offset 0 mask 0000000000000000)
 * - By default, '<em>pipe</em>' maps to the UDP payload bits 12 .. 23 (offset 40
 * mask 0000000fff000000)
 * - By default, '<em>tc</em>' maps to the DSCP field in IP header (offset 48 mask
 * 00000000000000fc)
 *
 * @cliexpar
 * Example of how modify the '<em>pipe</em>' classification filter to match VLAN:
 * @cliexcmd{set dpdk interface hqos pktfield GigabitEthernet0/8/0 id pipe offset 8 mask 0000000000000FFF}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_pktfield, static) = {
  .path = "set dpdk interface hqos pktfield",
  .short_help = "set dpdk interface hqos pktfield <interface> "
    "id subport|pipe|tc offset <n> mask <hex-mask>",
  .function = set_dpdk_if_hqos_pktfield,
};
/* *INDENT-ON* */

static clib_error_t *
show_dpdk_if_hqos (vlib_main_t * vm, unformat_input_t * input,
                  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;
  clib_error_t *error = NULL;

  u32 subport_id, i;
  u32 hw_if_index = ~0;
  u32 *hw_if_indexes = NULL;
  dpdk_device_and_queue_t *dq;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      if (unformat (line_input, "%U", unformat_vnet_hw_interface,
                    dm->vnet_main, &hw_if_index))
	{
	  u32 *if_index;
	  for (u32 cpu = 0; cpu < vec_len (dm->devices_by_hqos_cpu); cpu++)
	    {
	      vec_foreach (dq, dm->devices_by_hqos_cpu[cpu])
		{
		  if (hw_if_index == dm->devices[dq->device].hw_if_index)
		    {
		      vec_add2 (hw_if_indexes, if_index, 1);
		      *if_index = hw_if_index;
		    }
		}
	    }
	}
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	}
      unformat_free (line_input);
      if (error)
	{
	  goto done;
	}
    }
  else
    {
      for (u32 cpu = 0; cpu < vec_len (dm->devices_by_hqos_cpu); cpu++)
	{
	  vec_foreach (dq, dm->devices_by_hqos_cpu[cpu])
	    {
	      u32 *if_index;
	      vec_add2 (hw_if_indexes, if_index, 1);
	      *if_index = dm->devices[dq->device].hw_if_index;
	    }
	}
    }

  u32 *if_index;
  vec_foreach (if_index, hw_if_indexes)
    {
      error = dpdk_hqos_get_intf_context (*if_index, &xd, &devconf);
      if (error)
	{
	  goto done;
	}
      if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
	{
	  error = clib_error_return (0, "hqos not enabled on interface");
	  goto done;
	}

      vnet_hw_interface_t *hi =
	vnet_get_hw_interface (dm->vnet_main, *if_index);
      vlib_cli_output (vm, "Interface  %v sw_if_index: %u",
		       hi->name, *if_index);
      dpdk_device_config_hqos_t *cfg = &devconf->hqos;
      dpdk_device_hqos_per_hqos_thread_t *ht = xd->hqos_ht;
      dpdk_device_hqos_per_worker_thread_t *wk = &xd->hqos_wt[0];
      u32 *tctbl = wk->hqos_tc_table;

      struct rte_sched_port_params * port_params = &cfg->port_params;
      struct rte_sched_subport_profile_params * subport_profiles =
	port_params->subport_profiles;
      struct rte_sched_subport_params * subport_params = cfg->subport_params;
      u32 * subport_profile_id_map = cfg->subport_profile_id_map;


      vlib_cli_output (vm, " Thread:");
      vlib_cli_output (vm, "   Input SWQ size = %u packets", cfg->swq_size);
      vlib_cli_output (vm, "   Enqueue burst size = %u packets",
		       ht->hqos_burst_enq);
      vlib_cli_output (vm, "   Dequeue burst size = %u packets",
		       ht->hqos_burst_deq);

      vlib_cli_output (vm,
		       "   Packet field 0: slab position = %4u, slab bitmask ="
		       " 0x%016llx   (subport)",
		       wk->hqos_field0_slabpos, wk->hqos_field0_slabmask);
      vlib_cli_output (vm,
		       "   Packet field 1: slab position = %4u, slab bitmask ="
		       " 0x%016llx   (pipe)",
		       wk->hqos_field1_slabpos, wk->hqos_field1_slabmask);
      vlib_cli_output (vm,
		       "   Packet field 2: slab position = %4u, slab bitmask ="
		       " 0x%016llx   (tc)",
		       wk->hqos_field2_slabpos, wk->hqos_field2_slabmask);
      vlib_cli_output (vm,
		       "   Packet field 2  tc translation table: "
		       "([Mapped Value Range]: tc/queue tc/queue ...)");
      for (i = 0; i < 8; i++)
	{
	  int idx = i * 8;
	  vlib_cli_output (vm,
			   "     [ %u .. %u]: "
			   "%u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u",
			   idx, idx + (8 - 1),
			   tctbl[idx] >> 2, tctbl[idx] & 0x3,
			   tctbl[idx + 1] >> 2, tctbl[idx + 1] & 0x3,
			   tctbl[idx + 2] >> 2, tctbl[idx + 2] & 0x3,
			   tctbl[idx + 3] >> 2, tctbl[idx + 3] & 0x3,
			   tctbl[idx + 4] >> 2, tctbl[idx + 4] & 0x3,
			   tctbl[idx + 5] >> 2, tctbl[idx + 5] & 0x3,
			   tctbl[idx + 6] >> 2, tctbl[idx + 6] & 0x3,
			   tctbl[idx + 7] >> 2, tctbl[idx + 7] & 0x3);
	}
      vlib_cli_output (vm, " Port:");
      vlib_cli_output (vm, "   Rate = %u bytes/second", port_params->rate);
      vlib_cli_output (vm, "   MTU = %u bytes", port_params->mtu);
      vlib_cli_output (vm, "   Frame overhead = %u bytes",
		       port_params->frame_overhead);
      vlib_cli_output (vm, "   Max number of subports = %u",
		       port_params->n_subports_per_port);
      vlib_cli_output (vm, "   Max number of pipes per subport = %u",
		       port_params->n_pipes_per_subport);
      vlib_cli_output (vm, "   Max number of subport profiles = %u",
		       port_params->n_max_subport_profiles);
      vlib_cli_output (vm, "   Configured number of subport profiles = %u",
		       port_params->n_subport_profiles);

      for (subport_id = 0; subport_id < vec_len (subport_params); subport_id++)
	{
	  u32 subport_profile_id = subport_profile_id_map[subport_id];
	  vlib_cli_output (vm, " Subport %u: (Profile id: %u)", subport_id,
			   subport_profile_id);
	  vlib_cli_output (vm, "   Rate = %u bytes/second",
			   subport_profiles[subport_profile_id].tb_rate);
	  vlib_cli_output (vm, "   Token bucket size = %u bytes",
			   subport_profiles[subport_profile_id].tb_size);

	  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
	    {
#ifdef RTE_SCHED_RED
	      struct rte_red_params * red_params =
		&subport_params[subport_id].red_params[i][0];
#endif
	      vlib_cli_output (vm,
			       "   Traffic class rate: TC[%u] ="
			       " %u bytes/second ", i,
			       subport_profiles[subport_profile_id].tc_rate[i]);
	      vlib_cli_output (vm,
			       "     Packet queue size: TC[%u] = %u packets",
			       i, subport_params[subport_id].qsize[i]);

#ifdef RTE_SCHED_RED
	      vlib_cli_output (vm, "     Weighted Random Early Detection"
			       " (WRED):");
	      vlib_cli_output (vm, "     TC%u min: G = %u, Y = %u, R = %u", i,
			       red_params[RTE_COLOR_GREEN].min_th,
			       red_params[RTE_COLOR_YELLOW].min_th,
			       red_params[RTE_COLOR_RED].min_th);

	      vlib_cli_output (vm, "     TC%u max: G = %u, Y = %u, R = %u", i,
			       red_params[RTE_COLOR_GREEN].max_th,
			       red_params[RTE_COLOR_YELLOW].max_th,
			       red_params[RTE_COLOR_RED].max_th);

	      vlib_cli_output (vm,
			       "     TC%u inv probability:"
			       " G = %u, Y = %u, R = %u",
			       i,
			       red_params[RTE_COLOR_GREEN].maxp_inv,
			       red_params[RTE_COLOR_YELLOW].maxp_inv,
			       red_params[RTE_COLOR_RED].maxp_inv);

	      vlib_cli_output (vm, "     TC%u weight: R = %u, Y = %u, R = %u", i,
			       red_params[RTE_COLOR_GREEN].wq_log2,
			       red_params[RTE_COLOR_YELLOW].wq_log2,
			       red_params[RTE_COLOR_RED].wq_log2);
#endif
	    }
	  vlib_cli_output (vm, "   TC period = %u milliseconds",
			   subport_profiles[subport_profile_id].tc_period);
	  vlib_cli_output (vm, "   Max number of pipes = %u",
			   subport_params[subport_id].\
			   n_pipes_per_subport_enabled);
	  vlib_cli_output (vm, "   Max number of pipe profiles = %u",
			   subport_params[subport_id].n_max_pipe_profiles);
	  vlib_cli_output (vm, "   Configured number of pipe profiles = %u",
			   subport_params[subport_id].n_pipe_profiles);

	  for (int pipe_id = 0; pipe_id < cfg->pipes[subport_id]; pipe_id++)
	    {
	      u32 pipe_profile_id =
		cfg->pipe_profile_id_map[subport_id][pipe_id];
	      struct rte_sched_pipe_params * pipe_profiles =
		subport_params[subport_id].pipe_profiles;

	      vlib_cli_output (vm, " Pipe %u: (Profile id: %u)", pipe_id,
			       pipe_profile_id);
	      vlib_cli_output (vm, "   Rate = %u bytes/second",
			       pipe_profiles[pipe_profile_id].tb_rate);
	      vlib_cli_output (vm, "   Token bucket size = %u bytes",
			       pipe_profiles[pipe_profile_id].tb_size);
	      vlib_cli_output (vm, "   TC period = %u milliseconds",
			       pipe_profiles[pipe_profile_id].tc_period);
#ifdef RTE_SCHED_SUBPORT_TC_OV
	      vlib_cli_output (vm, "   TC oversubscription_weight = %u",
			       pipe_profiles[pipe_profile_id].tc_ov_weight);
#endif
	      for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		{
		  vlib_cli_output (vm,
				   "   Traffic class rate: TC[%u] = %u "
				   "bytes/second", i,
				   pipe_profiles[pipe_profile_id].tc_rate[i]);
		}
	      vlib_cli_output (vm,
			       "   Best Effort TC WRR weights: Q0 = %u, "
			       "Q1 = %u, Q2 = %u, Q3 = %u",
			       pipe_profiles[pipe_profile_id].wrr_weights[0],
			       pipe_profiles[pipe_profile_id].wrr_weights[1],
			       pipe_profiles[pipe_profile_id].wrr_weights[2],
			       pipe_profiles[pipe_profile_id].wrr_weights[3]);
	    }
	}
      vlib_cli_output (vm, "================================================"
		       "================================");
    }
done:
  vec_free (hw_if_indexes);

  return error;
}

/*?
 * This command is used to display details of an output interface's HQoS
 * settings.
 *
 * @cliexpar
 * Example of how to display HQoS settings for an interfaces:
 * @cliexstart{show dpdk interface hqos GigabitEthernet0/8/0}
 *  Thread:
 *    Input SWQ size = 4096 packets
 *    Enqueue burst size = 256 packets
 *    Dequeue burst size = 220 packets
 *    Packet field 0: slab position =    0, slab bitmask = 0x0000000000000000   (subport)
 *    Packet field 1: slab position =   40, slab bitmask = 0x0000000fff000000   (pipe)
 *    Packet field 2: slab position =    8, slab bitmask = 0x00000000000000fc   (tc)
 *    Packet field 2  tc translation table: ([Mapped Value Range]: tc/queue tc/queue ...)
 *      [ 0 .. 15]: 0/0 1/0 2/0 3/0 4/0 5/0 6/0 7/0 8/0 9/0 10/0 11/0 12/0 12/1 12/2 12/3
 *      [16 .. 31]: 0/0 1/0 2/0 3/0 4/0 5/0 6/0 7/0 8/0 9/0 10/0 11/0 12/0 12/1 12/2 12/3
 *      [32 .. 47]: 0/0 1/0 2/0 3/0 4/0 5/0 6/0 7/0 8/0 9/0 10/0 11/0 12/0 12/1 12/2 12/3
 *      [48 .. 63]: 0/0 1/0 2/0 3/0 4/0 5/0 6/0 7/0 8/0 9/0 10/0 11/0 12/0 12/1 12/2 12/3
 *  Port:
 *    Rate = 1250000000 bytes/second
 *    MTU = 1514 bytes
 *    Frame overhead = 24 bytes
 *    Number of subports = 1
 *    Number of pipes per subport = 4096
 *    Packet queue size: TC0 = 64, TC1 = 64, TC2 = 64, TC3 = 64 packets
 *    Number of pipe profiles = 2
 *  Subport 0:
 *    Rate = 1250000000 bytes/second
 *    Token bucket size = 1000000 bytes
 *    Traffic class rate: TC0 = 1250000000, TC1 = 1250000000, TC2 = 1250000000, TC3 = 1250000000 bytes/second
 *    TC period = 10 milliseconds
 *  Pipe profile 0:
 *    Rate = 305175 bytes/second
 *    Token bucket size = 1000000 bytes
 *    Traffic class rate: TC0 = 305175, TC1 = 305175, TC2 = 305175, TC3 = 305175 bytes/second
 *    TC period = 40 milliseconds
 *    TC0 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 *    TC1 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 *    TC2 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 *    TC3 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_if_hqos, static) = {
  .path = "show dpdk interface hqos",
  .short_help = "show dpdk interface hqos <interface>",
  .function = show_dpdk_if_hqos,
};

/* *INDENT-ON* */

static clib_error_t *
print_hqos_queue_stats (vlib_main_t *vm, dpdk_device_t *xd,
			dpdk_device_config_hqos_t *hqos, u32 subport_id,
			u32 pipe_id, u32 tc, u32 tc_q,
			struct rte_sched_queue_stats *stats)
{
  clib_error_t *error = dpdk_hqos_get_queue_stats (xd, hqos, subport_id,
						   pipe_id, tc, tc_q, stats);
  if (error == NULL)
    {
      vlib_cli_output (vm, "%-24s%-16s", "Stats Parameter", "Value");
      vlib_cli_output (vm, "%-24s%-16d", "Packets", stats->n_pkts);
      vlib_cli_output (vm, "%-24s%-16d", "Packets dropped",
		       stats->n_pkts_dropped);
#ifdef RTE_SCHED_RED
      vlib_cli_output (vm, "%-24s%-16d", "Packets dropped (RED)",
		       stats->n_pkts_red_dropped);
#endif
      vlib_cli_output (vm, "%-24s%-16d", "Bytes", stats->n_bytes);
      vlib_cli_output (vm, "%-24s%-16d", "Bytes dropped",
		       stats->n_bytes_dropped);
    }
  return error;
}

static clib_error_t *
show_dpdk_hqos_queue_stats (vlib_main_t * vm, unformat_input_t * input,
                           vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
#ifdef RTE_SCHED_COLLECT_STATS
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  dpdk_device_config_t *devconf;

  u32 hw_if_index = ~0;
  u32 subport_id = ~0;
  u32 pipe_id = ~0;
  u32 tc = ~0;
  u32 tc_q = ~0;
  struct rte_sched_queue_stats stats;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat
	      (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	       &hw_if_index))
	    ;
	  else if (unformat (line_input, "subport %d", &subport_id))
	    ;
	  else if (unformat (line_input, "pipe %d", &pipe_id))
	    ;
	  else if (unformat (line_input, "tc %d", &tc))
	    ;
	  else if (unformat (line_input, "tc_q %d", &tc_q))
	    ;
	  else
	    {
	      error = clib_error_return (0, "parse error: '%U'",
					 format_unformat_error, line_input);
	      goto free_input;
	    }
	}

      error = dpdk_hqos_get_intf_context (hw_if_index, &xd, &devconf);
      if (error)
	{
	  goto free_input;
	}
      if ((xd->flags & DPDK_DEVICE_FLAG_HQOS) == 0)
	{
	  error = clib_error_return (0, "hqos not enabled on interface");
	  goto free_input;
	}

      error = print_hqos_queue_stats (vm, xd, &devconf->hqos, subport_id,
				      pipe_id, tc, tc_q, &stats);

free_input:
      unformat_free (line_input);
      return error;
    }
  // Print all queue stats
  for (u32 cpu = 0; cpu < vec_len (dm->devices_by_hqos_cpu); cpu++)
    {
      dpdk_device_and_queue_t *dq;
      vec_foreach (dq, dm->devices_by_hqos_cpu[cpu])
	{
	  hw_if_index = dm->devices[dq->device].hw_if_index;
	  error = dpdk_hqos_get_intf_context (hw_if_index, &xd, &devconf);
	  if (error)
	    {
	      goto done;
	    }
	  vnet_hw_interface_t *hi = vnet_get_hw_interface (dm->vnet_main,
							   hw_if_index);
	  vlib_cli_output (vm, "=========================================");
	  vlib_cli_output (vm, "Interface: %v", hi->name);
	  vlib_cli_output (vm, "=========================================");
	  dpdk_device_config_hqos_t * hqos = &devconf->hqos;
	  for (subport_id = 0;
	       subport_id < vec_len (hqos->subport_params); subport_id++)
	    {
	      vlib_cli_output (vm, "-----------------------------------------");
	      vlib_cli_output (vm, "Subport: %u", subport_id);
	      vlib_cli_output (vm, "-----------------------------------------");
	      for (int pipe_id = 0;
		   pipe_id < hqos->pipes[subport_id]; pipe_id++)
		{
		  vlib_cli_output
		    (vm, ".........................................");
		  vlib_cli_output (vm, "Pipe: %u", pipe_id);
		  vlib_cli_output
		    (vm, ".........................................");
		  for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++)
		    {
		      if (tc != RTE_SCHED_TRAFFIC_CLASS_BE)
			{
			  // Priority class
			  vlib_cli_output (vm, "TC: %u Queue: %u", tc, 0);
			  error = print_hqos_queue_stats
			    (vm, xd, hqos, subport_id, pipe_id, tc, 0, &stats);
			  if (error)
			    {
			      goto done;
			    }
			  continue;
			}
		      // Best Effort class
		      for (tc_q =0; tc_q < RTE_SCHED_BE_QUEUES_PER_PIPE; tc_q++)
			{
			  vlib_cli_output(vm, "TC: %u Queue: %u", tc, tc_q);
			  error = print_hqos_queue_stats
			    (vm, xd, hqos, subport_id, pipe_id, tc,
			     tc_q, &stats);
			  if (error)
			    {
			      goto done;
			    }
			}
		    }
		}
	    }
	}
    }
#else
  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      return 0;
    }

  vlib_cli_output (vm, "RTE_SCHED_COLLECT_STATS disabled in DPDK");
  unformat_free (line_input);
#endif

done:
  return error;
}

/*?
 * This command is used to display statistics associated with a HQoS traffic class
 * queue.
 *
 * @note
 * Statistic collection by the scheduler is disabled by default in DPDK. In order to
 * turn it on, add the following line to '<em>../vpp/dpdk/Makefile</em>':
 * - <b>$(call set,RTE_SCHED_COLLECT_STATS,y)</b>
 *
 * @cliexpar
 * Example of how to display statistics of HQoS a HQoS traffic class queue:
 * @cliexstart{show dpdk hqos queue GigabitEthernet0/9/0 subport 0 pipe 3181 tc 0 tc_q 0}
 *      Stats Parameter          Value
 *          Packets               140
 *      Packets dropped            0
 *           Bytes               8400
 *       Bytes dropped             0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_hqos_queue_stats, static) = {
  .path = "show dpdk hqos queue",
  .short_help = "show dpdk hqos queue <interface> subport <subport_id>"
                   "pipe <pipe_id> tc <tc_id> tc_q <queue_id>",
  .function = show_dpdk_hqos_queue_stats,
};
/* *INDENT-ON* */

#endif /* FLEXIWAN_FEATURE - integrating_dpdk_qos_sched */ 

static clib_error_t *
show_dpdk_version_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
#define _(a,b,c) vlib_cli_output (vm, "%-25s " b, a ":", c);
  _("DPDK Version", "%s", rte_version ());
  _("DPDK EAL init args", "%s", dpdk_config_main.eal_init_args_str);
#undef _
  return 0;
}

/*?
 * This command is used to display the current DPDK version and
 * the list of arguments passed to DPDK when started.
 *
 * @cliexpar
 * Example of how to display how many DPDK buffer test command has allocated:
 * @cliexstart{show dpdk version}
 * DPDK Version:        DPDK 16.11.0
 * DPDK EAL init args:  -c 1 -n 4 --huge-dir /run/vpp/hugepages --file-prefix vpp -w 0000:00:08.0 -w 0000:00:09.0 --master-lcore 0 --socket-mem 256
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vpe_version_command, static) = {
  .path = "show dpdk version",
  .short_help = "show dpdk version",
  .function = show_dpdk_version_command_fn,
};
/* *INDENT-ON* */

/* Dummy function to get us linked in. */
void
dpdk_cli_reference (void)
{
}

clib_error_t *
dpdk_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dpdk_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
