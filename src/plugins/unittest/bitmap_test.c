/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 *  List of features made for FlexiWAN (denoted by FLEXIWAN_FEATURE flag):
 *
 *   - configurable_anti_replay_window_len : Add support to make the
 *     anti-replay check window configurable. A higher anti replay window
 *     length is needed in systems where packet reordering is expected due to
 *     features like QoS. A low window length can lead to the wrong dropping of
 *     out-of-order packets that are outside the window as replayed packets.
 */

#include <vlib/vlib.h>
#include <vppinfra/bitmap.h>

static clib_error_t *
test_bitmap_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u64 *bm = 0;
  u64 *bm2 = 0;
  u64 *dup;
  uword junk;

  bm = clib_bitmap_set_multiple (bm, 2, ~0ULL, BITS (uword));

  junk = clib_bitmap_next_clear (bm, 3);
  junk = clib_bitmap_next_clear (bm, 65);

  bm2 = clib_bitmap_set_multiple (bm2, 0, ~0ULL, BITS (uword));
  _vec_len (bm2) = 1;
  junk = clib_bitmap_next_clear (bm2, 0);


  bm = clib_bitmap_set_multiple (bm, 2, ~0ULL, BITS (uword) - 3);
  junk = clib_bitmap_get_multiple (bm, 2, BITS (uword));
  junk = clib_bitmap_first_set (bm);
  junk = 1 << 3;
  bm = clib_bitmap_xori (bm, junk);
  bm = clib_bitmap_andi (bm, junk);
  bm = clib_bitmap_xori_notrim (bm, junk);
  bm = clib_bitmap_andi_notrim (bm, junk);

  bm = clib_bitmap_set_multiple (bm, 2, ~0ULL, BITS (uword) - 3);
  bm2 = clib_bitmap_set_multiple (bm2, 2, ~0ULL, BITS (uword) - 3);

  dup = clib_bitmap_dup_and (bm, bm2);
  vec_free (dup);
  dup = clib_bitmap_dup_andnot (bm, bm2);
  vec_free (dup);
  vec_free (bm);
  vec_free (bm2);

#ifdef FLEXIWAN_FEATURE /* configurable_anti_replay_window_len */
  /* Tests to validate the newly added bitmap left shift API */
  clib_bitmap_alloc (bm, 256);
  clib_bitmap_alloc (bm2, 256);
  if (clib_bitmap_is_zero (bm))
    vlib_cli_output (vm, "Test 1 : PASS : Bitmap alloc initialized to zero");
  else
    vlib_cli_output (vm, "Test 1 : FAIL : Bitmap alloc initialized to zero");

  bm = clib_bitmap_set_multiple (bm, 63, ~0ULL, BITS (uword));
  clib_bitmap_shift_left (bm, 256);
  if (clib_bitmap_is_zero (bm))
    vlib_cli_output (vm, "Test 2 : PASS : Bitmap shift left by bitmap size");
  else
    vlib_cli_output (vm, "Test 2 : FAIL : Bitmap shift left by bitmap size");

  clib_bitmap_zero (bm);
  clib_bitmap_zero (bm2);
  bm = clib_bitmap_set_multiple (bm, 63, ~0ULL, BITS (uword));
  bm2 = clib_bitmap_set_multiple (bm2, 63, ~0ULL, BITS (uword));
  clib_bitmap_shift_left (bm, 0);
  if (clib_bitmap_is_equal (bm, bm2))
    vlib_cli_output (vm, "Test 3 : PASS : Bitmap shift left by 0");
  else
    vlib_cli_output (vm, "Test 3 : FAIL : Bitmap shift left by 0");

  clib_bitmap_zero (bm);
  clib_bitmap_zero (bm2);
  clib_bitmap_set (bm, 63, 1);
  clib_bitmap_set (bm2, 64, 1);
  clib_bitmap_shift_left (bm, 1);
  if (clib_bitmap_is_equal (bm, bm2))
    vlib_cli_output (vm, "Test 4 : PASS : Bitmap shift left by 1");
  else
    vlib_cli_output (vm, "Test 4 : FAIL : Bitmap shift left by 1");

  clib_bitmap_zero (bm);
  clib_bitmap_zero (bm2);
  clib_bitmap_set (bm, 64, 1);
  clib_bitmap_shift_left (bm, 10);
  clib_bitmap_set (bm2, 74, 10);
  if (clib_bitmap_is_equal (bm, bm2))
    vlib_cli_output (vm, "Test 5 : PASS : Bitmap shift left by 10");
  else
    vlib_cli_output (vm, "Test 5 : FAIL : Bitmap shift left by 10");

  clib_bitmap_free (bm);
  clib_bitmap_free (bm2);
#endif /* FLEXIWAN_FEATURE - configurable_anti_replay_window_len */

  return 0;
}



/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_bihash_command, static) =
{
  .path = "test bitmap",
  .short_help = "Coverage test for bitmap.h",
  .function = test_bitmap_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
