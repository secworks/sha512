//======================================================================
//
// tb_sha512_core.v
// ----------------
// Testbench for the SHA-512 core.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2013, Secworks Sweden AB
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or 
// without modification, are permitted provided that the following 
// conditions are met: 
// 
// 1. Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer. 
// 
// 2. Redistributions in binary form must reproduce the above copyright 
//    notice, this list of conditions and the following disclaimer in 
//    the documentation and/or other materials provided with the 
//    distribution. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

//------------------------------------------------------------------
// Simulator directives.
//------------------------------------------------------------------
`timescale 1ns/10ps


//------------------------------------------------------------------
// Test module.
//------------------------------------------------------------------
module tb_sha512_core();
  
  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter DEBUG = 1;

  parameter CLK_PERIOD      = 2;
  parameter CLK_HALF_PERIOD = CLK_PERIOD / 2;

  parameter MODE_SHA_512_224 = 0;
  parameter MODE_SHA_512_256 = 1;
  parameter MODE_SHA_384     = 2;
  parameter MODE_SHA_512     = 3;
  
  
  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0] cycle_ctr;
  reg [31 : 0] error_ctr;
  reg [31 : 0] tc_ctr;

  reg            tb_clk;
  reg            tb_reset_n;
  reg            tb_init;
  reg            tb_next;
  reg    [1 : 0] tb_mode;
  reg [1023 : 0] tb_block;
  wire           tb_ready;
  wire [511 : 0] tb_digest;
  wire           tb_digest_valid;
  
  
  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  sha512_core dut(
                   .clk(tb_clk),
                   .reset_n(tb_reset_n),
                 
                   .init(tb_init),
                   .next(tb_next),
                   .mode(tb_mode),

                   .block(tb_block),
                   
                   .ready(tb_ready),
                   
                   .digest(tb_digest),
                   .digest_valid(tb_digest_valid)
                 );
  

  //----------------------------------------------------------------
  // clk_gen
  //
  // Always running clock generator process.
  //----------------------------------------------------------------
  always 
    begin : clk_gen
      #CLK_HALF_PERIOD;
      tb_clk = !tb_clk;
    end // clk_gen
    

  //----------------------------------------------------------------
  // sys_monitor()
  //
  // An always running process that creates a cycle counter and
  // conditionally displays information about the DUT.
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      cycle_ctr = cycle_ctr + 1;
      #(CLK_PERIOD);
      if (DEBUG)
        begin
          dump_dut_state();
        end
    end

  
  //----------------------------------------------------------------
  // dump_dut_state()
  //
  // Dump the state of the dump when needed.
  //----------------------------------------------------------------
  task dump_dut_state();
    begin
      $display("State of DUT");
      $display("------------");
      $display("Inputs and outputs:");
      $display("init   = 0x%01x, next  = 0x%01x. mode = 0x%01x", 
               dut.init, dut.next, dut.mode);
      $display("block  = 0x%0128x", dut.block);

      $display("ready  = 0x%01x, valid = 0x%01x", 
               dut.ready, dut.digest_valid);
      $display("digest = 0x%064x", dut.digest);
      $display("H0_reg = 0x%08x, H1_reg = 0x%08x, H2_reg = 0x%08x, H3_reg = 0x%08x", 
               dut.H0_reg, dut.H1_reg, dut.H2_reg, dut.H3_reg);
      $display("H4_reg = 0x%08x, H5_reg = 0x%08x, H6_reg = 0x%08x, H7_reg = 0x%08x", 
               dut.H4_reg, dut.H5_reg, dut.H6_reg, dut.H7_reg);
      $display("");
      
      $display("Control signals and counter:");
      $display("sha512_ctrl_reg = 0x%02x", dut.sha512_ctrl_reg);
      $display("digest_init     = 0x%01x, digest_update = 0x%01x", 
               dut.digest_init, dut.digest_update);
      $display("state_init      = 0x%01x, state_update  = 0x%01x", 
               dut.state_init, dut.state_update);
      $display("first_block     = 0x%01x, ready_flag    = 0x%01x, w_init    = 0x%01x", 
               dut.first_block, dut.ready_flag, dut.w_init);
      $display("t_ctr_inc       = 0x%01x, t_ctr_rst     = 0x%01x, t_ctr_reg = 0x%02x", 
               dut.t_ctr_inc, dut.t_ctr_rst, dut.t_ctr_reg);
      $display("");

      $display("State registers:");
      $display("a_reg = 0x%08x, b_reg = 0x%08x, c_reg = 0x%08x, d_reg = 0x%08x", 
               dut.a_reg, dut.b_reg, dut.c_reg, dut.d_reg);
      $display("e_reg = 0x%08x, f_reg = 0x%08x, g_reg = 0x%08x, h_reg = 0x%08x", 
               dut.e_reg, dut.f_reg, dut.g_reg, dut.h_reg);
      $display("");
      $display("a_new = 0x%08x, b_new = 0x%08x, c_new = 0x%08x, d_new = 0x%08x", 
               dut.a_new, dut.b_new, dut.c_new, dut.d_new);
      $display("e_new = 0x%08x, f_new = 0x%08x, g_new = 0x%08x, h_new = 0x%08x", 
               dut.e_new, dut.f_new, dut.g_new, dut.h_new);
      $display("");

      $display("State update values:");
      $display("w  = 0x%08x, k  = 0x%08x", dut.w_data, dut.k_data);
      $display("t1 = 0x%08x, t2 = 0x%08x", dut.t1, dut.t2);
      $display("");
    end
  endtask // dump_dut_state
  
  
  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggle reset to put the DUT into a well known state.
  //----------------------------------------------------------------
  task reset_dut();
    begin
      $display("*** Toggle reset.");
      tb_reset_n = 0;
      #(2 * CLK_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut

  
  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim();
    begin
      cycle_ctr = 0;
      error_ctr = 0;
      tc_ctr = 0;
      
      tb_clk = 0;
      tb_reset_n = 1;

      tb_init = 0;
      tb_next = 0;
      tb_next = 2'b00;
      tb_mode = 2'b00;
      tb_block = {32{32'h00000000}};
    end
  endtask // init_dut

  
  //----------------------------------------------------------------
  // display_test_result()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_result();
    begin
      if (error_ctr == 0)
        begin
          $display("*** All %02d test cases completed successfully", tc_ctr);
        end
      else
        begin
          $display("*** %02d test cases did not complete successfully.", error_ctr);
        end
    end
  endtask // display_test_result
  

  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag in the dut to be set.
  //
  // Note: It is the callers responsibility to call the function
  // when the dut is actively processing and will in fact at some
  // point set the flag.
  //----------------------------------------------------------------
  task wait_ready();
    begin
      while (!tb_ready)
        begin
          #(2 * CLK_PERIOD);
        end
    end
  endtask // wait_ready

  
  //----------------------------------------------------------------
  // single_block_test()
  //
  // Run a test case spanning a single data block.
  //----------------------------------------------------------------
  task single_block_test(input [7 : 0]    tc_number,
                         input [1 : 0]    mode,
                         input [1023 : 0] block,
                         input [511 : 0]  expected);
   begin
     $display("*** TC %0d single block test case started.", tc_number);
     tc_ctr = tc_ctr + 1;

     tb_block = block;
     tb_mode  = mode;
     tb_init = 1;
     #(2 * CLK_PERIOD);
     tb_init = 0;
     
     wait_ready();
      
     if (tb_digest == expected)
       begin
         $display("*** TC %0d successful.", tc_number);
         $display("");
       end 
     else
       begin
         $display("*** ERROR: TC %0d NOT successful.", tc_number);
         $display("Expected: 0x%064x", expected);
         $display("Got:      0x%064x", tb_digest);
         $display("");
         
         error_ctr = error_ctr + 1;
       end
   end
  endtask // single_block_test

  
  //----------------------------------------------------------------
  // double_block_test()
  //
  // Run a test case spanning two data blocks. We check both
  // intermediate and final digest.
  //----------------------------------------------------------------
//  task double_block_test(input [7 : 0]    tc_number,
//                         input [1 : 0]    mode,
//                         input [1023 : 0] block1,
//                         input [511 : 0]  expected1,
//                         input [1023 : 0] block2,
//                         input [511 : 0]  expected2);
//
//     reg [255 : 0] db_digest1;
//     reg           db_error;
//   begin
//     $display("*** TC %0d double block test case started.", tc_number);
//     db_error = 0;
//     tc_ctr = tc_ctr + 1;
//
//     $display("*** TC %0d first block started.", tc_number);
//     tb_block = block1;
//     tb_init = 1;
//     #(2 * CLK_HALF_PERIOD);
//     tb_init = 0;
//     wait_ready();
//     db_digest1 = tb_digest;
//     $display("*** TC %0d first block done.", tc_number);
//     
//     $display("*** TC %0d second block started.", tc_number);
//     tb_block = block2;
//     tb_next = 1;
//     #(2 * CLK_HALF_PERIOD);
//     tb_next = 0;
//     wait_ready();
//     $display("*** TC %0d second block done.", tc_number);
//      
//     if (db_digest1 == expected1)
//       begin
//         $display("*** TC %0d first block successful", tc_number);
//         $display("");
//       end 
//     else
//       begin
//         $display("*** ERROR: TC %0d first block NOT successful", tc_number);
//         $display("Expected: 0x%064x", expected1);
//         $display("Got:      0x%064x", db_digest1);
//         $display("");
//         db_error = 1;
//       end
//      
//     if (db_digest1 == expected1)
//       begin
//         $display("*** TC %0d second block successful", tc_number);
//         $display("");
//       end 
//     else
//       begin
//         $display("*** ERROR: TC %0d second block NOT successful", tc_number);
//         $display("Expected: 0x%064x", expected2);
//         $display("Got:      0x%064x", tb_digest);
//         $display("");
//         db_error = 1;
//       end
//
//     if (db_error)
//       begin
//         error_ctr = error_ctr + 1;
//       end
//   end
//  endtask // double_block_test
                         
    
  //----------------------------------------------------------------
  // sha512_core_test
  // The main test functionality. 
  //
  // Test cases taken from:
  // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
  //----------------------------------------------------------------
  initial
    begin : sha512_core_test
      reg [1024 : 0] single_block;
      reg [511 : 0]  tc1_expected;
      reg [511 : 0]  tc2_expected;
      reg [511 : 0]  tc3_expected;
      reg [511 : 0]  tc4_expected;
      
      $display("   -- Testbench for sha512 core started --");

      init_sim();
      dump_dut_state();
      reset_dut();
      dump_dut_state();

      // Single block tests are using the same test block
      single_block = 1024'h6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018;

      tc1_expected = 512'hDDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F;
      single_block_test(8'h01, MODE_SHA_512, single_block, tc1_expected);

      tc2_expected = {288'h000000000000000000000000000000000000000000000000000000000000000000000000, 
                      224'h4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA};
      single_block_test(8'h02, MODE_SHA_512_224, single_block, tc2_expected);

      tc3_expected = {256'h0000000000000000000000000000000000000000000000000000000000000000, 
                      256'h53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23};
      single_block_test(8'h03, MODE_SHA_512_256, single_block, tc3_expected);
      
      tc4_expected = {128'h00000000000000000000000000000000, 
                      384'hCB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7};
      single_block_test(8'h04, MODE_SHA_384, single_block, tc4_expected);
      
      // TC1: 512/224
      // tc1_expected = 512'h
      // 4634270F 707B6A54 DAAE7530 460842E2 0E37ED26 5CEEE9A4 3E8924AA
                     
      display_test_result();
      $display("*** Simulation done.");
      $finish;
    end // sha512_core_test
endmodule // tb_sha512_core

//======================================================================
// EOF tb_sha512_core.v
//======================================================================
