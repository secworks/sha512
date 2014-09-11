//======================================================================
//
// sha512.v
// --------
// Top level wrapper for the SHA-512 hash function providing
// a simple memory like interface with 32 bit data access.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014,  Secworks Sweden AB
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

module sha512(
              // Clock and reset.
              input wire           clk,
              input wire           reset_n,
              
              // Control.
              input wire           cs,
              input wire           we,
              
              // Data ports.
              input wire  [7 : 0]  address,
              input wire  [31 : 0] write_data,
              output wire [31 : 0] read_data,
              output wire          error
             );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  parameter ADDR_NAME0         = 8'h00;
  parameter ADDR_NAME1         = 8'h01;
  parameter ADDR_VERSION       = 8'h02;
  
  parameter ADDR_CTRL          = 8'h08;
  parameter CTRL_INIT_BIT      = 0;
  parameter CTRL_NEXT_BIT      = 1;
  parameter CTRL_MODE_LOW_BIT  = 2;
  parameter CTRL_MODE_HIGH_BIT = 3;

  parameter ADDR_STATUS        = 8'h09;
  parameter STATUS_READY_BIT   = 0;
  parameter STATUS_VALID_BIT   = 1;
                             
  parameter ADDR_BLOCK0        = 8'h10;
  parameter ADDR_BLOCK1        = 8'h11;
  parameter ADDR_BLOCK2        = 8'h12;
  parameter ADDR_BLOCK3        = 8'h13;
  parameter ADDR_BLOCK4        = 8'h14;
  parameter ADDR_BLOCK5        = 8'h15;
  parameter ADDR_BLOCK6        = 8'h16;
  parameter ADDR_BLOCK7        = 8'h17;
  parameter ADDR_BLOCK8        = 8'h18;
  parameter ADDR_BLOCK9        = 8'h19;
  parameter ADDR_BLOCK10       = 8'h1a;
  parameter ADDR_BLOCK11       = 8'h1b;
  parameter ADDR_BLOCK12       = 8'h1c;
  parameter ADDR_BLOCK13       = 8'h1d;
  parameter ADDR_BLOCK14       = 8'h1e;
  parameter ADDR_BLOCK15       = 8'h1f;
  parameter ADDR_BLOCK16       = 8'h20;
  parameter ADDR_BLOCK17       = 8'h21;
  parameter ADDR_BLOCK18       = 8'h22;
  parameter ADDR_BLOCK19       = 8'h23;
  parameter ADDR_BLOCK20       = 8'h24;
  parameter ADDR_BLOCK21       = 8'h25;
  parameter ADDR_BLOCK22       = 8'h26;
  parameter ADDR_BLOCK23       = 8'h27;
  parameter ADDR_BLOCK24       = 8'h28;
  parameter ADDR_BLOCK25       = 8'h29;
  parameter ADDR_BLOCK26       = 8'h2a;
  parameter ADDR_BLOCK27       = 8'h2b;
  parameter ADDR_BLOCK28       = 8'h2c;
  parameter ADDR_BLOCK29       = 8'h2d;
  parameter ADDR_BLOCK30       = 8'h2e;
  parameter ADDR_BLOCK31       = 8'h2f;
                             
  parameter ADDR_DIGEST0       = 8'h40;
  parameter ADDR_DIGEST1       = 8'h41;
  parameter ADDR_DIGEST2       = 8'h42;
  parameter ADDR_DIGEST3       = 8'h43;
  parameter ADDR_DIGEST4       = 8'h44;
  parameter ADDR_DIGEST5       = 8'h45;
  parameter ADDR_DIGEST6       = 8'h46;
  parameter ADDR_DIGEST7       = 8'h47;
  parameter ADDR_DIGEST8       = 8'h48;
  parameter ADDR_DIGEST9       = 8'h49;
  parameter ADDR_DIGEST10      = 8'h4a;
  parameter ADDR_DIGEST11      = 8'h4b;
  parameter ADDR_DIGEST12      = 8'h4c;
  parameter ADDR_DIGEST13      = 8'h4d;
  parameter ADDR_DIGEST14      = 8'h4e;
  parameter ADDR_DIGEST15      = 8'h4f;
  
  parameter CORE_NAME0         = 32'h73686132; // "sha2"
  parameter CORE_NAME1         = 32'h2d353132; // "-512"
  parameter CORE_VERSION       = 32'h302e3830; // "0.80"

  parameter MODE_SHA_512_224   = 2'h0;
  parameter MODE_SHA_512_256   = 2'h1;
  parameter MODE_SHA_384       = 2'h2;
  parameter MODE_SHA_512       = 2'h3;

  
  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg init_reg;
  reg init_new;
  reg init_we;
  reg init_set;

  reg next_reg;
  reg next_new;
  reg next_we;
  reg next_set;

  reg [1 : 0] mode_reg;
  reg [1 : 0] mode_new;
  reg         mode_we;
  
  reg ready_reg;

  reg [31 : 0] block0_reg;
  reg          block0_we;
  reg [31 : 0] block1_reg;
  reg          block1_we;
  reg [31 : 0] block2_reg;
  reg          block2_we;
  reg [31 : 0] block3_reg;
  reg          block3_we;
  reg [31 : 0] block4_reg;
  reg          block4_we;
  reg [31 : 0] block5_reg;
  reg          block5_we;
  reg [31 : 0] block6_reg;
  reg          block6_we;
  reg [31 : 0] block7_reg;
  reg          block7_we;
  reg [31 : 0] block8_reg;
  reg          block8_we;
  reg [31 : 0] block9_reg;
  reg          block9_we;
  reg [31 : 0] block10_reg;
  reg          block10_we;
  reg [31 : 0] block11_reg;
  reg          block11_we;
  reg [31 : 0] block12_reg;
  reg          block12_we;
  reg [31 : 0] block13_reg;
  reg          block13_we;
  reg [31 : 0] block14_reg;
  reg          block14_we;
  reg [31 : 0] block15_reg;
  reg          block15_we;
  reg [31 : 0] block16_reg;
  reg          block16_we;
  reg [31 : 0] block17_reg;
  reg          block17_we;
  reg [31 : 0] block18_reg;
  reg          block18_we;
  reg [31 : 0] block19_reg;
  reg          block19_we;
  reg [31 : 0] block20_reg;
  reg          block20_we;
  reg [31 : 0] block21_reg;
  reg          block21_we;
  reg [31 : 0] block22_reg;
  reg          block22_we;
  reg [31 : 0] block23_reg;
  reg          block23_we;
  reg [31 : 0] block24_reg;
  reg          block24_we;
  reg [31 : 0] block25_reg;
  reg          block25_we;
  reg [31 : 0] block26_reg;
  reg          block26_we;
  reg [31 : 0] block27_reg;
  reg          block27_we;
  reg [31 : 0] block28_reg;
  reg          block28_we;
  reg [31 : 0] block29_reg;
  reg          block29_we;
  reg [31 : 0] block30_reg;
  reg          block30_we;
  reg [31 : 0] block31_reg;
  reg          block31_we;
  
  reg [511 : 0] digest_reg;
  reg           digest_valid_reg;

  
  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  wire            core_init;
  wire            core_next;
  wire [1 : 0]    core_mode;
  wire            core_ready;
  wire [1023 : 0] core_block;
  wire [511 : 0]  core_digest;
  wire            core_digest_valid;

  reg [31 : 0] tmp_read_data;
  reg          tmp_error;
  
  
  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign core_init = init_reg;
  
  assign core_next = next_reg;
  
  assign core_mode = mode_reg;
  
  assign core_block = {block0_reg,  block1_reg,  block2_reg,  block3_reg,  block4_reg,  
                       block5_reg,  block6_reg,  block7_reg,  block8_reg,  block9_reg,  
                       block10_reg, block11_reg, block12_reg, block13_reg, block14_reg, 
                       block15_reg, block16_reg, block17_reg, block18_reg, block19_reg,
                       block20_reg, block21_reg, block22_reg, block23_reg, block24_reg, 
                       block25_reg, block26_reg, block27_reg, block28_reg, block29_reg,
                       block30_reg, block31_reg};

  assign read_data = tmp_read_data;
  assign error     = tmp_error;
  
             
  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  sha512_core core(
                   .clk(clk),
                   .reset_n(reset_n),
                   
                   .init(core_init),
                   .next(core_next),
                   .mode(core_mode),
                  
                   .block(core_block),
                   
                   .ready(core_ready),
                   
                   .digest(core_digest),
                   .digest_valid(core_digest_valid)
                  );
  
  
  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset. All registers have write enable.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin
      if (!reset_n)
        begin
          init_reg         <= 0;
          next_reg         <= 0;
          mode_reg         <= MODE_SHA_512;
          ready_reg        <= 0;
          digest_reg       <= {16{32'h00000000}};
          digest_valid_reg <= 0;
          block0_reg       <= 32'h00000000;
          block1_reg       <= 32'h00000000;
          block2_reg       <= 32'h00000000;
          block3_reg       <= 32'h00000000;
          block4_reg       <= 32'h00000000;
          block5_reg       <= 32'h00000000;
          block6_reg       <= 32'h00000000;
          block7_reg       <= 32'h00000000;
          block8_reg       <= 32'h00000000;
          block9_reg       <= 32'h00000000;
          block10_reg      <= 32'h00000000;
          block11_reg      <= 32'h00000000;
          block12_reg      <= 32'h00000000;
          block13_reg      <= 32'h00000000;
          block14_reg      <= 32'h00000000;
          block15_reg      <= 32'h00000000;
          block16_reg      <= 32'h00000000;
          block17_reg      <= 32'h00000000;
          block18_reg      <= 32'h00000000;
          block19_reg      <= 32'h00000000;
          block20_reg      <= 32'h00000000;
          block21_reg      <= 32'h00000000;
          block22_reg      <= 32'h00000000;
          block23_reg      <= 32'h00000000;
          block24_reg      <= 32'h00000000;
          block25_reg      <= 32'h00000000;
          block26_reg      <= 32'h00000000;
          block27_reg      <= 32'h00000000;
          block28_reg      <= 32'h00000000;
          block29_reg      <= 32'h00000000;
          block30_reg      <= 32'h00000000;
          block31_reg      <= 32'h00000000;
        end
      else
        begin
          ready_reg        <= core_ready;
          digest_valid_reg <= core_digest_valid;

          if (init_we)
            begin
              init_reg <= init_new;
            end

          if (next_we)
            begin
              next_reg <= next_new;
            end

          if (mode_we)
            begin
              mode_reg <= mode_new;
            end
          
          if (core_digest_valid)
            begin
              digest_reg <= core_digest;
            end

          if (block0_we)
            begin
              block0_reg <= write_data;
            end

          if (block1_we)
            begin
              block1_reg <= write_data;
            end

          if (block2_we)
            begin
              block2_reg <= write_data;
            end

          if (block3_we)
            begin
              block3_reg <= write_data;
            end

          if (block4_we)
            begin
              block4_reg <= write_data;
            end

          if (block5_we)
            begin
              block5_reg <= write_data;
            end

          if (block6_we)
            begin
              block6_reg <= write_data;
            end

          if (block7_we)
            begin
              block7_reg <= write_data;
            end

          if (block8_we)
            begin
              block8_reg <= write_data;
            end

          if (block9_we)
            begin
              block9_reg <= write_data;
            end

          if (block10_we)
            begin
              block10_reg <= write_data;
            end

          if (block11_we)
            begin
              block11_reg <= write_data;
            end

          if (block12_we)
            begin
              block12_reg <= write_data;
            end

          if (block13_we)
            begin
              block13_reg <= write_data;
            end

          if (block14_we)
            begin
              block14_reg <= write_data;
            end

          if (block15_we)
            begin
              block15_reg <= write_data;
            end

          if (block16_we)
            begin
              block16_reg <= write_data;
            end

          if (block17_we)
            begin
              block17_reg <= write_data;
            end

          if (block18_we)
            begin
              block18_reg <= write_data;
            end

          if (block19_we)
            begin
              block19_reg <= write_data;
            end

          if (block20_we)
            begin
              block20_reg <= write_data;
            end

          if (block21_we)
            begin
              block21_reg <= write_data;
            end

          if (block22_we)
            begin
              block22_reg <= write_data;
            end

          if (block23_we)
            begin
              block23_reg <= write_data;
            end

          if (block24_we)
            begin
              block24_reg <= write_data;
            end

          if (block25_we)
            begin
              block25_reg <= write_data;
            end

          if (block26_we)
            begin
              block26_reg <= write_data;
            end

          if (block27_we)
            begin
              block27_reg <= write_data;
            end

          if (block28_we)
            begin
              block28_reg <= write_data;
            end

          if (block29_we)
            begin
              block29_reg <= write_data;
            end

          if (block30_we)
            begin
              block30_reg <= write_data;
            end

          if (block31_we)
            begin
              block31_reg <= write_data;
            end
        end
    end // reg_update


  //----------------------------------------------------------------
  // flag_reset
  //
  // Logic to reset init and next flags that has been set.
  //----------------------------------------------------------------
  always @*
    begin : flag_reset
      init_new = 0;
      init_we  = 0;
      next_new = 0;
      next_we  = 0;

      if (init_set)
        begin
          init_new = 1;
          init_we  = 1;
        end
      else if (init_reg)
        begin
          init_new = 0;
          init_we  = 1;
        end

      if (next_set)
        begin
          next_new = 1;
          next_we  = 1;
        end
      else if (next_reg)
        begin
          next_new = 0;
          next_we  = 1;
        end
    end


  //----------------------------------------------------------------
  // api_logic
  //
  // Implementation of the api logic. If cs is enabled will either 
  // try to write to or read from the internal registers.
  //----------------------------------------------------------------
  always @*
    begin : api_logic
      init_set      = 0;
      next_set      = 0;
      mode_new      = 2'b00;
      mode_we       = 0;
      block0_we     = 0;
      block1_we     = 0;
      block2_we     = 0;
      block3_we     = 0;
      block4_we     = 0;
      block5_we     = 0;
      block6_we     = 0;
      block7_we     = 0;
      block8_we     = 0;
      block9_we     = 0;
      block10_we    = 0;
      block11_we    = 0;
      block12_we    = 0;
      block13_we    = 0;
      block14_we    = 0;
      block15_we    = 0;
      block16_we    = 0;
      block17_we    = 0;
      block18_we    = 0;
      block19_we    = 0;
      block20_we    = 0;
      block21_we    = 0;
      block22_we    = 0;
      block23_we    = 0;
      block24_we    = 0;
      block25_we    = 0;
      block26_we    = 0;
      block27_we    = 0;
      block28_we    = 0;
      block29_we    = 0;
      block30_we    = 0;
      block31_we    = 0;
      tmp_read_data = 32'h00000000;
      tmp_error     = 0;
      
      if (cs)
        begin
          if (we)
            begin
              case (address)
                // Write operations.
                ADDR_CTRL:
                  begin
                    init_set = write_data[CTRL_INIT_BIT];
                    next_set = write_data[CTRL_NEXT_BIT];
                    mode_new = write_data[CTRL_MODE_HIGH_BIT : CTRL_MODE_LOW_BIT];
                    mode_we  = 1;
                  end
                
                ADDR_BLOCK0:
                  begin
                    block0_we = 1;
                   end

                ADDR_BLOCK1:
                  begin
                    block1_we = 1;
                  end

                ADDR_BLOCK2:
                  begin
                    block2_we = 1;
                  end

                ADDR_BLOCK3:
                  begin
                    block3_we = 1;
                  end

                ADDR_BLOCK4:
                  begin
                    block4_we = 1;
                  end

                ADDR_BLOCK5:
                  begin
                    block5_we = 1;
                  end

                ADDR_BLOCK6:
                  begin
                    block6_we = 1;
                  end

                ADDR_BLOCK7:
                  begin
                    block7_we = 1;
                  end

                ADDR_BLOCK8:
                  begin
                    block8_we = 1;
                  end

                ADDR_BLOCK9:
                  begin
                    block9_we = 1;
                  end

                ADDR_BLOCK10:
                  begin
                    block10_we = 1;
                  end

                ADDR_BLOCK11:
                  begin
                    block11_we = 1;
                  end

                ADDR_BLOCK12:
                  begin
                    block12_we = 1;
                  end

                ADDR_BLOCK13:
                  begin
                    block13_we = 1;
                  end

                ADDR_BLOCK14:
                  begin
                    block14_we = 1;
                  end

                ADDR_BLOCK15:
                  begin
                    block15_we = 1;
                  end

                ADDR_BLOCK16:
                  begin
                    block16_we = 1;
                  end

                ADDR_BLOCK17:
                  begin
                    block17_we = 1;
                  end

                ADDR_BLOCK18:
                  begin
                    block18_we = 1;
                  end

                ADDR_BLOCK19:
                  begin
                    block19_we = 1;
                  end

                ADDR_BLOCK20:
                  begin
                    block20_we = 1;
                  end

                ADDR_BLOCK21:
                  begin
                    block21_we = 1;
                  end

                ADDR_BLOCK22:
                  begin
                    block22_we = 1;
                  end

                ADDR_BLOCK23:
                  begin
                    block23_we = 1;
                  end

                ADDR_BLOCK24:
                  begin
                    block24_we = 1;
                  end

                ADDR_BLOCK25:
                  begin
                    block25_we = 1;
                  end

                ADDR_BLOCK26:
                  begin
                    block26_we = 1;
                  end

                ADDR_BLOCK27:
                  begin
                    block27_we = 1;
                  end

                ADDR_BLOCK28:
                  begin
                    block28_we = 1;
                  end

                ADDR_BLOCK29:
                  begin
                    block29_we = 1;
                  end

                ADDR_BLOCK30:
                  begin
                    block30_we = 1;
                  end

                ADDR_BLOCK31:
                  begin
                    block31_we = 1;
                  end
                
                default:
                  begin
                    tmp_error = 1;
                  end
              endcase // case (address)
            end // if (we)

          else
            begin
              case (address)
                // Read operations.
                ADDR_NAME0:
                  begin
                    tmp_read_data = CORE_NAME0;
                  end

                ADDR_NAME1:
                  begin
                    tmp_read_data = CORE_NAME1;
                  end
                
                ADDR_VERSION:
                  begin
                    tmp_read_data = CORE_VERSION;
                  end

                ADDR_CTRL:
                  begin
                    tmp_read_data = {28'h0000000, mode_reg, next_reg, init_reg};
                  end
                
                ADDR_STATUS:
                  begin
                    tmp_read_data = {28'h0000000, 2'b00, digest_valid_reg, ready_reg};
                  end
                
                ADDR_BLOCK0:
                  begin
                    tmp_read_data = block0_reg;
                  end

                ADDR_BLOCK1:
                  begin
                    tmp_read_data = block1_reg;
                  end

                ADDR_BLOCK2:
                  begin
                    tmp_read_data = block2_reg;
                  end

                ADDR_BLOCK3:
                  begin
                    tmp_read_data = block3_reg;
                  end

                ADDR_BLOCK4:
                  begin
                    tmp_read_data = block4_reg;
                  end

                ADDR_BLOCK5:
                  begin
                    tmp_read_data = block5_reg;
                  end

                ADDR_BLOCK6:
                  begin
                    tmp_read_data = block6_reg;
                  end

                ADDR_BLOCK7:
                  begin
                    tmp_read_data = block7_reg;
                  end

                ADDR_BLOCK8:
                  begin
                    tmp_read_data = block8_reg;
                  end

                ADDR_BLOCK9:
                  begin
                    tmp_read_data = block9_reg;
                  end

                ADDR_BLOCK10:
                  begin
                    tmp_read_data = block10_reg;
                  end

                ADDR_BLOCK11:
                  begin
                    tmp_read_data = block11_reg;
                  end

                ADDR_BLOCK12:
                  begin
                    tmp_read_data = block12_reg;
                  end

                ADDR_BLOCK13:
                  begin
                    tmp_read_data = block13_reg;
                  end

                ADDR_BLOCK14:
                  begin
                    tmp_read_data = block14_reg;
                  end

                ADDR_BLOCK15:
                  begin
                    tmp_read_data = block15_reg;
                  end

                ADDR_BLOCK16:
                  begin
                    tmp_read_data = block16_reg;
                  end

                ADDR_BLOCK17:
                  begin
                    tmp_read_data = block17_reg;
                  end

                ADDR_BLOCK18:
                  begin
                    tmp_read_data = block18_reg;
                  end

                ADDR_BLOCK19:
                  begin
                    tmp_read_data = block19_reg;
                  end

                ADDR_BLOCK20:
                  begin
                    tmp_read_data = block20_reg;
                  end

                ADDR_BLOCK21:
                  begin
                    tmp_read_data = block21_reg;
                  end

                ADDR_BLOCK22:
                  begin
                    tmp_read_data = block22_reg;
                  end

                ADDR_BLOCK23:
                  begin
                    tmp_read_data = block23_reg;
                  end

                ADDR_BLOCK24:
                  begin
                    tmp_read_data = block24_reg;
                  end

                ADDR_BLOCK25:
                  begin
                    tmp_read_data = block25_reg;
                  end

                ADDR_BLOCK26:
                  begin
                    tmp_read_data = block26_reg;
                  end

                ADDR_BLOCK27:
                  begin
                    tmp_read_data = block27_reg;
                  end

                ADDR_BLOCK28:
                  begin
                    tmp_read_data = block28_reg;
                  end

                ADDR_BLOCK29:
                  begin
                    tmp_read_data = block29_reg;
                  end

                ADDR_BLOCK30:
                  begin
                    tmp_read_data = block30_reg;
                  end

                ADDR_BLOCK31:
                  begin
                    tmp_read_data = block31_reg;
                  end

                ADDR_DIGEST0:
                  begin
                    tmp_read_data = digest_reg[511 : 480];
                  end

                ADDR_DIGEST1:
                  begin
                    tmp_read_data = digest_reg[479 : 448];
                  end

                ADDR_DIGEST2:
                  begin
                    tmp_read_data = digest_reg[447 : 416];
                  end

                ADDR_DIGEST3:
                  begin
                    tmp_read_data = digest_reg[415 : 384];
                  end

                ADDR_DIGEST4:
                  begin
                    tmp_read_data = digest_reg[383 : 352];
                  end

                ADDR_DIGEST5:
                  begin
                    tmp_read_data = digest_reg[351 : 320];
                  end

                ADDR_DIGEST6:
                  begin
                    tmp_read_data = digest_reg[319 : 288];
                  end

                ADDR_DIGEST7:
                  begin
                    tmp_read_data = digest_reg[287 : 256];
                  end
                
                ADDR_DIGEST8:
                  begin
                    tmp_read_data = digest_reg[255 : 224];
                  end

                ADDR_DIGEST9:
                  begin
                    tmp_read_data = digest_reg[223 : 192];
                  end

                ADDR_DIGEST10:
                  begin
                    tmp_read_data = digest_reg[191 : 160];
                  end

                ADDR_DIGEST11:
                  begin
                    tmp_read_data = digest_reg[159 : 128];
                  end

                ADDR_DIGEST12:
                  begin
                    tmp_read_data = digest_reg[127 :  96];
                  end

                ADDR_DIGEST13:
                  begin
                    tmp_read_data = digest_reg[95  :  64];
                  end

                ADDR_DIGEST14:
                  begin
                    tmp_read_data = digest_reg[63  :  32];
                  end

                ADDR_DIGEST15:
                  begin
                    tmp_read_data = digest_reg[31  :   0];
                  end
                
                default:
                  begin
                    tmp_error = 1;
                  end
              endcase // case (address)
            end
        end
    end // addr_decoder
endmodule // sha512

//======================================================================
// EOF sha512.v
//======================================================================
