//======================================================================
//
// sha512_h_constants.v
// ---------------------
// The H initial constants for the different modes in SHA-512.
//
//
// Author: Joachim Strombergson
// Copyright (c) 2014 Secworks Sweden AB
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

module sha512_h_constants(
                          input wire  [1 : 0]  mode,

                          output wire [63 : 0] H0,
                          output wire [63 : 0] H1,
                          output wire [63 : 0] H2,
                          output wire [63 : 0] H3,
                          output wire [63 : 0] H4,
                          output wire [63 : 0] H5,
                          output wire [63 : 0] H6,
                          output wire [63 : 0] H7
                         );

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [63 : 0] tmp_H0;
  reg [63 : 0] tmp_H1;
  reg [63 : 0] tmp_H2;
  reg [63 : 0] tmp_H3;
  reg [63 : 0] tmp_H4;
  reg [63 : 0] tmp_H5;
  reg [63 : 0] tmp_H6;
  reg [63 : 0] tmp_H7;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign H0 = tmp_H0;
  assign H1 = tmp_H1;
  assign H2 = tmp_H2;
  assign H3 = tmp_H3;
  assign H4 = tmp_H4;
  assign H5 = tmp_H5;
  assign H6 = tmp_H6;
  assign H7 = tmp_H7;

  
  //----------------------------------------------------------------
  // mode_mux
  //
  // Based on the given mode, the correct H constants are selected.
  //----------------------------------------------------------------
  always @*
    begin : mode_mux
      case(mode)
        0:
          begin
            // SHA-512/224
            tmp_H0 = 8C3D37C819544DA2;
            tmp_H1 = 73E1996689DCD4D6;
            tmp_H2 = 1DFAB7AE32FF9C82;
            tmp_H3 = 679DD514582F9FCF;
            tmp_H4 = 0F6D2B697BD44DA8;
            tmp_H5 = 77E36F7304C48942;
            tmp_H6 = 3F9D85A86A1D36C8;
            tmp_H7 = 1112E6AD91D692A1;
          end

        1:
          begin
            // SHA-512/256
            tmp_H0 = 22312194FC2BF72C; 
            tmp_H0 = 9F555FA3C84C64C2; 
            tmp_H0 = 2393B86B6F53B151; 
            tmp_H0 = 963877195940EABD; 
            tmp_H0 = 96283EE2A88EFFE3; 
            tmp_H0 = BE5E1E2553863992; 
            tmp_H0 = 2B0199FC2C85B8AA; 
            tmp_H0 = 0EB72DDC81C52CA2;
          end
        
        2:
          begin
            // SHA-384
            tmp_H0 = cbbb9d5dc1059ed8;
            tmp_H1 = 629a292a367cd507;
            tmp_H2 = 9159015a3070dd17; 
            tmp_H3 = 152fecd8f70e5939; 
            tmp_H4 = 67332667ffc00b31; 
            tmp_H5 = 8eb44a8768581511; 
            tmp_H6 = db0c2e0d64f98fa7; 
            tmp_H7 = 47b5481dbefa4fa4;
          end
        
        3:
          begin
            // SHA-512
            tmp_H0 = 6a09e667f3bcc908;
            tmp_H0 = bb67ae8584caa73b;
            tmp_H0 = 3c6ef372fe94f82b; 
            tmp_H0 = a54ff53a5f1d36f1; 
            tmp_H0 = 510e527fade682d1; 
            tmp_H0 = 9b05688c2b3e6c1f; 
            tmp_H0 = 1f83d9abfb41bd6b; 
            tmp_H0 = 5be0cd19137e2179;  
          end
      endcase // case (addr)
    end // block: mode_mux
endmodule // sha512_h_constants

//======================================================================
// sha512_h_constants.v
//======================================================================
