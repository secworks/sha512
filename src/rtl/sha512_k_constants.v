//======================================================================
//
// sha512_k_constants.v
// --------------------
// The table K with constants in the SHA-512 hash function.
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

module sha512_k_constants(
                          input wire  [5 : 0]  addr,
                          output wire [63 : 0] K
                         );

  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg [63 : 0] tmp_K;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign K = tmp_K;
  
  
  //----------------------------------------------------------------
  // addr_mux
  //----------------------------------------------------------------
  always @*
    begin : addr_mux
      case(addr)
        0:
          begin
            tmp_K = 32'h428a2f98;
          end

        1:
          begin
            tmp_K = 32'h71374491;
          end

        2:
          begin
            tmp_K = 32'hb5c0fbcf;
          end
        
        3:
          begin
            tmp_K = 32'he9b5dba5;
          end
        
        4:
          begin
            tmp_K = 32'h3956c25b;
          end
        
        5:
          begin
            tmp_K = 32'h59f111f1;
          end
        
        6:
          begin
            tmp_K = 32'h923f82a4;
          end
        
        7:
          begin
            tmp_K = 32'hab1c5ed5;
          end
        
        8:
          begin
            tmp_K = 32'hd807aa98;
          end
        
        9:
          begin
            tmp_K = 32'h12835b01;
          end
        
        10:
          begin
            tmp_K = 32'h243185be;
          end
        
        11:
          begin
            tmp_K = 32'h550c7dc3;
          end
        
        12:
          begin
            tmp_K = 32'h72be5d74;
          end
        
        13:
          begin
            tmp_K = 32'h80deb1fe;
          end
        
        14:
          begin
            tmp_K = 32'h9bdc06a7;
          end
        
        15:
          begin
            tmp_K = 32'hc19bf174;
          end
        
        16:
          begin
            tmp_K = 32'he49b69c1;
          end
        
        17:
          begin
            tmp_K = 32'hefbe4786;
          end
        
        18:
          begin
            tmp_K = 32'h0fc19dc6;
          end
        
        19:
          begin
            tmp_K = 32'h240ca1cc;
          end
        
        20:
          begin
            tmp_K = 32'h2de92c6f;
          end
        
        21:
          begin
            tmp_K = 32'h4a7484aa;
          end
        
        22:
          begin
            tmp_K = 32'h5cb0a9dc;
          end
        
        23:
          begin
            tmp_K = 32'h76f988da;
          end
        
        24:
          begin
            tmp_K = 32'h983e5152;
          end
        
        25:
          begin
            tmp_K = 32'ha831c66d;
          end
        
        26:
          begin
            tmp_K = 32'hb00327c8;
          end
        
        27:
          begin
            tmp_K = 32'hbf597fc7;
          end
        
        28:
          begin
            tmp_K = 32'hc6e00bf3;
          end
        
        29:
          begin
            tmp_K = 32'hd5a79147;
          end
        
        30:
          begin
            tmp_K = 32'h06ca6351;
          end
        
        31:
          begin
            tmp_K = 32'h14292967;
          end
        
        32:
          begin
            tmp_K = 32'h27b70a85;
          end
        
        33:
          begin
            tmp_K = 32'h2e1b2138;
          end
        
        34:
          begin
            tmp_K = 32'h4d2c6dfc;
          end
        
        35:
          begin
            tmp_K = 32'h53380d13;
          end
        
        36:
          begin
            tmp_K = 32'h650a7354;
          end
        
        37:
          begin
            tmp_K = 32'h766a0abb;
          end
        
        38:
          begin
            tmp_K = 32'h81c2c92e;
          end
        
        39:
          begin
            tmp_K = 32'h92722c85;
          end
        
        40:
          begin
            tmp_K = 32'ha2bfe8a1;
          end
        
        41:
          begin
            tmp_K = 32'ha81a664b;
          end
        
        42:
          begin
            tmp_K = 32'hc24b8b70;
          end
        
        43:
          begin
            tmp_K = 32'hc76c51a3;
          end
        
        44:
          begin
            tmp_K = 32'hd192e819;
          end
        
        45:
          begin
            tmp_K = 32'hd6990624;
          end
        
        46:
          begin
            tmp_K = 32'hf40e3585;
          end
        
        47:
          begin
            tmp_K = 32'h106aa070;
          end
        
        48:
          begin
            tmp_K = 32'h19a4c116;
          end
        
        49:
          begin
            tmp_K = 32'h1e376c08;
          end
        
        50:
          begin
            tmp_K = 32'h2748774c;
          end
        
        51:
          begin
            tmp_K = 32'h34b0bcb5;
          end
        
        52:
          begin
            tmp_K = 32'h391c0cb3;
          end
        
        53:
          begin
            tmp_K = 32'h4ed8aa4a;
          end
        
        54:
          begin
            tmp_K = 32'h5b9cca4f;
          end
        
        55:
          begin
            tmp_K = 32'h682e6ff3;
          end
        
        56:
          begin
            tmp_K = 32'h748f82ee;
          end
        
        57:
          begin
            tmp_K = 32'h78a5636f;
          end
        
        58:
          begin
            tmp_K = 32'h84c87814;
          end
        
        59:
          begin
            tmp_K = 32'h8cc70208;
          end
        
        60:
          begin
            tmp_K = 32'h90befffa;
          end
        
        61:
          begin
            tmp_K = 32'ha4506ceb;
          end
        
        62:
          begin
            tmp_K = 32'hbef9a3f7;
          end
        
        63:
          begin
            tmp_K = 32'hc67178f2;
          end
      endcase // case (addr)
    end // block: addr_mux
endmodule // sha512_k_constants

// 64'h428a2f98d728ae22 
// 64'h7137449123ef65cd
// 64'hb5c0fbcfec4d3b2f
// 64'he9b5dba58189dbbc
// 64'h3956c25bf348b538
// 64'h59f111f1b605d019
// 64'h923f82a4af194f9b
// 64'hab1c5ed5da6d8118
// 64'hd807aa98a3030242
// 64'h12835b0145706fbe
// 64'h243185be4ee4b28c
// 64'h550c7dc3d5ffb4e2
// 64'h72be5d74f27b896f
// 64'h80deb1fe3b1696b1
// 64'h9bdc06a725c71235
// 64'hc19bf174cf692694
// 64'he49b69c19ef14ad2
// 64'hefbe4786384f25e3
// 64'h0fc19dc68b8cd5b5
// 64'h240ca1cc77ac9c65
// 64'h2de92c6f592b0275
// 64'h4a7484aa6ea6e483
// 64'h5cb0a9dcbd41fbd4
// 64'h76f988da831153b5
// 64'h983e5152ee66dfab
// 64'ha831c66d2db43210
// 64'hb00327c898fb213f
// 64'hbf597fc7beef0ee4
// 64'hc6e00bf33da88fc2
// 64'hd5a79147930aa725
// 64'h06ca6351e003826f
// 64'h142929670a0e6e70
// 64'h27b70a8546d22ffc
// 64'h2e1b21385c26c926
// 64'h4d2c6dfc5ac42aed
// 64'h53380d139d95b3df
// 64'h650a73548baf63de
// 64'h766a0abb3c77b2a8
// 64'h81c2c92e47edaee6
// 64'h92722c851482353b
// 64'ha2bfe8a14cf10364
// 64'ha81a664bbc423001
// 64'hc24b8b70d0f89791
// 64'hc76c51a30654be30
// 64'hd192e819d6ef5218
// 64'hd69906245565a910
// 64'hf40e35855771202a
// 64'h106aa07032bbd1b8
// 64'h19a4c116b8d2d0c8
// 64'h1e376c085141ab53
// 64'h2748774cdf8eeb99
// 64'h34b0bcb5e19b48a8
// 64'h391c0cb3c5c95a63
// 64'h4ed8aa4ae3418acb
// 64'h5b9cca4f7763e373
// 64'h682e6ff3d6b2b8a3
// 64'h748f82ee5defb2fc
// 64'h78a5636f43172f60
// 64'h84c87814a1f0ab72
// 64'h8cc702081a6439ec
// 64'h90befffa23631e28
// 64'ha4506cebde82bde9
// 64'hbef9a3f7b2c67915
// 64'hc67178f2e372532b
// 64'hca273eceea26619c
// 64'hd186b8c721c0c207
// 64'heada7dd6cde0eb1e
// 64'hf57d4f7fee6ed178
// 64'h06f067aa72176fba
// 64'h0a637dc5a2c898a6
// 64'h113f9804bef90dae
// 64'h1b710b35131c471b
// 64'h28db77f523047d84
// 64'h32caab7b40c72493
// 64'h3c9ebe0a15c9bebc
// 64'h431d67c49c100d4c
// 64'h4cc5d4becb3e42b6
// 64'h597f299cfc657e2a
// 64'h5fcb6fab3ad6faec
// 64'h6c44198c4a475817


//======================================================================
// sha512_k_constants.v
//======================================================================
