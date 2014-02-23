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
            tmp_K = 64'h428a2f98d728ae22;
          end

        1:
          begin
            tmp_K = 64'h7137449123ef65cd;
          end

        2:
          begin
            tmp_K = 64'hb5c0fbcfec4d3b2f;
          end
        
        3:
          begin
            tmp_K = 64'he9b5dba58189dbbc;
          end
        
        4:
          begin
            tmp_K = 64'h3956c25bf348b538;
          end
        
        5:
          begin
            tmp_K = 64'h59f111f1b605d019;
          end
        
        6:
          begin
            tmp_K = 64'h923f82a4af194f9b;
          end
        
        7:
          begin
            tmp_K = 64'hab1c5ed5da6d8118;
          end
        
        8:
          begin
            tmp_K = 64'hd807aa98a3030242;
          end
        
        9:
          begin
            tmp_K = 64'h12835b0145706fbe;
          end
        
        10:
          begin
            tmp_K = 64'h243185be4ee4b28c;
          end
        
        11:
          begin
            tmp_K = 64'h550c7dc3d5ffb4e2;
          end
  
        12:
          begin
            tmp_K = 64'h72be5d74f27b896f;
          end

        13:
          begin
            tmp_K = 64'h80deb1fe3b1696b1;
          end

        14:
          begin
            tmp_K = 64'h9bdc06a725c71235;
          end

        15:
          begin
            tmp_K = 64'hc19bf174cf692694;
          end  

        16:        
          begin      
            tmp_K = 64'he49b69c19ef14ad2;
          end                  
          
        17:
          begin
            tmp_K = 64'hefbe4786384f25e3;
          end
           
        18:
          begin
            tmp_K = 64'h0fc19dc68b8cd5b5;
          end

        19:
          begin
            tmp_K = 64'h240ca1cc77ac9c65;
          end
        
        20:
          begin
            tmp_K = 64'h2de92c6f592b0275;
          end
          
        21:
          begin
            tmp_K = 64'h4a7484aa6ea6e483;
          end

        22:
          begin
            tmp_K = 64'h5cb0a9dcbd41fbd4;
          end
             
        23:
          begin
            tmp_K = 64'h76f988da831153b5;
          end
  
        24:
          begin
            tmp_K = 64'h983e5152ee66dfab;
          end
  
        25:
          begin
            tmp_K = 64'ha831c66d2db43210;
          end

        26:
          begin
            tmp_K = 64'hb00327c898fb213f;
          end

        27:
          begin
            tmp_K = 64'hbf597fc7beef0ee4;
          end
  
        28:
          begin
            tmp_K = 64'hc6e00bf33da88fc2;
          end
  
        29:
          begin
            tmp_K = 64'hd5a79147930aa725;
          end
  
        30:
          begin
            tmp_K = 64'h06ca6351e003826f;
          end

        31:
          begin
            tmp_K = 64'h142929670a0e6e70;
          end

        32:
          begin
            tmp_K = 64'h27b70a8546d22ffc;
          end
  
        33:
          begin
            tmp_K = 64'h2e1b21385c26c926;
          end

        34:
          begin
            tmp_K = 64'h4d2c6dfc5ac42aed;
          end

        35:  
          begin
            tmp_K = 64'h53380d139d95b3df;
          end

        36:
          begin
            tmp_K = 64'h650a73548baf63de;
          end

        37:
          begin
            tmp_K = 64'h766a0abb3c77b2a8;
          end

        38:
          begin
            tmp_K = 64'h81c2c92e47edaee6;
          end

        39:
          begin
            tmp_K = 64'h92722c851482353b;
          end

        40:
          begin
            tmp_K = 64'ha2bfe8a14cf10364;
          end

        41:
          begin
            tmp_K = 64'ha81a664bbc423001;
          end

        42:
          begin
            tmp_K = 64'hc24b8b70d0f89791;
          end

        43:
          begin
            tmp_K = 64'hc76c51a30654be30;
          end

        44:
          begin
            tmp_K = 64'hd192e819d6ef5218;
          end

        45:
          begin
            tmp_K = 64'hd69906245565a910;
          end

        46:
          begin
            tmp_K = 64'hf40e35855771202a;
          end

        47:
          begin
            tmp_K = 64'h106aa07032bbd1b8;
          end

        48:
          begin
            tmp_K = 64'h19a4c116b8d2d0c8;
          end

        49:
          begin
            tmp_K = 64'h1e376c085141ab53;
          end

        50:
          begin
            tmp_K = 64'h2748774cdf8eeb99;
          end

        51:
          begin
            tmp_K = 64'h34b0bcb5e19b48a8;
          end

        52:
          begin
            tmp_K = 64'h391c0cb3c5c95a63;
          end

        53:
          begin
            tmp_K = 64'h4ed8aa4ae3418acb;
          end

        54:
          begin
            tmp_K = 64'h5b9cca4f7763e373;
          end

        55:
          begin
            tmp_K = 64;'h682e6ff3d6b2b8a3;
          end

        56:
          begin
            tmp_K = 64'h748f82ee5defb2fc;
          end

        57:
          begin
            tmp_K = 64'h78a5636f43172f60;
          end

        58:
          begin
            tmp_K = 64'h84c87814a1f0ab72;
          end

        59:
          begin
            tmp_K = 64'h8cc702081a6439ec;
          end

        60:
          begin
            tmp_K = 64'h90befffa23631e28;
          end

        61:
          begin
            tmp_K = 64'ha4506cebde82bde9;
          end

        62:
          begin
            tmp_K = 64'hbef9a3f7b2c67915;
          end

        63:
          begin
            tmp_K = 64'hc67178f2e372532b;
          end
      endcase // case (addr)
    end // block: addr_mux
endmodule // sha512_k_constants

//======================================================================
// sha512_k_constants.v
//======================================================================
