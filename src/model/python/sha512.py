#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#=======================================================================
#
# sha512.py
# ---------
# Simple, pure Python model of the SHA-512 hash function. Used as a
# reference for the HW implementation. The code follows the structure
# of the HW implementation as much as possible.
#
#
# Author: Joachim Strömbergson
# Copyright (c) 2013 Secworks Sweden AB
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the following 
# conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright 
#    notice, this list of conditions and the following disclaimer. 
# 
# 2. Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in 
#    the documentation and/or other materials provided with the 
#    distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#=======================================================================

#-------------------------------------------------------------------
# Python module imports.
#-------------------------------------------------------------------
import sys


#-------------------------------------------------------------------
# Constants.
#-------------------------------------------------------------------
MAX_64BIT = 0xffffffffffffffff


#-------------------------------------------------------------------
# ChaCha()
#-------------------------------------------------------------------
class SHA512():
    def __init__(self, mode = 'MODE_SHA_512', verbose = 0):
        assert mode in ['MODE_SHA_512_224', 'MODE_SHA_512_256',
                        'MODE_SHA_384', 'MODE_SHA_512']
        self.mode = mode
        self.verbose = verbose
        self.mode 
        self.NUM_ROUNDS = 80
        self.H = [0] * 8
        self.t1 = 0
        self.t2 = 0
        self.a = 0
        self.b = 0
        self.c = 0
        self.d = 0
        self.e = 0
        self.f = 0
        self.g = 0
        self.h = 0
        self.w = 0
        self.W = [0] * 16
        self.k = 0
        self.K = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 
                  0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
                  0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
                  0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                  0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
                  0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
                  0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
                  0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
                  0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                  0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
                  0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                  0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
                  0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
                  0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
                  0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
                  0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                  0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

        
    def init(self):
        if self.mode == 'MODE_SHA_512_224':
            self.H = [0x8c3d37c819544da2, 0x73e1996689dcd4d6,
                      0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
                      0x0f6d2b697bd44da8, 0x77e36f7304c48942,
                      0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1]

        elif self.mode == 'MODE_SHA_512_256':
            self.H = [0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 
                      0x2393b86b6f53b151, 0x963877195940eabd, 
                      0x96283ee2a88effe3, 0xbe5e1e2553863992, 
                      0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2]
                      
        elif self.mode == 'MODE_SHA_384':
            self.H = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                      0x9159015a3070dd17, 0x152fecd8f70e5939, 
                      0x67332667ffc00b31, 0x8eb44a8768581511, 
                      0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]

        elif self.mode == 'MODE_SHA_512':
            self.H = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                      0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
                      0x510e527fade682d1, 0x9b05688c2b3e6c1f, 
                      0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
        

    def next(self, block):
        self._W_schedule(block)
        self._copy_digest()
        if self.verbose:
            print("State after init:")
            self._print_state(0)

        for i in range(self.NUM_ROUNDS):
            self._sha512_round(i)
            if self.verbose:
                self._print_state(i)

        self._update_digest()


    def get_digest(self):
        if self.mode == 'MODE_SHA_512_224':
            return self.H[0:3] # FIX THIS!

        elif self.mode == 'MODE_SHA_512_256':
            return self.H[0:4]

        elif self.mode == 'MODE_SHA_384':
            return self.H[0:6]

        elif self.mode == 'MODE_SHA_512':
            return self.H


    def _copy_digest(self):
        self.a = self.H[0] 
        self.b = self.H[1] 
        self.c = self.H[2] 
        self.d = self.H[3] 
        self.e = self.H[4] 
        self.f = self.H[5] 
        self.g = self.H[6] 
        self.h = self.H[7]
    
    
    def _update_digest(self):
        self.H[0] = (self.H[0] + self.a) & MAX_64BIT
        self.H[1] = (self.H[1] + self.b) & MAX_64BIT
        self.H[2] = (self.H[2] + self.c) & MAX_64BIT
        self.H[3] = (self.H[3] + self.d) & MAX_64BIT
        self.H[4] = (self.H[4] + self.e) & MAX_64BIT
        self.H[5] = (self.H[5] + self.f) & MAX_64BIT
        self.H[6] = (self.H[6] + self.g) & MAX_64BIT
        self.H[7] = (self.H[7] + self.h) & MAX_64BIT


    def _print_state(self, round):
        print("State at round 0x%02x:" % round)
        print("t1 = 0x%016x, t2 = 0x%016x" % (self.t1, self.t2))
        print("k  = 0x%016x, w  = 0x%016x" % (self.k,  self.w))
        print("a  = 0x%016x, b  = 0x%016x" % (self.a,  self.b))
        print("c  = 0x%016x, d  = 0x%016x" % (self.c,  self.d))
        print("e  = 0x%016x, f  = 0x%016x" % (self.e,  self.f))
        print("g  = 0x%016x, h  = 0x%016x" % (self.g,  self.h))
        print("")


    def _sha512_round(self, round):
        self.k = self.K[round]
        self.w = self._next_w(round)
        self.t1 = self._T1(self.e, self.f, self.g, self.h, self.k, self.w)
        self.t2 = self._T2(self.a, self.b, self.c)
        self.h = self.g
        self.g = self.f
        self.f = self.e
        self.e = (self.d + self.t1) & MAX_64BIT
        self.d = self.c
        self.c = self.b
        self.b = self.a
        self.a = (self.t1 + self.t2) & MAX_64BIT


    def _next_w(self, round):
        if (round < 16):
            return self.W[round]

        else:
            tmp_w = (self._delta1(self.W[14]) +
                     self.W[9] + 
                     self._delta0(self.W[1]) +
                     self.W[0]) & MAX_64BIT
            for i in range(15):
                self.W[i] = self.W[(i+1)]
            self.W[15] = tmp_w
            return tmp_w


    def _W_schedule(self, block):
        for i in range(16):
            self.W[i] = block[i]


    def _Ch(self, x, y, z):
        return (x & y) ^ (~x & z)


    def _Maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def _sigma0(self, x):
        return (self._rotr64(x, 28) ^ self._rotr64(x, 34) ^ self._rotr64(x, 39))


    def _sigma1(self, x):
        return (self._rotr64(x, 14) ^ self._rotr64(x, 18) ^ self._rotr64(x, 41))


    def _delta0(self, x):
        return (self._rotr64(x, 1) ^ self._rotr64(x, 8) ^ self._shr64(x, 7))


    def _delta1(self, x):
        return (self._rotr64(x, 19) ^ self._rotr64(x, 61) ^ self._shr64(x, 6))
    

    def _T1(self, e, f, g, h, k, w):
        return (h + self._sigma1(e) + self._Ch(e, f, g) + k + w) & MAX_64BIT


    def _T2(self, a, b, c):
        return (self._sigma0(a) + self._Maj(a, b, c)) & MAX_64BIT


    def _rotr64(self, n, r):
        return ((n >> r) | (n << (64 - r))) & MAX_64BIT

    
    def _shr64(self, n, r):
        return (n >> r)


def compare_digests(digest, expected):
    if (digest != expected):
        print("Error:")
        print("Got:")
        print(digest)
        print("Expected:")
        print(expected)
    else:
        print("Test case ok.")
        
    
#-------------------------------------------------------------------
# main()
#
# If executed tests the ChaCha class using known test vectors.
#-------------------------------------------------------------------
def main():
    print("Testing the SHA-512 Python model.")
    print("---------------------------------")
    print

    # Single block message.
    TC1_block = [0x6162638000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000018]

    
    my_sha512 = SHA512(mode = 'MODE_SHA_512', verbose=1);
    TC1_expected = [0xDDAF35A193617ABA, 0xCC417349AE204131, 0x12E6FA4E89A97EA2, 0x0A9EEEE64B55D39A,
                    0x2192992A274FC1A8, 0x36BA3C23A3FEEBBD, 0x454D4423643CE80E, 0x2A9AC94FA54CA49F]
    my_sha512.init()
    my_sha512.next(TC1_block)
    my_digest = my_sha512.get_digest()
    compare_digests(my_digest, TC1_expected)


    my_sha512 = SHA512(mode = 'MODE_SHA_512_224', verbose=1);
    TC2_expected = [0x4634270F707B6A54, 0xDAAE7530460842E2, 0x0E37ED265CEEE9A4, 0x3E8924AA00000000]
    my_sha512.init()
    my_sha512.next(TC1_block)
    my_digest = my_sha512.get_digest()
    compare_digests(my_digest, TC2_expected)


    my_sha512 = SHA512(mode = 'MODE_SHA_512_256', verbose=1);
    TC3_expected = [0x53048E2681941EF9, 0x9B2E29B76B4C7DAB, 0xE4C2D0C634FC6D46, 0xE0E2F13107E7AF23]
    my_sha512.init()
    my_sha512.next(TC1_block)
    my_digest = my_sha512.get_digest()
    compare_digests(my_digest, TC3_expected)


    my_sha512 = SHA512(mode = 'MODE_SHA_384', verbose=1);
    TC4_expected = [0xCB00753F45A35E8B, 0xB5A03D699AC65007, 0x272C32AB0EDED163, 0x1A8B605A43FF5BED,
                    0x8086072BA1E7CC23, 0x58BAECA134C825A7]
    my_sha512.init()
    my_sha512.next(TC1_block)
    my_digest = my_sha512.get_digest()
    compare_digests(my_digest, TC4_expected)

    

#-------------------------------------------------------------------
# __name__
# Python thingy which allows the file to be run standalone as
# well as parsed from within a Python interpreter.
#-------------------------------------------------------------------
if __name__=="__main__": 
    # Run the main function.
    sys.exit(main())

#=======================================================================
# EOF sha512.py
#=======================================================================
