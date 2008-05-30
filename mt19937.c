/* Coded by Takuji Nishimura, considering the suggestions by      */
/* Topher Cooper and Marc Rieffel in July-Aug. 1997.              */

/* This library is free software; you can redistribute it and/or   */
/* modify it under the terms of the GNU Library General Public     */
/* License as published by the Free Software Foundation; either    */
/* version 2 of the License, or (at your option) any later         */
/* version.                                                        */
/* This library is distributed in the hope that it will be useful, */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of  */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.            */
/* See the GNU Library General Public License for more details.    */
/* You should have received a copy of the GNU Library General      */
/* Public License along with this library; if not, write to the    */
/* Free Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA   */ 
/* 02111-1307  USA                                                 */

/* Copyright (C) 1997, 1999 Makoto Matsumoto and Takuji Nishimura. */
/* When you use this, send an email to: matumoto@math.keio.ac.jp   */
/* with an appropriate reference to your work.                     */

#include "mt19937.h"

#define closed_float  ( (double)genrand() * 2.3283064370807974e-10 ); /*[0,1]*/
#define open_float    ( (double)genrand() * 2.3283064365386963e-10 ); /*[0,1)*/


#define N 624
#define M 397
#define MATRIX_A 0x9908b0df  
#define UPPER_MASK 0x80000000
#define LOWER_MASK 0x7fffffff
#define TEMPERING_MASK_B 0x9d2c5680
#define TEMPERING_MASK_C 0xefc60000
#define TEMPERING_SHIFT_U(y)  (y >> 11)
#define TEMPERING_SHIFT_S(y)  (y << 7)
#define TEMPERING_SHIFT_T(y)  (y << 15)
#define TEMPERING_SHIFT_L(y)  (y >> 18)

static unsigned long mt[N];
static int mti=N+1;


void sgenrand( unsigned int seed )
   {
   int i;

   for (i=0; i < N; i++)
      {
      mt[i] = seed & 0xffff0000;
      seed = 69069 * seed + 1;
      mt[i] |= (seed & 0xffff0000) >> 16;
      seed = 69069 * seed + 1;
      }
   mti = N;
   }



unsigned int genrand()
   {
   unsigned long y;
   static unsigned long mag01[2] = {0x0, MATRIX_A};
   int kk;

   if (mti >= N)
      {
      if (mti == N+1) sgenrand( 2437 );  /* seed generator if not done */

      for (kk=0; kk < N-M; kk++)
         {
         y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
         mt[kk] = mt[kk+M] ^ (y >> 1) ^ mag01[ y & 0x1 ];
         }
      for (; kk < N-1; kk++)
         {
         y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
         mt[kk] = mt[ kk+(M-N) ] ^ (y >> 1) ^ mag01[ y & 0x1 ];
         }
      y = (mt[N-1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
      mt[N-1] = mt[M-1] ^ (y >> 1) ^ mag01[ y & 0x1 ];

      mti = 0;
      }
  
   y = mt[mti++];
   y ^= TEMPERING_SHIFT_U(y);
   y ^= TEMPERING_SHIFT_S(y) & TEMPERING_MASK_B;
   y ^= TEMPERING_SHIFT_T(y) & TEMPERING_MASK_C;
   y ^= TEMPERING_SHIFT_L(y);

   return y;
   }
