#include "Crypto1.h"

/* avoid compiler complaining at the shift macros */
#pragma GCC diagnostic ignored "-Wuninitialized"

// uncomment if platform is not avr
// #define NO_INLINE_ASM 1

#define PRNG_MASK        0x002D0000UL
/* x^16 + x^14 + x^13 + x^11 + 1 */

#define PRNG_SIZE        4 /* Bytes */
#define NONCE_SIZE       4 /* Bytes */

#define LFSR_MASK_EVEN   0x2010E1UL
#define LFSR_MASK_ODD    0x3A7394UL
/* x^48 + x^43 + x^39 + x^38 + x^36 + x^34 + x^33 + x^31 + x^29 +
 * x^24 + x^23 + x^21 + x^19 + x^13 + x^9 + x^7 + x^6 + x^5 + 1 */

#define LFSR_SIZE        6 /* Bytes */

const uint8_t TableA[32] PROGMEM = { // for first, third and fourth
	0,0,1,1,0,1,0,0,
	0,1,0,0,1,1,1,1,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0
};

const uint8_t TableB[32] PROGMEM = { // for second and fifth
	0,0,0,1,1,1,0,0,
	1,0,0,1,1,0,1,1,
	0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0
};

uint32_t StateOdd;
uint32_t StateEven;

static uint8_t Crypto1ByteAuth(uint8_t In, uint8_t AuthSet)
{
	uint8_t KeyStream = 0;
	uint8_t i;

	/* Generate 8 keystream-bits */
	for (i=0; i<8; i++) {

		/* Calculate next bit and add to KeyStream */
		uint8_t Out = Crypto1Bit(In&1,AuthSet);

		In>>=1;
		KeyStream>>=1;
		if(Out) {
			KeyStream |= (1<<7);
		}
		
	}

	return KeyStream;
}

void Crypto1Setup(uint8_t Key[6], uint8_t Uid[4], uint8_t CardNonce[4])
{

	StateOdd = 0;
	StateEven = 0;

	int i = 0, j = 0;
	for(i = 0 ; i < 6 ; i++) {

		for(j = 7 ; j > 0 ; j -= 2) {
			StateOdd = StateOdd << 1 | (Key[i]>>((j-1) ^ 7)&1);
			StateEven = StateEven << 1 | (Key[i]>>((j) ^ 7)&1);
		}
	}

	for(i=0; i<4; i++) {
		CardNonce[i] ^= Crypto1ByteAuth(Uid[i] ^ CardNonce[i], 0);
	}

}

void Crypto1Auth(uint8_t EncryptedReaderNonce[4])
{
	uint8_t i;

	/* Calculate Authentication on Nonce */
	for(i = 0 ; i < 4 ; i++) {
		Crypto1ByteAuth(EncryptedReaderNonce[i],1);
	}
}

uint8_t Crypto1Byte(void)
{
	uint8_t KeyStream = 0;
	uint8_t i;

	/* Generate 8 keystream-bits */
	for (i=0; i<8; i++) {

		/* Calculate next bit and add to KeyStream */
		uint8_t Out = Crypto1Bit(0,0);

		KeyStream>>=1;
		if(Out) {
			KeyStream |= (1<<7);
		}
		
	}

	return KeyStream;
}

uint8_t Crypto1Nibble(void)
{
	uint8_t KeyStream = 0;
	uint8_t i;

	/* Generate 4 keystream-bits */
	for (i=0; i<4; i++) {

		/* Calculate next bit and add to KeyStream */
		uint8_t Out = Crypto1Bit(0,0);

		KeyStream>>=1;
		if(Out) {
			KeyStream |= (1<<7);
		}
		
	}

	return KeyStream;
}

void Crypto1PRNG(uint8_t State[4], uint8_t ClockCount)
{
	while(ClockCount--) {
		/* Actually, the PRNG is a 32 bit register with the upper 16 bit
		* used as a LFSR. Furthermore only mask-byte 2 contains feedback at all.
		* We rely on the compiler to optimize this for us here.
		* XOR all tapped bits to a single feedback bit. */
		uint8_t Feedback = 0;

		Feedback ^= State[0] & (uint8_t) (PRNG_MASK >> 0);
		Feedback ^= State[1] & (uint8_t) (PRNG_MASK >> 8);
		Feedback ^= State[2] & (uint8_t) (PRNG_MASK >> 16);
		Feedback ^= State[3] & (uint8_t) (PRNG_MASK >> 24);

		Feedback ^= Feedback >> 4;
		Feedback ^= Feedback >> 2;
		Feedback ^= Feedback >> 1;

		/* For ease of processing convert the state into a 32 bit integer first */
		uint32_t Temp = 0;

		Temp |= (uint32_t) State[0] << 0;
		Temp |= (uint32_t) State[1] << 8;
		Temp |= (uint32_t) State[2] << 16;
		Temp |= (uint32_t) State[3] << 24;

		/* Cycle LFSR and feed back. */
		Temp >>= 1;

		if (Feedback & 0x01) {
			Temp |= (uint32_t) 1 << (8 * PRNG_SIZE - 1);
		}

		/* Store back state */
		State[0] = (uint8_t) (Temp >> 0);
		State[1] = (uint8_t) (Temp >> 8);
		State[2] = (uint8_t) (Temp >> 16);
		State[3] = (uint8_t) (Temp >> 24);
	}


}

/* Functions fa, fb and fc in filter output network. Definitions taken
 * from Timo Kasper's thesis */
#define FA(x3, x2, x1, x0) ( \
    ( (x0 | x1) ^ (x0 & x3) ) ^ ( x2 & ( (x0 ^ x1) | x3 ) ) \
)

#define FB(x3, x2, x1, x0) ( \
    ( (x0 & x1) | x2 ) ^ ( (x0 ^ x1) & (x2 | x3) ) \
)

#define FC(x4, x3, x2, x1, x0) ( \
    ( x0 | ( (x1 | x4) & (x3 ^ x4) ) ) ^ ( ( x0 ^ (x1 & x3) ) & ( (x2 ^ x3) | (x1 & x4) ) ) \
)


/* For AVR only */ 
#ifndef NO_INLINE_ASM

/* Buffer size and parity offset */
#include "../Codec/ISO14443-2A.h"

/* Table lookup for odd parity */
#include "../Common.h"

/* Special macros for optimized usage of the xmega */
/* see http://rn-wissen.de/wiki/index.php?title=Inline-Assembler_in_avr-gcc */

/* Split byte into odd and even nibbles- */
/* Used for LFSR setup. */
#define SPLIT_BYTE(__even, __odd, __byte) \
    __asm__ __volatile__ ( \
        "lsr %2"             "\n\t"   \
        "ror %0"             "\n\t"   \
        "lsr %2"             "\n\t"   \
        "ror %1"             "\n\t"   \
        "lsr %2"             "\n\t"   \
        "ror %0"             "\n\t"   \
        "lsr %2"             "\n\t"   \
        "ror %1"             "\n\t"   \
        "lsr %2"             "\n\t"   \
        "ror %0"             "\n\t"   \
        "lsr %2"             "\n\t"   \
        "ror %1"             "\n\t"   \
        "lsr %2"             "\n\t"   \
        "ror %0"             "\n\t"   \
        "lsr %2"             "\n\t"   \
        "ror %1"                      \
        : "+r" (__even), 	          \
                  "+r" (__odd),       \
          "+r" (__byte)	              \
                :                     \
        : "r0" )		

/* Shift half LFSR state stored in three registers */
/* Input is bit 0 of __in */
#define SHIFT24(__b0, __b1, __b2, __in) \
    __asm__ __volatile__ (              \
        "lsr %3"    "\n\t"              \
        "ror %2"    "\n\t"              \
        "ror %1"    "\n\t"              \
        "ror %0"                        \
        : "+r" (__b0),                  \
          "+r" (__b1),                  \
          "+r" (__b2),                  \
          "+r" (__in)                   \
        :                               \
        :   )

/* Shift half LFSR state stored in three registers    */
/* Input is bit 0 of __in                             */
/* decrypt with __stream if bit 0 of __decrypt is set */
#define SHIFT24_COND_DECRYPT(__b0, __b1, __b2, __in, __stream, __decrypt) \
    __asm__ __volatile__ ( \
        "sbrc %5, 0"  "\n\t"    \
        "eor  %3, %4" "\n\t"    \
        "lsr  %3"     "\n\t"    \
        "ror  %2"     "\n\t"    \
        "ror  %1"     "\n\t"    \
        "ror  %0"               \
        : "+r" (__b0),          \
          "+r" (__b1),          \
          "+r" (__b2),          \
          "+r" (__in)           \
        : "r"  (__stream),      \
          "r"  (__decrypt)      \
        : "r0" )		

/* Shift a byte with input from an other byte  */
/* Input is bit 0 of __in */
#define SHIFT8(__byte, __in) \
        __asm__ __volatile__ (  \
        "lsr %1"    "\n\t"      \
        "ror %0"                \
        : "+r" (__byte),        \
          "+r"  (__in)          \
                :               \
        : "r0" )
/* End AVR specific */
#else

/* Plattform independend code */

/* avoid including avr-Files in case of test */
#ifndef CODEC_BUFFER_SIZE
#define CODEC_BUFFER_SIZE           256
#endif
#ifndef ISO14443A_BUFFER_PARITY_OFFSET
#define ISO14443A_BUFFER_PARITY_OFFSET    (CODEC_BUFFER_SIZE/2)
#endif

#define SHIFT24(__b0, __b1, __b2, __in) \
               __b0 = (__b0>>1) | (__b1<<7); \
               __b1 = (__b1>>1) | (__b2<<7); \
               __b2 = (__b2>>1) | ((__in)<<7) 

#define SHIFT24_COND_DECRYPT(__b0, __b1, __b2, __in, __stream, __decrypt) \
               __b0 = (__b0>>1) | (__b1<<7); \
               __b1 = (__b1>>1) | (__b2<<7); \
               __b2 = (__b2>>1) | (((__in)^((__stream)&(__decrypt)))<<7)

#define SHIFT8(__byte, __in)  __byte = (__byte>>1) | ((__in)<<7) 

#define SPLIT_BYTE(__even, __odd, __byte) \
    __even = (__even >> 1) | (__byte<<7); __byte>>=1; \
    __odd  = (__odd  >> 1) | (__byte<<7); __byte>>=1; \
    __even = (__even >> 1) | (__byte<<7); __byte>>=1; \
    __odd  = (__odd  >> 1) | (__byte<<7); __byte>>=1; \
    __even = (__even >> 1) | (__byte<<7); __byte>>=1; \
    __odd  = (__odd  >> 1) | (__byte<<7); __byte>>=1; \
    __even = (__even >> 1) | (__byte<<7); __byte>>=1; \
    __odd  = (__odd  >> 1) | (__byte<<7)


/* Generate odd parity bit */
#define ODD_PARITY(val)	                   \
        (__extension__({                   \
        uint8_t __p = (uint8_t)(val);      \
        __p ^= ((__p >> 4)|(__p << 4)) ;   \
        __p ^= __p >> 2 ;                  \
        ((--__p) >> 1) & 1;  /* see "avr/util.h" */ \
 }))
#endif

/* Split Crypto1 state into even and odd bits            */
/* to speed up the output filter network                 */
/* Put both into one struct to enable relative adressing */
typedef struct
{
    uint8_t Even[LFSR_SIZE/2];
    uint8_t Odd[LFSR_SIZE/2];
} Crypto1LfsrState_t;
static Crypto1LfsrState_t State = {{0},{0}};


/* Debug output of state */
void Crypto1GetState(uint8_t* pEven, uint8_t* pOdd)
{
    if (pEven)
    {
        pEven[0] = State.Even[0];
        pEven[1] = State.Even[1];
        pEven[2] = State.Even[2];
    }
    if (pOdd)
    {
        pOdd[0] = State.Odd[0];
        pOdd[1] = State.Odd[1];
        pOdd[2] = State.Odd[2];
    }

}

/* Proceed LFSR by one clock cycle */
/* Prototype to force inlining */
static __inline__ uint8_t Crypto1LFSRbyteFeedback (uint8_t E0,
                            uint8_t E1,
                            uint8_t E2,
                            uint8_t O0,
                            uint8_t O1,
                            uint8_t O2) __attribute__((always_inline));
static uint8_t Crypto1LFSRbyteFeedback (uint8_t E0,
                            uint8_t E1,
                            uint8_t E2,
                            uint8_t O0,
                            uint8_t O1,
                            uint8_t O2) 
{
    uint8_t Feedback;

    /* Calculate feedback according to LFSR taps. XOR all state bytes
     * into a single bit. */
    Feedback  = E0 & (uint8_t) (LFSR_MASK_EVEN );
    Feedback ^= E1 & (uint8_t) (LFSR_MASK_EVEN >> 8);
    Feedback ^= E2 & (uint8_t) (LFSR_MASK_EVEN >> 16);

    Feedback ^= O0 & (uint8_t) (LFSR_MASK_ODD );
    Feedback ^= O1 & (uint8_t) (LFSR_MASK_ODD >> 8);
    Feedback ^= O2 & (uint8_t) (LFSR_MASK_ODD >> 16);

    /* fold 8 into 1 bit */
    Feedback ^= ((Feedback >> 4)|(Feedback << 4)); /* Compiler uses a swap for this (fast!) */
    Feedback ^= Feedback >> 2;
    Feedback ^= Feedback >> 1;

    return(Feedback);
}

/* Proceed LFSR by one clock cycle */
/* Prototype to force inlining */
static __inline__ void Crypto1LFSR (uint8_t In) __attribute__((always_inline));
static void Crypto1LFSR(uint8_t In) {
    register uint8_t Temp0, Temp1, Temp2;
    uint8_t Feedback;

    /* Load even state. */
    Temp0 = State.Even[0];
    Temp1 = State.Even[1];
    Temp2 = State.Even[2];


    /* Calculate feedback according to LFSR taps. XOR all 6 state bytes
     * into a single bit. */
    Feedback  = Temp0 & (uint8_t) (LFSR_MASK_EVEN >> 0);
    Feedback ^= Temp1 & (uint8_t) (LFSR_MASK_EVEN >> 8);
    Feedback ^= Temp2 & (uint8_t) (LFSR_MASK_EVEN >> 16);

    Feedback ^= State.Odd[0] & (uint8_t) (LFSR_MASK_ODD >> 0);
    Feedback ^= State.Odd[1] & (uint8_t) (LFSR_MASK_ODD >> 8);
    Feedback ^= State.Odd[2] & (uint8_t) (LFSR_MASK_ODD >> 16);

    Feedback ^= ((Feedback >> 4)|(Feedback << 4)); /* Compiler uses a swap for this (fast!) */
    Feedback ^= Feedback >> 2;
    Feedback ^= Feedback >> 1;

    /* Now the shifting of the Crypto1 state gets more complicated when
     * split up into even/odd parts. After some hard thinking, one can
     * see that after one LFSR clock cycle
     * - the new even state becomes the old odd state
     * - the new odd state becomes the old even state right-shifted by 1. */
    SHIFT24(Temp0, Temp1, Temp2, Feedback);

    /* Convert even state back into byte array and swap odd/even state
    * as explained above. */
    State.Even[0] = State.Odd[0];
    State.Even[1] = State.Odd[1];
    State.Even[2] = State.Odd[2];

    State.Odd[0] = Temp0;
    State.Odd[1] = Temp1;
    State.Odd[2] = Temp2;
}
