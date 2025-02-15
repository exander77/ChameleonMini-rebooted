#ifndef CRYPTO1_H
#define CRYPTO1_H

#include <stdint.h>
#include <stdbool.h>
#include "Crypto1_asm.h"
#include <avr/pgmspace.h>

void Crypto1GetState(uint8_t* pEven, uint8_t* pOdd);

/* Gets the current keystream-bit, without shifting the internal LFSR */
uint8_t Crypto1FilterOutput(void);

/* Set up Crypto1 cipher using the given Key, Uid and CardNonce. Also encrypts
 * the CardNonce in-place while in non-linear mode. */
void Crypto1Setup(uint8_t Key[6], uint8_t Uid[4], uint8_t CardNonce[4]);

/* Load the decrypted ReaderNonce into the Crypto1 state LFSR */
void Crypto1Auth(uint8_t EncryptedReaderNonce[4]);

/* Generate 8 Bits of key stream */
uint8_t Crypto1Byte(void);

/* Generate 4 Bits of key stream */
uint8_t Crypto1Nibble(void);

/* Generate 1 Bit of key stream */
uint8_t Crypto1Bit(uint8_t In, uint8_t AuthFilter);

/* Execute 'ClockCount' cycles on the PRNG state 'State' */
void Crypto1PRNG(uint8_t State[4], uint8_t ClockCount);

#endif //CRYPTO1_H
