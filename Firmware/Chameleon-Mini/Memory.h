/*
 * Flash.h
 *
 *  Created on: 20.03.2013
 *      Author: skuser
 */

#ifndef MEMORY_H_
#define MEMORY_H_

#include "Common.h"

#define MEMORY_INIT_VALUE			0x00

#define MEMORY_FLASH_USART	USARTD0
#define MEMORY_FLASH_PORT	PORTD
#define MEMORY_FLASH_CS		PIN4_bm
#define MEMORY_FLASH_MOSI	PIN3_bm
#define MEMORY_FLASH_MISO	PIN2_bm
#define MEMORY_FLASH_SCK	PIN1_bm

#define MEMORY_PAGE_SIZE		256
#define MEMORY_SIZE_PER_SETTING_4K	4096
#define MEMORY_SIZE_PER_SETTING_1K	1024


// extra config memory section
// 8 slots possible, 
// 2byte ataq
// 1byte sak
// 1 bit magic gen1a
// 1 bit magic gen1b
// 1 bit magic gen2

void FlashReadManufacturerDeviceInfo(void* Buffer);

void MemoryInit(void);
void MemoryReadBlock(void* Buffer, uint16_t Address, uint16_t ByteCount);
void MemoryWriteBlock(const void* Buffer, uint16_t Address, uint16_t ByteCount);
void MemorySetBlock(uint8_t Value, uint16_t Address, uint16_t ByteCount);

void MemoryClear(void);

/* For use with XModem */
bool MemoryUploadBlock(void* Buffer, uint16_t BlockAddress, uint16_t ByteCount);
bool MemoryDownloadBlock(void* Buffer, uint16_t BlockAddress, uint16_t ByteCount);

/* EEPROM functions */
uint16_t WriteEEPBlock(uint16_t Address, const void *SrcPtr, uint16_t ByteCount);
uint16_t ReadEEPBlock(uint16_t Address, void *DestPtr, uint16_t ByteCount);

void Read_Save(void* Buffer, uint16_t Address, uint16_t ByteCount);
void Write_Save(void* Buffer, uint16_t Address, uint16_t ByteCount);
#endif /* MEMORY_H_ */
