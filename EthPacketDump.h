/*
* EthpacketDump.h
* Ethernet packet dump library header
*/

#ifndef _ETHPACKETDUMP_LIB_H
#define _ETHPACKETDUMP_LIB_H

#include <inttypes.h>
#include <wprogram.h>
#include <avr/pgmspace.h>

/* Any #defines */

class EthPacketDump {
  private:
	HardwareSerial *_Serial;

  public:
  	EthPacketDump( void );
	void begin( HardwareSerial *serIn, boolean dumpPacket, boolean ethernetDump,
			boolean arpDump, boolean packetDetails );

	void printIP( uint8_t *buf, int startByte );
	void printMac( uint8_t *buf, int startByte );

	void packetDump( uint8_t *buf, int plen );

};
#endif //_ETHPACKETDUMP_H

