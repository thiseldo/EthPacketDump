/***********************************************************************
 * Basic packet dumping library for ENC28J60 received packets
 * Uses Serial.print class to output packet details.
 * Andrew Lindsay
 ***********************************************************************/

#include "EthPacketDump.h"
#include "net.h"
#include <inttypes.h>
#include <wprogram.h>
#include <avr/pgmspace.h>

char tmpNumStr[8];
boolean dumpPacket = true;
boolean ethernetDump = true;
boolean arpDump = true;
boolean packetDetails = true;

// Default constructor
EthPacketDump::EthPacketDump( void  ) {
	_Serial = NULL;
}

// Begin method 
void EthPacketDump::begin( HardwareSerial *serIn, boolean dumpPacketIn, boolean ethernetDumpIn,
		boolean arpDumpIn, boolean packetDetailsIn ) {
	_Serial = serIn;
	_Serial->begin(19200);
	_Serial->println("EthPacketDump");
	dumpPacket = dumpPacketIn;
	ethernetDump = ethernetDumpIn;
	arpDump = arpDumpIn;
	packetDetails = packetDetailsIn;
}

// Output a mac address from buffer from startByte
void EthPacketDump::printMac( uint8_t *buf, int startByte ) {
  for( int i = 0; i < 6; i++ ) {
    sprintf(tmpNumStr, "%02x", buf[startByte + i] );
    _Serial->print( tmpNumStr );
    if( i<5 )
      _Serial->print(":" );
  }
}

// Output a ip address from buffer from startByte
void EthPacketDump::printIP( uint8_t *buf, int startByte ) {
  for( int i = 0; i < 4; i++ ) {
    _Serial->print( buf[startByte + i ], DEC );
    if( i<3 )
      _Serial->print("." );
  }
}

// main packet dumping function, just give it pointer to packet start and received length
void EthPacketDump::packetDump( uint8_t *buf, int plen ) {

  if( plen == 0 ) 
    return;    // Nothing to dump

  if( dumpPacket ) {
    _Serial->print("Packet length: " );
    _Serial->println( plen, DEC ); 

    // Hex dump of packet
    _Serial->print("Hex packet dump");
    for( int i = 0; i < plen; i++ ) {
      if( i % 16 == 0 ) {
        _Serial->println();
        sprintf(tmpNumStr, "%04x: ", i );
        _Serial->print( tmpNumStr );
      }
      sprintf(tmpNumStr, "%02x ", buf[i] );
      _Serial->print( tmpNumStr );
    }
    _Serial->println();
  }
  int packetType = (buf[ETH_TYPE_H_P] << 8) + buf[ETH_TYPE_L_P];

  if( ethernetDump ) {
    // Display details of the packet in easy to read format
    // Ethernet headers - first 14 bytes
    _Serial->println("Ethernet Header");
    _Serial->print( "Dest MAC: " );
    printMac( buf, ETH_DST_MAC );

    _Serial->print( "\nSrc MAC: " );
    printMac( buf, ETH_SRC_MAC );

    _Serial->print( "\nType: " );
    sprintf(tmpNumStr, "%04x ", packetType );
    _Serial->print( tmpNumStr );
    if( packetType == 0x800 )
      _Serial->println("IP");
    else if( packetType == 0x806 )
      _Serial->println("ARP");
    else
      _Serial->println();
  }   
  // ARP details
  if( packetType == 0x0806  && arpDump) {
    _Serial->println("\nARP Details");
    _Serial->print( "ARP type: " );
    sprintf(tmpNumStr, "%04x ", (buf[ETH_ARP_OPCODE_H_P] << 8) + buf[ETH_ARP_OPCODE_L_P]);
    _Serial->println( tmpNumStr );
    _Serial->print( "Src MAC: " );
    printMac( buf, ETH_ARP_SRC_MAC_P );
    _Serial->print( " Src IP: " );
    printIP( buf, ETH_ARP_SRC_IP_P );
    _Serial->print( "\nDest MAC: " );
    printMac( buf, ETH_ARP_DST_MAC_P );
    _Serial->print( " Dest IP: " );
    printIP( buf, ETH_ARP_DST_IP_P );

    _Serial->println();
  }
  if( packetType == 0x800 && packetDetails ) { 
    _Serial->println("\nIP Details");
    // IP headers
    _Serial->print("Version: v" );
    _Serial->print( (buf[IP_HEADER_LEN_VER_P] & 0xf0) >> 4 );
    _Serial->print( " Header Len: ");
    int ipHeaderLen = (buf[IP_HEADER_LEN_VER_P] & 0x0f) << 2;
    _Serial->print( ipHeaderLen, DEC );
    _Serial->print( " Total IP length: " );
    int ipLen = (buf[IP_TOTLEN_H_P] << 8) + buf[IP_TOTLEN_L_P];
    _Serial->println( ipLen, DEC );

    _Serial->print( "Src IP: " );
    printIP( buf, IP_SRC_P );

    _Serial->print( " Dest IP: " );
    printIP( buf, IP_DST_P );

    _Serial->print( "\nProtocol: " );
    int proto = buf[IP_PROTO_P];
    _Serial->print( proto, DEC);
    if( proto == IP_PROTO_ICMP_V ) 
      _Serial->println( " - ICMP" );
    else if( proto == IP_PROTO_TCP_V ) 
      _Serial->println( " - TCP" );
    else if( proto == IP_PROTO_UDP_V ) 
      _Serial->println( " - UDP" );
    else
      _Serial->println();

//    if( proto == IP_PROTO_ICMP_V ) {
      // ICMP headers
//      _Serial->println( " ICMP" );
//    }

    if( proto == IP_PROTO_TCP_V ) {
      // TCP headers
      unsigned int srcPort = (buf[TCP_SRC_PORT_H_P] << 8) + buf[TCP_SRC_PORT_L_P];
      _Serial->print( "SRC Port: " );
      _Serial->print( srcPort, DEC );
      unsigned int dstPort = (buf[TCP_DST_PORT_H_P] << 8) + buf[TCP_DST_PORT_L_P];
      _Serial->print( " DST Port: " );
      _Serial->println( dstPort, DEC );
      _Serial->print( "Seq: " );
      _Serial->print( buf[TCP_SEQ_H_P], HEX );
      _Serial->print( buf[TCP_SEQ_H_P+1], HEX );
      _Serial->print( buf[TCP_SEQ_H_P+2], HEX );
      _Serial->print( buf[TCP_SEQ_H_P+3], HEX );

      _Serial->print( " Seq Ack: " );
      _Serial->print( buf[TCP_SEQACK_H_P], HEX );
      _Serial->print( buf[TCP_SEQACK_H_P+1], HEX );
      _Serial->print( buf[TCP_SEQACK_H_P+2], HEX );
      _Serial->println( buf[TCP_SEQACK_H_P+3], HEX );

      _Serial->print( "Flags: " );
      _Serial->print( buf[TCP_FLAGS_P], HEX );
      _Serial->print( " - " );
      if( buf[TCP_FLAGS_P] & 0x02 ) _Serial->print( "SYN " );
      if( buf[TCP_FLAGS_P] & 0x01 ) _Serial->print( "FIN " );
      if( buf[TCP_FLAGS_P] & 0x04 ) _Serial->print( "RST " );
      if( buf[TCP_FLAGS_P] & 0x08 ) _Serial->print( "PUSH " );
      if( buf[TCP_FLAGS_P] & 0x10 ) _Serial->print( "ACK " );
      _Serial->println();

      _Serial->print( "TCP header Len: " );
      int tcpHeaderLen = (buf[TCP_HEADER_LEN_P] >> 4) * 4;
      _Serial->print( tcpHeaderLen, DEC );

      _Serial->print( " TCP Win Size: " );
      _Serial->print( buf[TCP_WIN_SIZE], HEX );
      _Serial->print( buf[TCP_WIN_SIZE+1], HEX );

      _Serial->print( " TCP Checksum: " );
      _Serial->print( buf[TCP_CHECKSUM_H_P], HEX );
      _Serial->print( buf[TCP_CHECKSUM_L_P], HEX );

      if( tcpHeaderLen > TCP_HEADER_LEN_PLAIN ) {
        _Serial->print( " Options: " );
        _Serial->println( buf[TCP_OPTIONS_P], HEX );
      } else {
	_Serial->println();
      }

      // packet made up of
      //	  14 Ethernet header
      //	+ 20 IP header
      //	+ 20 tcp header
      //	+ payload.
      int payloadLen = ipLen - ipHeaderLen - tcpHeaderLen;
      _Serial->print("Payload Data len: " );
      _Serial->println( payloadLen, DEC );

      if( payloadLen > 0 ) {
        char asciiBuf[16];
        int asciiBufCount = 0;
        _Serial->println("Payload dump");
        for( int i = 0; i < payloadLen; i++ ) {
          if( i % 16 == 0 ) {
            if( asciiBufCount > 0 ) {
              _Serial->print( "  " );
              for( int j = 0; j < 16; j++ ) {
                if( asciiBuf[j] > 31 && asciiBuf[j] <127 ) {
                  _Serial->print( asciiBuf[j] );
                } 
                else {
                  _Serial->print(".");
                }
              }
              asciiBufCount = 0;
            }
            _Serial->println();
            sprintf(tmpNumStr, "%04x: ", i );
            _Serial->print( tmpNumStr );
          }
          sprintf(tmpNumStr, "%02x ", buf[14 + ipHeaderLen + tcpHeaderLen + i] );
          asciiBuf[i % 16] = buf[14 + ipHeaderLen + tcpHeaderLen + i];
          asciiBufCount++;
          _Serial->print( tmpNumStr );
        }
        if( asciiBufCount > 0 ) {
          for( int j = asciiBufCount; j < 16; j++ ) {
            _Serial->print( "   " );
          }
          _Serial->print( "  " );
          for( int j = 0; j < asciiBufCount; j++ ) {
            if( asciiBuf[j] > 31 && asciiBuf[j] <127 ) {
              _Serial->print( asciiBuf[j] );
            } 
            else {
              _Serial->print(".");
            }
          }
        }
        _Serial->println();
      }
    }

    if( proto == IP_PROTO_UDP_V ) {
      // UDP headers
      unsigned int srcPort = (buf[UDP_SRC_PORT_H_P] << 8) + buf[UDP_SRC_PORT_L_P];
      _Serial->print( "SRC Port: " );
      _Serial->print( srcPort, DEC );
      unsigned int dstPort = (buf[UDP_DST_PORT_H_P] << 8) + buf[UDP_DST_PORT_L_P];
      _Serial->print( " DST Port: " );
      _Serial->print( dstPort, DEC );
      _Serial->println();

      _Serial->print("Len: ");
      _Serial->println( (buf[UDP_LEN_H_P] << 8) + buf[UDP_LEN_L_P]);
      if( srcPort != 0x7b )
        _Serial->println("Port is not NTP" );
    }
  }
}

