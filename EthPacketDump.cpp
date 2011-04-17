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

int packetType = 0;
int ipHeaderLen = 0;
int ipLen = 0;
int proto = 0;

// Default constructor
EthPacketDump::EthPacketDump( void  ) {
	_Serial = NULL;
}

// Display string stored in flash memory
void EthPacketDump::print( const prog_char *progmem_s ) {
        char c;
        while ((c = pgm_read_byte(progmem_s++))) {
                _Serial->print( c );
        }
}

// Display string stored in flash memory and add \n
void EthPacketDump::println( const prog_char *progmem_s ) {
	print( progmem_s );
	_Serial->println();
}

// Begin method 
void EthPacketDump::begin( HardwareSerial *serIn, boolean dumpPacketIn, boolean ethernetDumpIn,
		boolean arpDumpIn, boolean packetDetailsIn ) {
	_Serial = serIn;
	_Serial->begin(19200);
	println( PSTR( "EthPacketDump" ));
	dumpPacket = dumpPacketIn;
	ethernetDump = ethernetDumpIn;
	arpDump = arpDumpIn;
	packetDetails = packetDetailsIn;
}

// Output a mac address from buffer from startByte
void EthPacketDump::printMac( uint8_t *buf, int startByte ) {
  for( int i = 0; i < 6; i++ ) {
    sprintf(tmpNumStr, "%02x", buf[startByte + i] );
    //_Serial->print( tmpNumStr );
    _Serial->print( tmpNumStr );
    if( i<5 )
      print( PSTR(":") );
  }
}

// Output a ip address from buffer from startByte
void EthPacketDump::printIP( uint8_t *buf, int startByte ) {
  for( int i = 0; i < 4; i++ ) {
    _Serial->print( buf[startByte + i ], DEC );
    if( i<3 )
      print( PSTR(".") );
  }
}

// main packet dumping function, just give it pointer to packet start and received length
void EthPacketDump::packetDump( uint8_t *buf, int plen ) {

  if( plen == 0 ) 
    return;    // Nothing to dump

  if( dumpPacket ) {
    dumpHex( buf, plen );
  }
  packetType = (buf[ETH_TYPE_H_P] << 8) + buf[ETH_TYPE_L_P];

  if( ethernetDump ) {
    dumpEthernetHeader( buf, plen );
  }   

  // ARP details
  if( packetType == 0x0806  && arpDump) {
    dumpArp( buf, plen );
  }

  if( packetType == 0x800 && packetDetails ) { 
    //_Serial->println("\nIP Details");
    println( PSTR( "\nIP Details" ) );
    dumpIpHeader( buf, plen );
    ipHeaderLen = (buf[IP_HEADER_LEN_VER_P] & 0x0f) << 2;
    ipLen = (buf[IP_TOTLEN_H_P] << 8) + buf[IP_TOTLEN_L_P];
    proto = buf[IP_PROTO_P];

    if( proto == IP_PROTO_TCP_V ) {
      dumpTcp( buf, plen );
      // TCP headers
      unsigned int srcPort = (buf[TCP_SRC_PORT_H_P] << 8) + buf[TCP_SRC_PORT_L_P];
      print( PSTR("SRC Port: ") );
      _Serial->print( srcPort, DEC );
      unsigned int dstPort = (buf[TCP_DST_PORT_H_P] << 8) + buf[TCP_DST_PORT_L_P];
      print( PSTR(" DST Port: ") );
      _Serial->println( dstPort, DEC );
      print( PSTR( "Seq: ") );
      _Serial->print( buf[TCP_SEQ_H_P], HEX );
      _Serial->print( buf[TCP_SEQ_H_P+1], HEX );
      _Serial->print( buf[TCP_SEQ_H_P+2], HEX );
      _Serial->print( buf[TCP_SEQ_H_P+3], HEX );

      print( PSTR( " Seq Ack: ") );
      _Serial->print( buf[TCP_SEQACK_H_P], HEX );
      _Serial->print( buf[TCP_SEQACK_H_P+1], HEX );
      _Serial->print( buf[TCP_SEQACK_H_P+2], HEX );
      _Serial->println( buf[TCP_SEQACK_H_P+3], HEX );

      print( PSTR( "Flags: " ) );
      _Serial->print( buf[TCP_FLAGS_P], HEX );
      _Serial->print( PSTR( " - " ) );
      if( buf[TCP_FLAGS_P] & 0x02 ) print( PSTR( "SYN " ) );
      if( buf[TCP_FLAGS_P] & 0x01 ) print( PSTR( "FIN " ) );
      if( buf[TCP_FLAGS_P] & 0x04 ) print( PSTR( "RST " ) );
      if( buf[TCP_FLAGS_P] & 0x08 ) print( PSTR( "PUSH " ) );
      if( buf[TCP_FLAGS_P] & 0x10 ) print( PSTR( "ACK " ) );
      _Serial->println();

      print( PSTR( "TCP header Len: " ) );
      int tcpHeaderLen = (buf[TCP_HEADER_LEN_P] >> 4) * 4;
      _Serial->print( tcpHeaderLen, DEC );

      print( PSTR( " TCP Win Size: " ) );
      _Serial->print( buf[TCP_WIN_SIZE], HEX );
      _Serial->print( buf[TCP_WIN_SIZE+1], HEX );

      print( PSTR( " TCP Checksum: " ) );
      _Serial->print( buf[TCP_CHECKSUM_H_P], HEX );
      _Serial->print( buf[TCP_CHECKSUM_L_P], HEX );

      if( tcpHeaderLen > TCP_HEADER_LEN_PLAIN ) {
        print( PSTR( " Options: " ) );
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
      print( PSTR( "Payload Data len: " ) );
      _Serial->println( payloadLen, DEC );

      if( payloadLen > 0 ) {
        char asciiBuf[16];
        int asciiBufCount = 0;
        println( PSTR( "Payload dump" ));
        dumpHexAscii( buf, 14 + ipHeaderLen + tcpHeaderLen, payloadLen );
      }
    }

    if( proto == IP_PROTO_UDP_V ) {
      // UDP headers
      unsigned int srcPort = (buf[UDP_SRC_PORT_H_P] << 8) + buf[UDP_SRC_PORT_L_P];
      print( PSTR( "SRC Port: " ) );
      _Serial->print( srcPort, DEC );
      unsigned int dstPort = (buf[UDP_DST_PORT_H_P] << 8) + buf[UDP_DST_PORT_L_P];
      print( PSTR( " DST Port: " ) );
      _Serial->print( dstPort, DEC );
      _Serial->println();

      print( PSTR( "Len: " ));
      _Serial->println( (buf[UDP_LEN_H_P] << 8) + buf[UDP_LEN_L_P]);
      // Display full info depending on protocol/ports
      switch( srcPort ) {
	      case 53:		// DNS
		      dumpDns( buf, plen );
		      break;
	      case 67:		// DHCP Client
	      case 68:		// DHCP Server
		      dumpDhcp( buf, plen );
		      break;
	      case 0x7b:	// NTP
		      dumpNtp( buf, plen );
		      break;

	      default:
		      break;
      }
    }
  }
}


// Dump hex and ascii in buffer from offset for length plen
void EthPacketDump::dumpHexAscii( uint8_t *buf, int offset, int payloadLen ) {

  char asciiBuf[16];
  int asciiBufCount = 0;
  for( int i = 0; i < payloadLen; i++ ) {
    if( i % 16 == 0 ) {
      if( asciiBufCount > 0 ) {
        _Serial->print( "  " );
        for( int j = 0; j < 16; j++ ) {
          if( asciiBuf[j] > 31 && asciiBuf[j] <127 ) {
            _Serial->print( asciiBuf[j] );
          } 
          else {
            print( PSTR( "." ));
          }
        }
        asciiBufCount = 0;
      }
      _Serial->println();
      sprintf(tmpNumStr, "%04x: ", i );
      _Serial->print( tmpNumStr );
    }
    sprintf(tmpNumStr, "%02x ", buf[i] );
    asciiBuf[i % 16] = buf[i];
    asciiBufCount++;
    _Serial->print( tmpNumStr );
  }
  if( asciiBufCount > 0 ) {
    for( int j = asciiBufCount; j < 16; j++ ) {
      print(  PSTR( "   " ) );
    }
    print( PSTR ( "  " ) );
    for( int j = 0; j < asciiBufCount; j++ ) {
      if( asciiBuf[j] > 31 && asciiBuf[j] <127 ) {
        _Serial->print( asciiBuf[j] );
      } 
      else {
        print( PSTR( "." ));
      }
    }
  }
  _Serial->println();
}

void EthPacketDump::dumpHex( uint8_t *buf, int plen ) {
  print(PSTR( "Packet length: " ) );
  _Serial->println( plen, DEC ); 

  // Hex dump of packet
  print(PSTR( "Hex packet dump" ));
  dumpHexAscii( buf, 0, plen );
}


void EthPacketDump::dumpEthernetHeader( uint8_t *buf, int plen ) {
  // Display details of the packet in easy to read format
  // Ethernet headers - first 14 bytes
  println(PSTR( "Ethernet Header" ));
  print( PSTR( "Dest MAC: " ) );
  printMac( buf, ETH_DST_MAC );

  print( PSTR( "\nSrc MAC: " ) );
  printMac( buf, ETH_SRC_MAC );

  print( PSTR( "\nType: " ) );
  sprintf(tmpNumStr, "%04x ", packetType );
  _Serial->print( tmpNumStr );
  if( packetType == 0x800 )
    println(PSTR( "IP" ));
  else if( packetType == 0x806 )
    println(PSTR( "ARP" ));
  else
  _Serial->println();
}


void EthPacketDump::dumpArp( uint8_t *buf, int plen ) {
  println(PSTR( "\nARP Details" ));
  print( PSTR( "ARP Operation: "));
  int oper = (buf[ETH_ARP_OPCODE_H_P] << 8) + buf[ETH_ARP_OPCODE_L_P];
  sprintf(tmpNumStr, "%04x ", oper);
  _Serial->print( tmpNumStr );
  _Serial->print( " - " );

  if( oper == 1 )
    println(PSTR( "Request" ));
  else if( oper == 2 )
    println(PSTR( "Response" ));
  else
    println(PSTR( "Unknown" ));

  print( PSTR( "Src MAC: "  ));
  printMac( buf, ETH_ARP_SRC_MAC_P );
  print( PSTR( " Src IP: "  ));
  printIP( buf, ETH_ARP_SRC_IP_P );
  print( PSTR( "\nDest MAC: "  ));
  printMac( buf, ETH_ARP_DST_MAC_P );
  print( PSTR( " Dest IP: "  ));
  printIP( buf, ETH_ARP_DST_IP_P );

  _Serial->println();
}


void EthPacketDump::dumpIpHeader( uint8_t *buf, int plen ) {
  // IP headers
  int ipHeaderLen = (buf[IP_HEADER_LEN_VER_P] & 0x0f) << 2;
  int ipLen = (buf[IP_TOTLEN_H_P] << 8) + buf[IP_TOTLEN_L_P];
  print(PSTR( "Version: v" ) );
  _Serial->print( (buf[IP_HEADER_LEN_VER_P] & 0xf0) >> 4 );
  print( PSTR( " Header Len: " ));
  _Serial->print( ipHeaderLen, DEC );
  print( PSTR( " Total IP length: " ) );
  _Serial->println( ipLen, DEC );

  print( PSTR( "Src IP: " ) );
  printIP( buf, IP_SRC_P );

  print( PSTR( " Dest IP: " ) );
  printIP( buf, IP_DST_P );

  print( PSTR( "\nProtocol: " ) );
  int proto = buf[IP_PROTO_P];
  _Serial->print( proto, DEC);
  if( proto == IP_PROTO_ICMP_V ) 
    println( PSTR( " - ICMP" ) );
  else if( proto == IP_PROTO_TCP_V ) 
    println( PSTR( " - TCP" ) );
  else if( proto == IP_PROTO_UDP_V ) 
    println( PSTR( " - UDP" ) );
  else
    _Serial->println();
}

void EthPacketDump::dumpTcp( uint8_t *buf, int plen ) {
  // TCP headers
  unsigned int srcPort = (buf[TCP_SRC_PORT_H_P] << 8) + buf[TCP_SRC_PORT_L_P];
  unsigned int dstPort = (buf[TCP_DST_PORT_H_P] << 8) + buf[TCP_DST_PORT_L_P];
  int tcpHeaderLen = (buf[TCP_HEADER_LEN_P] >> 4) * 4;
  print( PSTR( "SRC Port: " ) );
  _Serial->print( srcPort, DEC );
  print( PSTR( " DST Port: " ) );
  _Serial->println( dstPort, DEC );
  print( PSTR( "Seq: " ) );
  _Serial->print( buf[TCP_SEQ_H_P], HEX );
  _Serial->print( buf[TCP_SEQ_H_P+1], HEX );
  _Serial->print( buf[TCP_SEQ_H_P+2], HEX );
  _Serial->print( buf[TCP_SEQ_H_P+3], HEX );

  print( PSTR( " Seq Ack: " ) );
  _Serial->print( buf[TCP_SEQACK_H_P], HEX );
  _Serial->print( buf[TCP_SEQACK_H_P+1], HEX );
  _Serial->print( buf[TCP_SEQACK_H_P+2], HEX );
  _Serial->println( buf[TCP_SEQACK_H_P+3], HEX );

  print( PSTR( "Flags: " ) );
  _Serial->print( buf[TCP_FLAGS_P], HEX );
  print( PSTR( " - " ) );
  if( buf[TCP_FLAGS_P] & 0x02 ) print( PSTR( "SYN " ) );
  if( buf[TCP_FLAGS_P] & 0x01 ) print( PSTR( "FIN " ) );
  if( buf[TCP_FLAGS_P] & 0x04 ) print( PSTR( "RST " ) );
  if( buf[TCP_FLAGS_P] & 0x08 ) print( PSTR( "PUSH " ) );
  if( buf[TCP_FLAGS_P] & 0x10 ) print( PSTR( "ACK " ) );
  _Serial->println();

  print( PSTR( "TCP header Len: " ) );
  _Serial->print( tcpHeaderLen, DEC );

  print( PSTR( " TCP Win Size: " ) );
  _Serial->print( buf[TCP_WIN_SIZE], HEX );
  _Serial->print( buf[TCP_WIN_SIZE+1], HEX );

  print( PSTR( " TCP Checksum: " ) );
  _Serial->print( buf[TCP_CHECKSUM_H_P], HEX );
  _Serial->print( buf[TCP_CHECKSUM_L_P], HEX );

  if( tcpHeaderLen > TCP_HEADER_LEN_PLAIN ) {
    print( PSTR( " Options: " ) );
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
  print( PSTR( "Payload Data len: " ) );
  _Serial->println( payloadLen, DEC );

  if( payloadLen > 0 ) {
    char asciiBuf[16];
    int asciiBufCount = 0;
    println( PSTR( "Payload dump" ));
    dumpHexAscii( buf, 14 + ipHeaderLen + tcpHeaderLen, payloadLen );
  }
}


void EthPacketDump::dumpDns( uint8_t *buf, int plen ) {
  // Analyze DNS response
  print( PSTR( "Flags: " ));
  _Serial->print(buf[UDP_DATA_P+2], HEX);
  _Serial->print(" ");
  _Serial->println(buf[UDP_DATA_P+3], HEX);

  print( PSTR( "Questions: " ));
  _Serial->print(buf[UDP_DATA_P+4], HEX);
  _Serial->print(" ");
  _Serial->println(buf[UDP_DATA_P+5], HEX);

  print( PSTR( "Answer RRS: " ));
  _Serial->print(buf[UDP_DATA_P+6], HEX);
  _Serial->print(" ");
  int numans = buf[UDP_DATA_P+7];
  _Serial->println(buf[UDP_DATA_P+7], HEX);

  print( PSTR( "Authority RRS: " ));
  _Serial->print(buf[UDP_DATA_P+8], HEX);
  _Serial->print(" ");
  _Serial->println(buf[UDP_DATA_P+9], HEX);

  print( PSTR( "Additional RRS: " ));
  _Serial->print(buf[UDP_DATA_P+10], HEX);
  print( PSTR( " " ));
  _Serial->println(buf[UDP_DATA_P+11], HEX);

  print( PSTR( "Query: " ) );
  int x = 0;
  while( buf[UDP_DATA_P+12 + x] != 0 ) {
    _Serial->print(buf[UDP_DATA_P+12 + x] );
    x++;
  }
  _Serial->println();
  x++;  // skip terminating 0

  print(PSTR( "Type: " ));
  _Serial->print(buf[UDP_DATA_P+12+x], HEX);
  _Serial->print(" ");
  x++;
  _Serial->println(buf[UDP_DATA_P+12+x], HEX);
  x++;

  print(PSTR( "Class: " ));
  _Serial->print(buf[UDP_DATA_P+12+x], HEX);
  _Serial->print(" ");
  x++;
  _Serial->println(buf[UDP_DATA_P+12+x], HEX);
  x++;
  // Now at start of first answer

  for( int ansnum=1; ansnum <= numans; ansnum++ ) {
    print( PSTR( "Answer " ));
    _Serial->println(ansnum, DEC);

    print( PSTR( "Name: " ) );
    _Serial->print(buf[UDP_DATA_P+12+x], HEX);
    print( PSTR( " " ));
    x++;
    _Serial->println(buf[UDP_DATA_P+12+x], HEX);
    x++;

    print( PSTR( "Type: " ) );
    _Serial->print(buf[UDP_DATA_P+12+x], HEX);
    print(PSTR( " " ));
    x++;
    int anstype = buf[UDP_DATA_P+12+x];
    _Serial->println(buf[UDP_DATA_P+12+x], HEX);
    x++;

    if( anstype == 1 ) {
      println( PSTR( "TYPE A record!" ));
    }

    print(  PSTR( "Class: " ) );
    _Serial->print(buf[UDP_DATA_P+12+x], HEX);
    print( PSTR( " " ));
    x++;
    _Serial->println(buf[UDP_DATA_P+12+x], HEX);
    x++;

    print( PSTR( "TTL: " ) );
    _Serial->print(buf[UDP_DATA_P+12+x], HEX);
    print( PSTR( " " ));
    x++;
    _Serial->print(buf[UDP_DATA_P+12+x], HEX);
    print(PSTR( " " ));
    x++;
    _Serial->print(buf[UDP_DATA_P+12+x], HEX);
    print(PSTR( " " ));
    x++;
    _Serial->println(buf[UDP_DATA_P+12+x], HEX);
    x++;

    print( PSTR( "Data Length: " ) );
    _Serial->print(buf[UDP_DATA_P+12+x], HEX);
    print( PSTR( " " ));
    x++;
    int alen = buf[UDP_DATA_P+12+x];
    _Serial->println(buf[UDP_DATA_P+12+x], HEX);
    x++;

    print( PSTR( "Data: " ) );
    for( int dp=0; dp < alen; dp++ ){
      _Serial->print(buf[UDP_DATA_P+12+x], DEC);
      print( PSTR( "." ));
      x++;
    }
    _Serial->println();
  }

  // there might be multiple answers, we use only the first one
  //
  // UDP_DATA_P+12+querylen is first byte of first answer.
  // The answer contains again the domain name and we need to
  // jump over it to find the IP. This part can be abbreviated by
  // the use of 2 byte pointers. See RFC 1035.
  int i=12+buf[UDP_DATA_P]; // we encoded the query len into tid
  print( PSTR( "Query len is " ));
  _Serial->println(i, DEC );
  if (buf[UDP_DATA_P+i] & 0xc0) {
    // pointer
    i+=2;
  } else {
    // we just search for the first, zero=root domain
    // all other octets must be non zero
    while(i<plen-UDP_DATA_P-7){
      i++;
      if (buf[UDP_DATA_P+i]==0){
        i++;
        break;
      }
    }
  }
  // i is now pointing to the low octet of the length field
  print(PSTR( "len = " ) );
  _Serial->println( buf[UDP_DATA_P+i+9], DEC );

  print(PSTR( "A type = " ) );
  _Serial->println( buf[UDP_DATA_P+i+1], DEC );

  int numAnswers = buf[UDP_DATA_P+7];
  int ansNum = 0;

  print( PSTR( "A i=" ) );
  _Serial->println(i, DEC);
  while( buf[UDP_DATA_P+i+1] != 1 && ansNum < numAnswers ) {
    print(PSTR( "B type = " ) );
    _Serial->println( buf[UDP_DATA_P+i+1], DEC );
    print( PSTR( "B i=" ) );
    _Serial->println(i, DEC);

    i += buf[UDP_DATA_P+i+9] + 12;
  }
  print(PSTR( "C type = " ) );
  _Serial->println( buf[UDP_DATA_P+i+1], DEC );
  print( PSTR( "C i=" ) );
  _Serial->println(i, DEC);

  //if (buf[UDP_DATA_P+i+9] !=4 ){
  if ( ansNum == numAnswers ) {
    println(PSTR( "Not IPv4" ));
  }
  i+=10;
  int j=0;
  while(j<4){
    _Serial->print( buf[UDP_DATA_P+i+j], DEC );
    print( PSTR( "." ) );
    j++;
  }
  _Serial->println();

}

void EthPacketDump::dumpDhcp( uint8_t *buf, int plen ) {
/*
    Server host name not given
    Boot file name not given
    Magic cookie: (OK)
    Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        Option: (53) DHCP Message Type
        Length: 1
        Value: 01
 */
  int i=UDP_DATA_P;
  println(PSTR( "\nDHCP Details:"));
  print( PSTR( "Message type: ") );
  print( buf[i++] == 1 ? PSTR( "Request") : PSTR( "Reply") );
  print( PSTR( " Hardware type: " ) );
  print( buf[i++] == 1 ? PSTR( "Ethernet") : PSTR( "Other!") );
  print( PSTR( " HW Address Len: ") );
  _Serial->print( buf[i++], DEC );
  print( PSTR( " Hops: ") );
  _Serial->print( buf[i++], DEC );
  print( PSTR( "\nTrans ID: 0x") );
  _Serial->print( buf[i++], HEX );
  _Serial->print( buf[i++], HEX );
  _Serial->print( buf[i++], HEX );
  _Serial->print( buf[i++], HEX );
  print( PSTR( " Seconds: ") );
  int secs = buf[i] << 8 + buf[i+1];
  _Serial->print( secs, DEC );
  i += 2;
  print( PSTR( " Flags: 0x") );
  _Serial->print( buf[i++], HEX );
  _Serial->print( buf[i++], HEX );

  print( PSTR( "\nClient IP: ") );
  printIP( buf, i);
  i += 4;

  print( PSTR( "\nYour IP: " ) );
  printIP( buf, i);
  i += 4;

  print( PSTR( "\nNext Server IP: " ) );
  printIP( buf, i);
  i += 4;

  print( PSTR( "\nRelay Agent IP: " ) );
  printIP( buf, i);
  i += 4;

  print( PSTR( "\nClient MAC: " ) );
  printMac( buf, i);
  i += 6;

  // other bits

  // Options start at 236+4
  i = 282;
  if( buf[i] == 53 ) {
	  print( PSTR( "\nType: " ) );
	  i += 2;
	  switch( buf[i] ) {
		  case 1:
			print( PSTR( "DHCP Discover" ) );
			break; 
		  case 2:
			print( PSTR( "DHCP Offer" ) );
			break; 
		  case 3:
			print( PSTR( "DHCP Request" ) );
			break; 
		  case 5:
			print( PSTR( "DHCP Ack" ) );
			break; 
		  default:
			_Serial->print( buf[i], HEX );
			break; 
	  }
  }
  _Serial->println();
}

void EthPacketDump::dumpNtp( uint8_t *buf, int plen ) {

}

