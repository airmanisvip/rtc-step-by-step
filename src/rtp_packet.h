#ifndef __rtp_defines_h__
#define __rtp_defines_h__

#include "base_types.h"

const unsigned char kRtpVersion = 2;
const unsigned short kOneByteHeaderId = 0xBEDE;

//只支持one-byte-header
struct rtp_extension_header
{
    unsigned char id; //范围[1, 14]
    unsigned char len;//范围[0, 15]
    unsigned char data[16];
};

struct rtppacket
{
    unsigned char version;
    unsigned char padding;
    unsigned char x;
    unsigned char cc;
    unsigned char market;
    unsigned char payload;

    unsigned short seqnumber;

    unsigned int timestamp;
    unsigned int ssrc;

    unsigned int csrc[16];

    //扩展头信息
    unsigned short extension_profile;
    unsigned short extension_length;
    struct rtp_extension_header extension_header[14];

    unsigned short padding_size;

    unsigned char *data;
    unsigned short data_len;
};

bool buffer2rtppacket(unsigned char *buffer, unsigned int size, rtppacket &pkt);
bool rtppacket2buffer(rtppacket &pkt, unsigned char *buffer, unsigned int &size);

#endif //#ifndef __rtp_defines_h__