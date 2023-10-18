#ifndef __rtp_defines_h__
#define __rtp_defines_h__

#include "base_types.h"

const unsigned char  kRtpVersion = 2;   //rtp版本号固定位为2
const unsigned short kOneByteHeaderId = 0xBEDE; //webrtc只支持这一种
const unsigned short kExtensionCount = 16;

//只支持one-byte-header
struct rtp_extension_header
{
    unsigned char id; //范围[1, 14]
    unsigned char len;//rfc中范围[0, 15]，这里我们使用真实占用的字节数，即范围为 [1, 16]
    unsigned char data[16];
};

struct rtppacket
{
    unsigned char version;
    unsigned char padding;
    unsigned char x;    //1 - 有扩展头
    unsigned char cc;
    unsigned char market;
    unsigned char payload;

    unsigned short seqnumber;

    unsigned int timestamp;
    unsigned int ssrc;

    unsigned int csrc[16];

    //扩展头信息
    unsigned short extension_profile; //0xBEDE
    unsigned short extension_length; //有多少个4字节数据
    unsigned short extension_length_in_byte;
    unsigned short extension_count;

    struct rtp_extension_header extension_header[kExtensionCount];

    unsigned short padding_size;

    unsigned char *data;
    unsigned short data_len;
};

bool read_rtppacket_from_buffer(unsigned char *buffer, unsigned int size, rtppacket &pkt);
bool write_rtppacket_to_buffer(rtppacket &pkt, unsigned char *buffer, unsigned int &size);

void add_extension_header(struct rtppacket &pkt, struct rtp_extension_header &hdr);

#endif //#ifndef __rtp_defines_h__