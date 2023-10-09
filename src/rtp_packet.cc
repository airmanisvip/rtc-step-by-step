#include "rtp_packet.h"

#include <memory.h>
#include <stdlib.h>

/*
 RFC3550
 |     byte1     |     byte2     |      byte3    |    byte4      |         
 |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |v=2|p|x|  cc   |m|      pt     |       sequence number         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                          timestamp                            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                            ssrc                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                            csrc                               |
 |                            ....                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          profile              |          length               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

bool buffer2rtppacket(unsigned char *buffer, unsigned int size, rtppacket &pkt)
{
    unsigned char *current_pos = buffer;

    pkt.version = (((*current_pos) & 0xc0) >> 6);
    if (pkt.version != kRtpVersion)
    {
        return false;
    }

    pkt.padding = (((*current_pos) & 0x20) >> 5);
    pkt.x = (((*current_pos) & 0x10) >> 4);
    pkt.cc = ((*current_pos) & 0x0f);

    current_pos++;
    pkt.seqnumber = net2host_uint16(*((unsigned short *)current_pos));

    current_pos = current_pos + 2;
    pkt.timestamp = net2host_uint32(*((unsigned int *)current_pos));

    current_pos = current_pos + 4;
    pkt.ssrc = net2host_uint32(*((unsigned int *)current_pos));

    if(pkt.cc > 0)
    {
        for (int i = 0; i < pkt.cc; i++)
        {
            pkt.csrc[i] = net2host_uint32(*((unsigned int *)current_pos));
            current_pos = current_pos + 4;
        }
    }

    if (pkt.x == 1)
    {
        pkt.extension_profile = net2host_uint16(*((unsigned short *)current_pos));
        if (pkt.extension_profile != kOneByteHeaderId)
        {
            //只支持one byte header
            return false;
        }       

        current_pos = current_pos + 2;
        pkt.extension_length = net2host_uint16(*((unsigned short *)current_pos));

        unsigned char *extension_pos = current_pos + 2;
        unsigned short extension_size = pkt.extension_length;

        //解析扩展头

        while(extension_size > 0)
        {
            //取id
            unsigned char id = extension_pos[0] >> 4;
            if(id == 1) //id 范围 [1, 14] 0 - padding,continue, 15 - error, break
            {
                extension_pos++;
                extension_size--;
                continue;
            }
            else if(id == 15)
            {
                break;
            }

            //取长度
            unsigned char len = extension_pos[0] & 0x0f;
            if(len > 15)
            {
                break;
            }

            len = len + 1; //len 范围 [0, 15], 0 - 1字节，15 - 16字节

            pkt.extension_header[id - 1].id = id;
            pkt.extension_header[id - 1].len = len;

            extension_pos++;
            extension_size--;

            memcpy(pkt.extension_header[id - 1].data, extension_pos, len);

            extension_pos = extension_pos + len;
            extension_size = extension_size - len;
        }


        current_pos = current_pos + 2 + pkt.extension_length * 4;
    }

    unsigned int rtp_data_size = current_pos - buffer;

    if (pkt.padding)
    {
        rtp_data_size = rtp_data_size - buffer[size - 1]; //不需要转换字节序？
    }
    
    pkt.data = (unsigned char *)malloc(rtp_data_size);

    memcpy(pkt.data, current_pos, rtp_data_size);

    return true;
}
bool rtppacket2buffer(rtppacket &pkt, unsigned char *buffer, unsigned int &size)
{
    memset(buffer, 0, size);

    unsigned short empty_size = size;

    unsigned char *current_pos = buffer;
    *current_pos = (pkt.version << 6) | (pkt.padding << 5) | (pkt.x << 4) | (pkt.cc);

    current_pos++;
    *current_pos = (pkt.market << 7) | pkt.payload;

    current_pos++;
    (*(unsigned short *)current_pos) = host2net_uint16(pkt.seqnumber);

    current_pos = current_pos + 2;
    (*(unsigned int *)current_pos) = host2net_uint32(pkt.timestamp);

    current_pos = current_pos + 4;
    (*(unsigned int *)current_pos) = host2net_uint32(pkt.ssrc);

    current_pos = current_pos + 4;
    if (pkt.cc > 0)
    {
        for (int i = 0; i < pkt.cc; i++)
        {
            (*(unsigned int *)current_pos) = host2net_uint32(pkt.csrc[i]);
            current_pos = current_pos + 4;
        }
    }

    if (pkt.x == 1)
    {
        (*(unsigned short *)current_pos) = host2net_uint16(pkt.extension_profile);

        current_pos = current_pos + 2;
        (*(unsigned short *)current_pos) = host2net_uint16(pkt.extension_length);

        current_pos = current_pos + 2 + pkt.extension_length * 4;
    }

    empty_size = size - (current_pos - buffer);

    if(pkt.data_len > empty_size)
    {
        return false;
    }

    memcpy(current_pos, pkt.data, pkt.data_len);

    return true;
}