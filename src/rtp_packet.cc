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
 |                            ....                               |
 |                            ....               |  padding size |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

bool read_rtppacket_from_buffer(unsigned char *buffer, unsigned int size, rtppacket &pkt)
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
        pkt.extension_length_in_byte = pkt.extension_length * 4;

        unsigned char *extension_pos = current_pos + 2;
        unsigned short extension_size = pkt.extension_length_in_byte;

        unsigned short extension_idx = 0;

        //解析扩展头

/*
0                   1                   2                   3
|7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0 7 6 5 4 3 2 1 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       0xBE    |    0xDE       |           length=3            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ID   | L=0   |     data      |  ID   |  L=1  |   data...     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     ...data   |    0 (pad)    |    0 (pad)    |  ID   | L=3   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          data                                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
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

            len = len + 1; //len 范围 [0, 15], 0 - 1字节，1 - 2字节，3 - 4字节，... ，15 - 16字节

            pkt.extension_header[extension_idx].id = id; //id的范围为 1 - 14，
            pkt.extension_header[extension_idx].len = len;

            extension_pos++;
            extension_size--;
            extension_idx++;
            pkt.extension_count++;

            memcpy(pkt.extension_header[extension_idx].data, extension_pos, len);

            extension_pos = extension_pos + len;
            extension_size = extension_size - len;
        }


        current_pos = current_pos + 2 + pkt.extension_length * 4;
    }

    unsigned int rtp_data_size = current_pos - buffer;

    //最后一个字节存放padding大小
    if (pkt.padding)
    {
        rtp_data_size = rtp_data_size - buffer[size - 1]; //不需要转换字节序？
    }
    
    pkt.data = (unsigned char *)malloc(rtp_data_size);

    memcpy(pkt.data, current_pos, rtp_data_size);

    return true;
}
bool write_rtppacket_to_buffer(rtppacket &pkt, unsigned char *buffer, unsigned int &size)
{
    memset(buffer, 0, size);

    unsigned short empty_size = size;

    unsigned char *current_pos = buffer;
    unsigned char extension_bit = (pkt.extension_count > 0) ? 1 : 0;
    *current_pos = (pkt.version << 6) | (pkt.padding << 5) | extension_bit | (pkt.cc);

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

    if (pkt.extension_count > 0)
    {
        //写profile - 0xBEDE
        (*(unsigned short *)current_pos) = host2net_uint16(pkt.extension_profile);

        current_pos = current_pos + 2;

        unsigned short remainder = pkt.extension_length_in_byte % 4;
        pkt.extension_length = pkt.extension_length_in_byte / 4 + remainder;

        (*(unsigned short *)current_pos) = host2net_uint16(pkt.extension_length);

        //写真实的扩展信息
        unsigned char *extension_pos = current_pos + 2;
        unsigned short extension_size = 0;
        for(int i = 0; i < pkt.extension_count; i++)
        {
            (*(unsigned char *)extension_pos) = (pkt.extension_header[i].id << 4) | (pkt.extension_header[i].len - 1);

            memcpy(extension_pos, pkt.extension_header[i].data, pkt.extension_header[i].len);

            extension_pos = extension_pos + 1 + pkt.extension_header[i].len;
            extension_size = extension_size + 1 + pkt.extension_header[i].len;

            //需要padding
            if(remainder != 0 && i == (pkt.extension_count - 2))
            {
                //最后一个扩展数据长度能被4整除，则将padding数据放到其前面
                if(pkt.extension_header[pkt.extension_count - 1].len % 4 == 0)
                {
                    memset(extension_pos, 0, remainder);
                    extension_pos = extension_pos + remainder;
                }
            }
        }

        pkt.extension_length = extension_size / 4 + extension_size % 4;
        
        current_pos = current_pos + 2 + pkt.extension_length * 4;
    }

    empty_size = size - (current_pos - buffer);

    if(pkt.data_len > empty_size)
    {
        return false;
    }

    memcpy(current_pos, pkt.data, pkt.data_len);

    current_pos = current_pos + pkt.data_len;

    if(pkt.padding_size > 0)
    {
        current_pos[pkt.padding_size - 1] = pkt.padding_size;
        current_pos = current_pos + pkt.padding_size;
    }

    //返回包括padding在内 总数据大小
    size = current_pos - buffer;

    return true;
}

void add_extension_header(struct rtppacket &pkt, struct rtp_extension_header &hdr)
{
    //如果已存在 直接返回
    for(int i = 0; i < pkt.extension_count; i++)
    {
        if(pkt.extension_header[i].id == hdr.id)
        {
            return ;
        }
    }

    pkt.extension_header[pkt.extension_count].id = hdr.id;
    pkt.extension_header[pkt.extension_count].len = hdr.len;
    memcpy(pkt.extension_header[pkt.extension_count].data, hdr.data, hdr.len);
    
    pkt.extension_count++;
    pkt.extension_length_in_byte = pkt.extension_length_in_byte + hdr.len;
}