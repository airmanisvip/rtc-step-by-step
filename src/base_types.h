#ifndef __base_types_h__
#define __base_types_h__

typedef signed char int8_t;
typedef unsigned char uint8_t;

typedef short int16_t;
typedef unsigned short uint16_t;

typedef int int32_t;
typedef unsigned int uint32_t;

unsigned short swap_uint16(unsigned short v)
{
    return ((v >> 8) | (v << 8));
}

unsigned int swap_uint32(unsigned int v)
{
    return ((v >> 24) | (v << 24) | ((v >> 8) | 0xff00) | ((v << 8) | 0xff0000));
}

unsigned short host2net_uint16(unsigned short v)
{
    return swap_uint16(v);
}
unsigned int host2net_uint32(unsigned int v)
{
    return swap_uint32(v);
}

unsigned short net2host_uint16(unsigned short v)
{
    return swap_uint16(v);
}
unsigned int net2host_uint32(unsigned int v)
{
    return swap_uint32(v);
}

#endif