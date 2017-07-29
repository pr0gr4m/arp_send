#include "common.h"

/*
 * Prototype : void dumpcode(u_char *buf, int len)
 * Last Modified 2017/07/29
 * Written by ohhara
 * Modified by pr0gr4m
 *
 * dump code from buf
 * buf is start address, len is length to print hex
 */
void dumpcode(const u_char *buf, int len)
{
    int i;

    printf("%7s", "offset ");
    for (i = 0; i < 16; i++)
    {
        printf("%02x ", i);

        if (!(i % 16 - 7))
            printf("- ");
    }
    printf("\n\r");

    for (i = 0; i < len; i++)
    {
        if (!(i % 16))
            printf("0x%04x ", i);

        printf("%02x ", buf[i]);

        if (!(i % 16 - 7))
            printf("- ");

        if (!(i % 16 - 15))
        {
            putchar(' ');

            printf("\n\r");
        }
    }

    printf("\n\r");
}
