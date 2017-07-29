#include "common.h"

static void printchar(u_char c)
{
    if (isprint(c))
        printf("%c", c);
    else
        putchar('.');
}

/*
 * Prototype : void dumpcode(u_char *buf, int len)
 * Last Modified 2017/07/29
 * Written by ohhara
 *
 * dump code from buf
 * buf is start address, len is length to print hex
 */
void dumpcode(u_char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        if (!(i % 16))
            printf("0x%08x ", &buf[i]);
        printf("%02x ", buf[i]);

        if (!(i % 16 - 7))
            printf("- ");

        if (!(i % 16 - 15))
        {
            int j;
            putchar(' ');

            for (j = i - 15; j <= i; j++)
                printchar(buf[j]);
            printf("\n\r");
        }
    }

    if (i % 16)
    {
        int j;
        int sp = (len - i + 16 - i % 16) * 3 + 2;

        for (j = 0; j < sp; j++)
            putchar(' ');

        for (j = i - i % 16; j < len; j++)
            printchar(buf[j]);
    }

    printf("\n\r");
}
