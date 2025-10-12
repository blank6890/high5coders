// Minimal WebSocket echo server in C for Windows (Winsock)
// Supports a single client, text frames only, for demo/learning purposes
// Compile: gcc ws_echo_server.c -o ws_echo_server.exe -lws2_32
// Run: ws_echo_server.exe

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8081
#define BUF_SIZE 8192

// Simple base64 encoding for Sec-WebSocket-Accept
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void base64_encode(const unsigned char *in, size_t inlen, char *out) {
    int i, j;
    for (i = 0, j = 0; i < inlen;) {
        uint32_t octet_a = i < inlen ? in[i++] : 0;
        uint32_t octet_b = i < inlen ? in[i++] : 0;
        uint32_t octet_c = i < inlen ? in[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = b64_table[(triple >> 6) & 0x3F];
        out[j++] = b64_table[triple & 0x3F];
    }
    int mod = inlen % 3;
    if (mod) {
        out[j - 1] = '=';
        if (mod == 1) out[j - 2] = '=';
    }
    out[j] = '\0';
}

// Minimal public domain SHA1 implementation for handshake
// Source: https://github.com/clibs/sha1 (public domain)
#include <stdint.h>
#include <string.h>

#define SHA1_BLOCK_SIZE 20

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const unsigned char* data, uint32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]) {
    uint32_t a, b, c, d, e;
    typedef union {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16 block[1];
    memcpy(block, buffer, 64);
    uint32_t i, j, t, W[80];
    for (i = 0; i < 16; i++) W[i] = (block->l[i] << 24) | ((block->l[i] & 0xff00) << 8) | ((block->l[i] & 0xff0000) >> 8) | (block->l[i] >> 24);
    for (i = 16; i < 80; i++) W[i] = rol(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        t = rol(a,5) + f + e + k + W[i];
        e = d; d = c; c = rol(b,30); b = a; a = t;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void SHA1Init(SHA1_CTX* context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX* context, const unsigned char* data, uint32_t len) {
    uint32_t i, j;
    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) SHA1Transform(context->state, &data[i]);
        j = 0;
    } else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(unsigned char digest[20], SHA1_CTX* context) {
    unsigned char finalcount[8];
    for (int i = 0; i < 8; i++) finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3-(i&3))*8)) & 255);
    SHA1Update(context, (unsigned char *)"\200", 1);
    while ((context->count[0] & 504) != 448) SHA1Update(context, (unsigned char *)"\0", 1);
    SHA1Update(context, finalcount, 8);
    for (int i = 0; i < 20; i++) digest[i] = (unsigned char)((context->state[i>>2] >> ((3-(i & 3))*8)) & 255);
}

void sha1(const char *msg, size_t len, unsigned char *hash) {
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    SHA1Update(&ctx, (const unsigned char*)msg, (uint32_t)len);
    SHA1Final(hash, &ctx);
}

int main() {
    WSADATA wsa;
    SOCKET server, client;
    struct sockaddr_in addr;
    char buf[BUF_SIZE];
    int ret;

    WSAStartup(MAKEWORD(2,2), &wsa);
    server = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    bind(server, (struct sockaddr*)&addr, sizeof(addr));
    listen(server, 1);
    printf("WebSocket echo server running on ws://localhost:%d\n", PORT);

    client = accept(server, NULL, NULL);
    ret = recv(client, buf, BUF_SIZE, 0);
    buf[ret] = 0;
    // Find Sec-WebSocket-Key
    char *key = strstr(buf, "Sec-WebSocket-Key: ");
    if (!key) { closesocket(client); closesocket(server); WSACleanup(); return 1; }
    key += 19;
    char *eol = strstr(key, "\r\n");
    char ws_key[128] = {0};
    strncpy(ws_key, key, eol - key);
    // Concatenate magic string
    char concat[256];
    snprintf(concat, sizeof(concat), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", ws_key);
    // SHA1 and base64
    unsigned char hash[SHA1_BLOCK_SIZE];
    sha1(concat, strlen(concat), hash);
    char accept[64];
    base64_encode(hash, SHA1_BLOCK_SIZE, accept);
    // Send handshake response
    snprintf(buf, BUF_SIZE,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n", accept);
    send(client, buf, strlen(buf), 0);

    // Echo loop (text frames only)
    while (1) {
        ret = recv(client, buf, BUF_SIZE, 0);
        if (ret <= 0) break;
        // Parse WebSocket frame (assume small, unmasked, text)
        unsigned char opcode = buf[0] & 0x0F;
        if (opcode == 8) break; // close
        int payload_len = buf[1] & 0x7F;
        int mask_offset = 2;
        unsigned char mask[4] = {0};
        memcpy(mask, buf + mask_offset, 4);
        char msg[BUF_SIZE];
        for (int i = 0; i < payload_len; i++)
            msg[i] = buf[mask_offset + 4 + i] ^ mask[i % 4];
        msg[payload_len] = 0;
        printf("Received: %s\n", msg);
        // Send back (text frame)
        unsigned char frame[BUF_SIZE];
        frame[0] = 0x81; // FIN + text
        frame[1] = payload_len;
        memcpy(frame + 2, msg, payload_len);
        send(client, (char*)frame, payload_len + 2, 0);
    }
    closesocket(client);
    closesocket(server);
    WSACleanup();
    return 0;
}
// Note: For a real server, use a proper SHA1 and handle all WebSocket edge cases.
