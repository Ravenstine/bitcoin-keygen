#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ripemd.h>
#include <qrencode.h>

#define VERSION_PREFIX 0x80 // Prefix for a private key WIF
#define COMPRESSED_FLAG 0x01
#define MAINNET_PREFIX "bc"

static const char * BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char * BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint32_t polymodStep (uint32_t pre) {
    const uint32_t b = pre >> 25;

    return ((pre & 0x1FFFFFF) << 5)
        ^ (-((b >> 0) & 1) & 0x3b6a57b2UL)
        ^ (-((b >> 1) & 1) & 0x26508e6dUL)
        ^ (-((b >> 2) & 1) & 0x1ea119faUL)
        ^ (-((b >> 3) & 1) & 0x3d4233ddUL)
        ^ (-((b >> 4) & 1) & 0x2a1462b3UL);
}

unsigned char * convertBits (
    const unsigned char * input,
    size_t inputLength,
    int fromBits,
    int toBits,
    size_t * outputLength,
    int pad
) {
    int acc = 0;
    int bits = 0;

    const int maxV = (1 << toBits) - 1;
    const int maxAcc = (1 << (fromBits + toBits - 1)) - 1;

    size_t retlen = (inputLength * fromBits + toBits - 1) / toBits;

    unsigned char * output = malloc(retlen * sizeof(unsigned char));

    if (!output) {
        return NULL;
    }

    for (size_t i = 0; i < inputLength; i++) {
        int value = input[i];

        acc = ((acc << fromBits) | value) & maxAcc;
        bits += fromBits;

        while (bits >= toBits) {
            bits -= toBits;
            output[(* outputLength)++] = (acc >> bits) & maxV;
        }
    }

    if (pad) {
        if (bits) output[(* outputLength)++] = (acc << (toBits - bits)) & maxV;
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxV)) {
        free(output);

        return NULL;
    }

    return output;
}

int bech32Encode (
    char * output,
    const char * hrp,
    const unsigned char * data,
    size_t dataLength
) {
    int chk = 1;

    for (size_t i = 0; hrp && hrp[i] != '\0'; ++i) {
        chk = polymodStep(chk) ^ (hrp[i] >> 5);
    }

    chk = polymodStep(chk);

    for (size_t i = 0; hrp && hrp[i] != '\0'; ++i) {
        chk = polymodStep(chk) ^ (hrp[i] & 0x1f);
    }

    size_t resultLength = 0;

    while (hrp[resultLength] != '\0') {
        if (hrp[resultLength] >= 'A' && hrp[resultLength] <= 'Z') return -1;
        output[resultLength] = hrp[resultLength];
        resultLength++;
    }

    output[resultLength++] = '1';

    for (size_t i = 0; i < dataLength; ++i) {
        if (data[i] >> 5) return -1; // High bits can't be set in 5-bit values
        chk = polymodStep(chk) ^ data[i];
        output[resultLength++] = BECH32_CHARSET[data[i]];
    }

    for (int i = 0; i < 6; ++i) {
        chk = polymodStep(chk);
    }

    chk ^= 1;

    for (int i = 0; i < 6; ++i) {
        output[resultLength++] = BECH32_CHARSET[(chk >> ((5 - i) * 5)) & 0x1f];
    }

    output[resultLength] = 0; // null-terminate the result

    return 0;
}

int createBech32Address (
    char * output,
    const char * hrp,
    int witnessVersion,
    const unsigned char * witnessProgram,
    size_t programSize
) {
    size_t length = 0;

    unsigned char data[64];

    data[length++] = witnessVersion;

    size_t dataLength = 0;

    unsigned char * converted = convertBits(witnessProgram, programSize, 8, 5, &dataLength, 1);

    if (!converted) {
        return -1;
    }

    memcpy(&data[length], converted, dataLength);

    length += dataLength;

    free(converted);

    if (bech32Encode(output, hrp, data, length) == -1) {
        return -1;
    }

    return 0;
}

void bigNumToBytes (const BIGNUM * bn, unsigned char * buffer, int length) {
    int bnLength = BN_num_bytes(bn);
    int padding = length - bnLength;

    memset(buffer, 0, padding);

    BN_bn2bin(bn, buffer + padding);
}

int base58Encode (const BIGNUM * bn, char * output, int outputLength) {
    unsigned char buffer[BN_num_bytes(bn)];

    bigNumToBytes(bn, buffer, sizeof(buffer));

    char * p = output;

    BIGNUM * value = BN_dup(bn);
    BN_CTX * ctx = BN_CTX_new();
    BIGNUM * dv = BN_new();
    BIGNUM * rem = BN_new();
    BIGNUM * base = BN_new();
    BN_set_word(base, 58);

    while (!BN_is_zero(value)) {
        if (BN_div(dv, rem, value, base, ctx) == 0) {
            BN_CTX_free(ctx);
            BN_free(base);
            BN_free(rem);
            BN_free(dv);
            BN_clear_free(value);

            return 0;
        }

        * p = BASE58_ALPHABET[BN_get_word(rem)];
        p++;

        BN_swap(value, dv);
    }

    for (int i = sizeof(buffer) - 1; i >= 0; i--) {
        if (buffer[i]) break;

        * p = '1';
        p++;
    }

    * p = '\0'; // null terminate the string

    // Reverse the string
    int length = p - output;

    for (int i = 0; i < length / 2; i++) {
        char t = output[i];

        output[i] = output[length - i - 1];
        output[length - i - 1] = t;
    }

    BN_CTX_free(ctx);
    BN_free(base);
    BN_free(rem);
    BN_free(dv);
    BN_clear_free(value);

    return 1;
}

void printQRCode(const char * data) {
    QRcode * qr = QRcode_encodeString(data, 0, QR_ECLEVEL_L, QR_MODE_8, 1);

    int width = qr->width;
    int realWidth = (width) + 4;

    // Top border
    for (int i = 0; i < realWidth; i++) {
        printf("█");
    }

    printf("\n");

    // Print QR modules (processing two rows at a time)
    for (int y = 0; y < width; y += 2) {
        printf("██"); // Left border

        for (int x = 0; x < width; x++) {
            unsigned char moduleUpper = qr->data[y * width + x] & 1;
            unsigned char moduleLower = (y + 1 < width) ? qr->data[(y + 1) * width + x] & 1 : 0;

            if (moduleUpper && moduleLower) {
                printf(" ");
            } else if (moduleUpper) {
                printf("▄");
            } else if (moduleLower) {
                printf("▀");
            } else {
                printf("█");
            }
        }

        printf("██\n"); // Right border
    }

    // Bottom border
    for (int i = 0; i < realWidth; i++) {
        printf("▀");
    }

    printf("\n\n");

    // Clean up
    QRcode_free(qr);
}

int main () {
    // Generate a new EC key on the Bitcoin curve secp256k1
    EC_KEY * key = EC_KEY_new_by_curve_name(NID_secp256k1);

    if (!key) {
        fprintf(stderr, "Unable to generate EC_KEY\n");

        return 1;
    }

    if (!EC_KEY_generate_key(key)) {
        fprintf(stderr, "Unable to generate EC private key\n");
        EC_KEY_free(key);

        return 1;
    }

    const BIGNUM * privateBN = EC_KEY_get0_private_key(key);

    unsigned char private[32];

    BN_bn2binpad(privateBN, private, 32);

    // Add 0x80 prefix for mainnet private key, and append a 0x01 suffix to indicate a compressed pubkey
    unsigned char privateFull[34];

    privateFull[0] = VERSION_PREFIX;

    memcpy(privateFull + 1, private, 32);

    privateFull[33] = COMPRESSED_FLAG;

    // Double SHA256 for checksum and take first 4 bytes
    unsigned char hash[32];

    SHA256(privateFull, 34, hash);
    SHA256(hash, 32, hash);

    unsigned char checksum[4];

    memcpy(checksum, hash, 4);

    // Combine the private key with prefix, suffix, and checksum
    unsigned char privateEncoded[38];

    memcpy(privateEncoded, privateFull, 34);
    memcpy(privateEncoded + 34, checksum, 4);

    // Convert the result into a BIGNUM
    BIGNUM * bnPrivate = BN_new();
    BN_bin2bn(privateEncoded, 38, bnPrivate);

    // Encode the result using base58 encoding
    char wif[52];

    if (!base58Encode(bnPrivate, wif, sizeof(wif))) {
        fprintf(stderr, "Failed to base58 encode private key\n");
        BN_clear_free(bnPrivate);
        EC_KEY_free(key);

        return 1;
    }

    BN_clear_free(bnPrivate);
    printf("\nPrivate Key WIF: %s\n\n", wif);
    printQRCode(wif);

    // Create bech32 address for corresponding pubkey
    EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);

    // Allocate enough space to store compressed public key
    unsigned char public[33]; // A compressed public key is always 33 bytes long.

    // pubLen will contain the actual length of the key after conversion
    size_t publicLength = EC_POINT_point2oct(
        EC_KEY_get0_group(key),
        EC_KEY_get0_public_key(key),
        POINT_CONVERSION_COMPRESSED,
        public,
        sizeof(public),
        NULL
    );

    if (publicLength == 0) {
        fprintf(stderr, "Failed to create public key\n");
        EC_KEY_free(key);

        return 1;
    }

    // Create 20-byte witness program
    unsigned char witnessProgram[20];

    SHA256(public, publicLength, hash);
    RIPEMD160(hash, SHA256_DIGEST_LENGTH, witnessProgram);

    // Create bech32 address
    char address[100];

    if (createBech32Address(address, MAINNET_PREFIX, 0, witnessProgram, sizeof(witnessProgram)) != 0) {
        fprintf(stderr, "Failed to create bech32 address\n");
        EC_KEY_free(key);

        return 1;
    }

    printf("Bech32 Address: %s\n\n", address);
    printQRCode(address);
    fflush(stdout);
    EC_KEY_free(key);

    return 0;
}
