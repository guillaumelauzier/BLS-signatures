#include <iostream>
#include <cstring>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Generate a new BLS private key
BIGNUM* bls_generate_private_key()
{
    BIGNUM* private_key = BN_new();
    BN_rand(private_key, 256, 0, 0);
    return private_key;
}

// Generate a new BLS public key from a private key
EC_POINT* bls_generate_public_key(const BIGNUM* private_key)
{
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* public_key = EC_POINT_new(group);
    EC_POINT_mul(group, public_key, private_key, NULL, NULL, NULL);
    return public_key;
}

// Sign a message using a BLS private key
BIGNUM* bls_sign(const BIGNUM* private_key, const unsigned char* message, size_t message_len)
{
    BIGNUM* signature = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    // Hash the message
    unsigned char hash[32];
    SHA256(message, message_len, hash);

    // Convert the hash to a BIGNUM
    BIGNUM* h = BN_bin2bn(hash, 32, NULL);

    // Compute the signature
    BN_mod_exp(signature, h, private_key, BN_get0_order(EC_GROUP_new_by_curve_name(NID_secp256k1)), ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(h);

    return signature;
}

// Verify a BLS signature using a public key and message
bool bls_verify(const EC_POINT* public_key, const unsigned char* message, size_t message_len, const BIGNUM* signature)
{
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX* ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    // Hash the message
    unsigned char hash[32];
    SHA256(message, message_len, hash);

    // Convert the hash to a BIGNUM
    BIGNUM* h = BN_bin2bn(hash, 32, NULL);

    // Compute the left-hand side of the equation
    EC_POINT* lhs = EC_POINT_new(group);
    EC_POINT_mul(group, lhs, NULL, public_key, signature, ctx);

    // Compute the right-hand side of the equation
    EC_POINT* rhs = EC_POINT_new(group);
    EC_POINT_mul(group, rhs, h, NULL, NULL, ctx);
    EC_POINT_add(group, rhs, rhs, public_key, ctx);

    // Compare the two points
    int result = EC_POINT_cmp(group, lhs, rhs, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(h);
    EC_POINT_free(lhs);
    EC_POINT_free(rhs);

    return (result == 0);
}

int main()
{
    // Generate a new private key and public key
    BIGNUM* private_key = bls_generate_private_key();
    EC_POINT* public_key = bls_generate_public_key(private_key);

    // Sign a message
    unsigned char message[] = "Hello, world!";
    BIGNUM* signature = bls_sign(private_key, message, sizeof(message) - 1);

    // Verify the signature
    bool valid = bls_verify(public_key, message, sizeof(message) - 1, signature

                                BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(h);
    BN_free(signature);
    BN_free(private_key);
    EC_POINT_free(public_key);

    return (result == 0);
}

int main()
{
    // Generate a new private key and public key
    BIGNUM* private_key = bls_generate_private_key();
    EC_POINT* public_key = bls_generate_public_key(private_key);

    // Sign a message
    unsigned char message[] = "Hello, world!";
    BIGNUM* signature = bls_sign(private_key, message, sizeof(message) - 1);

    // Verify the signature
    bool valid = bls_verify(public_key, message, sizeof(message) - 1, signature);

    // Print the results
    printf("Private key: %s\n", BN_bn2hex(private_key));
    printf("Public key: %s\n", EC_POINT_point2hex(EC_GROUP_new_by_curve_name(NID_secp256k1), public_key, POINT_CONVERSION_UNCOMPRESSED, NULL));
    printf("Signature: %s\n", BN_bn2hex(signature));
    printf("Signature is %svalid\n", valid ? "" : "not ");

    BN_free(signature);
    BN_free(private_key);
    EC_POINT_free(public_key);

    return 0;
}
