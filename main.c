#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bignum.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "sha3.h"
#include "bip39.h"
#include "bip32.h"
#include "sha2.h"
#include "hasher.h"
#include "sha3.h"
#include "memzero.h"

int main(void) {
    const char *mnemonic = "bulb huge marriage supreme dawn mention crime faculty quiz hockey drum bulk history swarm special color split congress verb future unaware below lesson crop";
    uint8_t seed[64];
    const char *passphrase = "";

    mnemonic_to_seed(mnemonic, passphrase, seed, NULL);

    // verify the seed
    printf("Seed: ");
    for (int i=0; i<64; i++)
    {
        printf("%02x", seed[i]);
    }
    printf("\n");
    
    //  to find master node we do the sha512 hash one more time
    HDNode master_node;
    if (!hdnode_from_seed(seed, 64, "secp256k1", &master_node)) {
    fprintf(stderr, "Failed to derive master node \n");
    return 1;
    }

    printf("\nMaster node: \n");
    get_node_info(&master_node); 

    // Hardened derivation to find purpose node
    HDNode purpose_node = master_node;
    // INDEX = 44 for BIP44 standard 
    uint32_t purpose_index = 0x2C;
    if (!hdnode_private_ckd(&purpose_node, purpose_index + 0x80000000)) {
    fprintf(stderr, "Failed to derive purpose node\n");
    return 1;
    }

    printf("\nPurpose node: \n");
    get_node_info(&purpose_node);


    // Hardened derivation to find coin node
    HDNode coin_node = purpose_node;
    // INDEX = 1 for Bitcoin Testnet
    uint32_t coin_index = 0x1;
    if (!hdnode_private_ckd(&coin_node, coin_index + 0x80000000)) {
    fprintf(stderr, "Failed to derive coin node\n");
    return 1;
    }

    printf("\nCoin node: \n");
    get_node_info(&coin_node);

    // Hardened derivation to find account node
    int32_t account_index;
    // INDEX based on bank account types, eg. 0 for savings, 1 for payments etc.
    printf("\nEnter account index: ");
    scanf("%d", &account_index);
    HDNode account_node = coin_node;
    if (!hdnode_private_ckd(&account_node, account_index + 0x80000000))
    {
        fprintf(stderr, "Failed to derive account node\n");
        return 1;
    }

    printf("\nAccount node: \n");
    get_node_info(&account_node);

    //Non hardened derivation to find change node
    HDNode change_node=account_node;
    // INDEX based on change in transaction, 0 for external(receiving payments), 1 for internal(signing transactions)
    uint32_t change_index;
    printf("\nEnter change index: ");
    scanf("%d", &change_index);
    if (!hdnode_private_ckd(&change_node, change_index))
    {
        fprintf(stderr, "Failed to derive change node\n");
        return 1;
    }

    printf("\nChange node: \n");
    get_node_info(&change_node);

    // Non hardened derivation to find address node
    HDNode address_node=change_node;
    // INDEX based on address number
    uint32_t address_index;
    printf("\nEnter address index: ");
    scanf("%d", &address_index);
    if (!hdnode_private_ckd(&address_node, address_index))
    {
        fprintf(stderr, "Failed to derive address node\n");
        return 1;
    }

    printf("\nAddress node: \n");
    get_node_info(&address_node);

    // Get public key
    uint8_t public_key[33];
    hdnode_fill_public_key(&address_node);
    memcpy(public_key, address_node.public_key, sizeof(address_node.public_key));

    printf("\nPublic key: ");
    for (int i=0; i<33; i++)
    {
        printf("%02x", public_key[i]);
    }
    printf("\n");

    // UNSIGNED TRANSACTION DETAILS
    const char *unsigned_transaction = "0200000001a5f69f8a3bf5901a1943e6b20c2a46579bbebb075a07a113ac06c0141a1f9d70010000001976a9148d4cd2f8e2d7a49f417180bd6c46142c6b5e771f88acffffffff0260ea0000000000001976a914ed614881f32c024a80d1b6b58dfed8f493f41c7288acf81d0c00000000001976a914857990da1c4f984127e7229f52cffb33b0dfc67488ac00000000";
    Transaction trans;
    trans.version = 0x02000000;
    trans.num_inputs = 0x01;

    const char* prev_transhash_rev = "a5f69f8a3bf5901a1943e6b20c2a46579bbebb075a07a113ac06c0141a1f9d70";
    for (int i = 0; i < 32; i++) {
    sscanf(&prev_transhash_rev[i * 2], "%02hhx", &trans.prev_transhash_rev[i]);
    }

    trans.prev_output_index = 0x01000000;
    trans.script_length_input = 0x19;

    const char* script_sig = "76a9148d4cd2f8e2d7a49f417180bd6c46142c6b5e771f88ac";
    for (int i = 0; i < 25; i++) {
    sscanf(&script_sig[i * 2], "%02hhx", &trans.script_sig[i]);
    }

    trans.sequence = 0xffffffff;
    trans.num_outputs = 0x02;

    const char* value = "60ea000000000000";
    for (int i = 0; i < 8; i++) {
    sscanf(&value[i * 2], "%02hhx", &trans.value[i]);
    }

    trans.script_length_output = 0x19;
    const char* script_pub_key = "76a914ed614881f32c024a80d1b6b58dfed8f493f41c7288ac";
    for (int i = 0; i < 25; i++) {
    sscanf(&script_pub_key[i * 2], "%02hhx", &trans.script_pub_key[i]);
    }

    trans.locktime = 0x00000000;
    trans.sighash = 0x01000000;

    printf("\n");

    //SIGNING PROCESS
    uint8_t digest[SHA256_DIGEST_LENGTH];
    size_t byte_len;
    uint8_t* byte_array = hex_str_to_byte_array(unsigned_transaction, &byte_len);

    const uint8_t new_data[] = {0x01, 0x00, 0x00, 0x00};
    size_t new_data_len = sizeof(new_data);
    size_t total_len = byte_len + new_data_len;
    uint8_t* new_array = (uint8_t*)malloc(total_len * sizeof(uint8_t));

    // Copy existing data
    memcpy(new_array, byte_array, byte_len * sizeof(uint8_t));

    // Append new data
    memcpy(new_array + byte_len, new_data, new_data_len * sizeof(uint8_t));

    printf("Array to be hashed: ");
    for (int i=0; i<total_len; i++) {
    printf("%02x", new_array[i]);
    }
    printf("\n");

    uint8_t temp_digest[SHA256_DIGEST_LENGTH];
    sha256_Raw(new_array, total_len, temp_digest);
    sha256_Raw(temp_digest, sizeof(digest), digest);

    printf("Digest: ");
    for (int i=0; i<SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");

    uint8_t signature[65];
    uint8_t *priv_key=address_node.private_key;
    ecdsa_sign_digest(&secp256k1, (const uint8_t *)priv_key, digest, signature, NULL, NULL);

    printf("Signature:");
    for (int i=0; i<65; i++)
    {
        printf("%02x", signature[i]);
    }
    printf("\n");

    // Creating scriptsig
    uint8_t scriptsig[107];
    scriptsig[0] = 0x48;
    scriptsig[1] = 0x30;
    scriptsig[2] = 0x45;
    scriptsig[3] = 0x02;
    scriptsig[4] = 0x21;
    scriptsig[5] = 0x00;

    memcpy(scriptsig + 6, signature, 32);
    scriptsig[38] = 0x02;
    scriptsig[39] = 0x20;

    memcpy(scriptsig + 40, signature + 32, 32);
    scriptsig[72] = 0x01;
    scriptsig[73] = 0x21;

    memcpy(scriptsig + 74, public_key, 33);

    printf("\nScriptSig: \n");
    for (int i=0; i<107; i++)
    {
        printf("%02x", scriptsig[i]);
    }
    printf("\n");

    memcpy(trans.script_sig, scriptsig, 107);

    // PRINTING SERIALIZED TRANSACTION
    printf("\nSerialized Transaction: \n");
    printf("%08x", trans.version);
    printf("%02x", trans.num_inputs);
    for (int i = 0; i < 32; i++) printf("%02x", trans.prev_transhash_rev[i]);
    printf("%08x", trans.prev_output_index);
    printf("6b");
    for (int i = 0; i < 107; i++) printf("%02x", trans.script_sig[i]);
    printf("%08x", trans.sequence);
    printf("%02x", trans.num_outputs);
    for (int i = 0; i < 8; i++) printf("%02x", trans.value[i]);
    printf("%02x", trans.script_length_output);
    for (int i = 0; i < 25; i++) printf("%02x", trans.script_pub_key[i]);
    // Second output
    printf("f81d0c00000000001976a914857990da1c4f984127e7229f52cffb33b0dfc67488ac");
    printf("%08x", trans.locktime);

    printf("\n");

    return 0;
}