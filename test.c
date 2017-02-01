#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include "paillier.h"

#define KEY_SIZE 1024
#define DEBUG_MODE 0   // 1 to show all DEBUG INFO


int main(int argc, char **argv) {
    
    
    printf("STARTING TEST\n");
    
    
    printf("TESTING KEY GENERATION\n");
    /* Generating Keypair */
    paillier_pubkey_t* pub;
    paillier_prvkey_t* prv;
    paillier_keygen(KEY_SIZE, &pub, &prv, paillier_get_rand_devurandom);
    
    if(DEBUG_MODE){
        gmp_printf("private key p:%Zd \n", prv->p);
        gmp_printf("private key q:%Zd \n", prv->q);
        gmp_printf("public key n:%Zd \n", pub->n);
    }
    
    if(mpz_sizeinbase(pub->n, 2) != KEY_SIZE){
        printf("TEST FAILED: KEYGEN\n");
        return EXIT_FAILURE;
    }
    
    /* Encryption of a small integer */
    printf("TESTING ENCRYPTION\n");
    
    // Encryption of a small integer
    paillier_plaintext_t *small_plaintext = paillier_plaintext_from_ui(42);
    paillier_ciphertext_t *small_ciphertext;
    paillier_enc(&small_ciphertext, pub, small_plaintext, paillier_get_rand_devurandom);
    
    // Encryption of a large number
    char *magic_number_str = "9601375721773960030826048348718350956180868954786249183055522621772391594913965263068361191091587324151101807311169301869981191762119859865346892157945421998951222949069729370836921713919282283633399891943869137940899827469813950721928452427835958620445001112962904065293585229146038515621140909326729";
    paillier_plaintext_t *large_plaintext = paillier_plaintext_from_str(magic_number_str, 10);
    paillier_ciphertext_t *large_ciphertext;
    paillier_enc(&large_ciphertext, pub, large_plaintext, paillier_get_rand_devurandom);
    
    if(DEBUG_MODE){
        gmp_printf("small_plaintext : %Zd \n", small_plaintext->m);
        gmp_printf("small_ciphertext: %Zd \n", small_ciphertext->c);
        gmp_printf("large_plaintext : %Zd \n", large_plaintext->m);
        gmp_printf("large_ciphertext: %Zd \n", large_ciphertext->c);
    }
    
    printf("TESTING DECRYPTION\n");
    /* Decryption of a small integer */
    paillier_plaintext_t *decrypted_small_plaintext;
    paillier_dec(&decrypted_small_plaintext, pub, prv, small_ciphertext);
    if( mpz_cmp(decrypted_small_plaintext->m, small_plaintext->m) != 0) {
        printf("TEST FAILED: DECRYPTION SMALL NUMBER\n");
        return EXIT_FAILURE;
    }
    
    paillier_plaintext_t *decrypted_large_plaintext;
    paillier_dec(&decrypted_large_plaintext, pub, prv, large_ciphertext);
    if( mpz_cmp(decrypted_large_plaintext->m, large_plaintext->m) != 0) {
        printf("TEST FAILED: DECRYPTION LARGE NUMBER\n");
        return EXIT_FAILURE;
    }
    
    if(DEBUG_MODE){
        gmp_printf("encrypted small value: %Zd \n", small_plaintext->m);
        gmp_printf("decrypted small value: %Zd \n", decrypted_small_plaintext->m);
        gmp_printf("encrypted large value: %Zd \n", large_plaintext->m);
        gmp_printf("decrypted small value: %Zd \n", decrypted_large_plaintext->m);
    }
    
    
    printf("TESTING MULTIPLICATION\n");
    /* Multiplication of two values */

    paillier_ciphertext_t *ciphertext_result;
    paillier_mul(&ciphertext_result, pub, small_ciphertext, large_ciphertext);
    
    if(DEBUG_MODE){
        gmp_printf("encrypted multiplied value: %Zd \n", ciphertext_result->c);
    }
    
    paillier_plaintext_t *decrypted_multiplied_plaintext;
    paillier_dec(&decrypted_multiplied_plaintext, pub, prv, ciphertext_result);
    
    mpz_t added;
    mpz_init(added);
    mpz_add_ui(added, large_plaintext->m, 42);

    if( mpz_cmp(decrypted_multiplied_plaintext->m, added) != 0) {
        printf("MULTIPLICATION FAILED \n");
        gmp_printf("result: %Zd\n", decrypted_multiplied_plaintext->m);
        gmp_printf("expected:  %Zd\n", added);
        return EXIT_FAILURE;
    }
    
    mpz_clear(added);

    printf("ALL TESTS PASSED\n");
    
    /* Cleaning */
    paillier_freeplaintext(small_plaintext);
    paillier_freeplaintext(large_plaintext);
    
    paillier_freeplaintext(decrypted_small_plaintext);
    paillier_freeplaintext(decrypted_large_plaintext);
    
    paillier_freeplaintext(decrypted_multiplied_plaintext);
    
    paillier_freeciphertext(small_ciphertext);
    paillier_freeciphertext(large_ciphertext);
    paillier_freeciphertext(ciphertext_result);
    
    paillier_freepubkey(pub);
    paillier_freeprvkey(prv);

    
    return 0;
}