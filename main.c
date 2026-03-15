#include <sodium/crypto_pwhash.h>
#include <sodium/utils.h>
#include <stdio.h>
#include <sodium.h>
#include <stdbool.h>
#include <string.h>

/*compile command: gcc main.c \
  -Ivendor/libsodium/build/include \
  -Lvendor/libsodium/build/lib \
  -lsodium -o main
*/

FILE *fptr;
FILE *fptr2;

void askNewPassphrase() {
    char passPhrase[256];
    char hash[crypto_pwhash_STRBYTES];

    printf("Enter your new master passphrase:\n");

    if(fgets(passPhrase, sizeof(passPhrase), stdin) == NULL){
        fprintf(stderr, "Input error\n");
        return;
    }

    passPhrase[strcspn(passPhrase, "\n")] = 0;

    size_t pass_len = strlen(passPhrase);

    if(crypto_pwhash_str(hash, passPhrase, pass_len,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0){

        fprintf(stderr, "Password hashing failed\n");
        sodium_memzero(passPhrase, sizeof(passPhrase));
        return;
    }

    fptr = fopen("data.2fuc", "w");
    fprintf(fptr, "%s", hash);
    fclose(fptr);

    sodium_memzero(passPhrase, sizeof(passPhrase));
}

int main(){ 


    bool authenticated = false;

    if (sodium_init() < 0) {
        printf("Sodium failed init\n");
        return 1;
    }

    bool newToProgram = false;//false by default
    char pwd[256];
    char dataInFirstLn[crypto_pwhash_STRBYTES];

    //check if new to program and adjust the bool properly


    if(newToProgram == true){
        printf("Welcome to PassoutManager!\n");
        askNewPassphrase();
        fptr2 = fopen("data.1fuc", "w");
        fclose(fptr2);
    }else{
        printf("Enter your master passphrase: \n");

        fgets(pwd, sizeof(pwd), stdin);
        pwd[strcspn(pwd, "\n")] = 0;

        fptr = fopen("data.2fuc", "r");
        fgets(dataInFirstLn, sizeof(dataInFirstLn), fptr);

        if (crypto_pwhash_str_verify(dataInFirstLn, pwd, strlen(pwd)) == 0) {
            printf("Successfully logged in\n");
            authenticated = true;
        } else {
            printf("Wrong password\n");
        }

        sodium_memzero(pwd, sizeof(pwd));
        fclose(fptr);
    }


    //##AUTHENTICATION ABOVE##//

    






    return 0;
}