#include <sodium/crypto_pwhash.h>
#include <sodium/utils.h>
#include <stdio.h>
#include <sodium.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

/*compile command: gcc main.c \
  -Ivendor/libsodium/build/include \
  -Lvendor/libsodium/build/lib \
  -lsodium -o main
*/

FILE *fptr;
FILE *fptr2;

int count_lines(char *filename) {
    FILE *fp = fopen(filename, "r");
    int count = 0;
    int ch;

    if (fp == NULL) {
        printf("Could not open file %s\n", filename);
        return -1;
    }

    while ((ch = fgetc(fp)) != EOF) {
        if (ch == '\n') {
            count++;
        }
    }

    fclose(fp);
    return count;
}

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

void addNewUser(char program[], char username[], char password[]){
    fptr2 = fopen("data.1fuc", "a");

    fprintf(fptr2, "\n%s{", program);
    fprintf(fptr2,"\n#USERNAME:%s;", username);
    fprintf(fptr2, "\n&PASSWORD:%s;", password);
    fprintf(fptr2, "\n}");

    fclose(fptr2);

    printf("\nADDED NEW USER\n");
}

int main(){ 

    bool authenticated = true;

    if (sodium_init() < 0) {
        printf("Sodium failed init\n");
        return 1;
    }

    bool newToProgram = false;//false by default






    char pwd[256];
    char dataInFirstLn[crypto_pwhash_STRBYTES];

    if(newToProgram == true){

        printf("Welcome to PassoutManager!\n");
        askNewPassphrase();

        fptr2 = fopen("data.1fuc", "w");
        fclose(fptr2);

    }else{

        printf("Enter your master passphrase:\n");

        fgets(pwd, sizeof(pwd), stdin);
        pwd[strcspn(pwd, "\n")] = 0;

        fptr = fopen("data.2fuc", "r");

        if (fptr == NULL) {
            printf("No master password set. Run first-time setup.\n");
            return 1;
        }

        fgets(dataInFirstLn, sizeof(dataInFirstLn), fptr);

        if (crypto_pwhash_str_verify(dataInFirstLn, pwd, strlen(pwd)) == 0) {
            printf("Successfully logged in\n");
            authenticated = true;
        } else {
            printf("Wrong password\n");
            authenticated = false;
        }

        sodium_memzero(pwd, sizeof(pwd));
        fclose(fptr);
    }

    char input[256];
    char username[256];
    char password[256];

    while(authenticated == true){

        printf("\nEnter an option:\n");
        printf("1. Read a password/program\n");
        printf("2. Add a new password/program\n");
        printf("3. Quit\n");

        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;

        if(strcmp(input, "3") == 0){

            authenticated = false;

        }else if (strcmp(input, "2") == 0) {

            printf("Enter program name (e.g. Discord):\n");
            fgets(input, sizeof(input), stdin);
            input[strcspn(input, "\n")] = 0;

            printf("Enter program username:\n");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;

            printf("Enter program password:\n");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = 0;

            addNewUser(input, username, password);

        }else if (strcmp(input, "1") == 0){

            fptr2 = fopen("data.1fuc", "r");

            if(fptr2 != NULL){

                char line[256];
                char programs[100][256];
                int programCount = 0;

                while(fgets(line, sizeof(line), fptr2)){

                    if(strchr(line, '{') != NULL){

                        line[strcspn(line, "{")] = 0;

                        strcpy(programs[programCount], line);
                        programCount++;
                    }
                }

                if(programCount == 0){
                    printf("No saved programs.\n");
                    fclose(fptr2);
                    continue;
                }

                printf("\nSelect a program:\n");

                for(int i = 0; i < programCount; i++){
                    printf("%d. %s\n", i+1, programs[i]);
                }

                printf("Choice: ");
                fgets(input, sizeof(input), stdin);
                int choice = atoi(input);

                if(choice < 1 || choice > programCount){
                    printf("Invalid choice\n");
                    fclose(fptr2);
                    continue;
                }

                char chosenProgram[256];
                strcpy(chosenProgram, programs[choice-1]);

                rewind(fptr2);

                bool insideBlock = false;

                while(fgets(line, sizeof(line), fptr2)){

                    if(strchr(line, '{') != NULL){

                        char temp[256];
                        strcpy(temp, line);

                        temp[strcspn(temp, "{")] = 0;

                        if(strcmp(temp, chosenProgram) == 0){
                            insideBlock = true;
                            continue;
                        }
                    }

                    if(insideBlock){

                        if(strncmp(line, "#USERNAME:", 10) == 0){

                            char *token = strtok(line, ":");
                            token = strtok(NULL, ";");

                            printf("Username: %s\n", token);
                        }

                        if(strncmp(line, "&PASSWORD:", 10) == 0){

                            char *token = strtok(line, ":");
                            token = strtok(NULL, ";");

                            printf("Password: %s\n", token);
                        }

                        if(strchr(line, '}') != NULL){
                            break;
                        }
                    }
                }

                fclose(fptr2);

            }else{

                printf("file not found\n");
            }
        }
    }

    printf("\nGoodbye!\n");
    return 0;
}