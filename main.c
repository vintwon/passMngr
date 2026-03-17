/*
 * PassoutManager — secure version (fixed MAX_INPUT + heap safety)
 *
 * compile:
 *   gcc main.c \
 *     -Ivendor/libsodium/build/include \
 *     -Lvendor/libsodium/build/lib \
 *     -lsodium -o main
 *
 * Files used:
 *   data.2fuc  — master password hash (Argon2id) + key-derivation salt
 *   data.1fuc  — XChaCha20-Poly1305 encrypted password store
 */

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#ifndef MAX_INPUT
#define MAX_INPUT 256
#endif

#define PASS_FILE   "data.1fuc"   
#define META_FILE   "data.2fuc"   

#define KEY_LEN     crypto_secretstream_xchacha20poly1305_KEYBYTES
#define HDR_LEN     crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define TAG_LEN     crypto_secretstream_xchacha20poly1305_ABYTES
#define MAX_PROGRAMS 100

/* ------------------------------------------------------------------ */
/*  Secure input (hidden echo)                                        */
/* ------------------------------------------------------------------ */

static void get_password(char *buf, size_t len, const char *prompt) {
    printf("%s", prompt);
    fflush(stdout);

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    GetConsoleMode(hStdin, &mode);
    DWORD old_mode = mode;

    mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(hStdin, mode);

    if (fgets(buf, len, stdin) != NULL)
        buf[strcspn(buf, "\n")] = '\0';

    SetConsoleMode(hStdin, old_mode);

#else
    struct termios oldt, newt;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    if (fgets(buf, len, stdin) != NULL)
        buf[strcspn(buf, "\n")] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    printf("\n");
}

/* ------------------------------------------------------------------ */
/*  Key derivation                                                     */
/* ------------------------------------------------------------------ */

static int derive_key(unsigned char key[KEY_LEN],
                      const char *passphrase,
                      const unsigned char salt[crypto_pwhash_SALTBYTES])
{
    return crypto_pwhash(key, KEY_LEN,
                         passphrase, strlen(passphrase),
                         salt,
                         crypto_pwhash_OPSLIMIT_MODERATE,
                         crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_DEFAULT);
}

/* ------------------------------------------------------------------ */
/*  Encrypt / Decrypt password store                                   */
/* ------------------------------------------------------------------ */

static long decrypt_store(const unsigned char key[KEY_LEN],
                          char **out)
{
    *out = NULL;

    FILE *fp = fopen(PASS_FILE, "rb");
    if (!fp) {
        *out = calloc(1, 1);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    if (fsize < (long)(HDR_LEN + TAG_LEN)) {
        fclose(fp);
        *out = calloc(1, 1);
        return 0;
    }

    unsigned char *ciphertext = malloc(fsize);
    if (!ciphertext) { fclose(fp); return -1; }

    if ((long)fread(ciphertext, 1, fsize, fp) != fsize) {
        free(ciphertext); fclose(fp); return -1;
    }
    fclose(fp);

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, ciphertext, key) != 0) {
        fprintf(stderr, "Decryption init failed (wrong key or corrupted file)\n");
        sodium_memzero(ciphertext, fsize);
        free(ciphertext);
        return -1;
    }

    long ct_body_len = fsize - HDR_LEN;
    long pt_len = ct_body_len - TAG_LEN;
    if (pt_len < 0) pt_len = 0;

    unsigned char *plain = malloc(pt_len + 1);
    if (!plain) { free(ciphertext); return -1; }

    unsigned long long actual_pt_len = 0;
    unsigned char tag = 0;

    if (crypto_secretstream_xchacha20poly1305_pull(
            &st,
            plain, &actual_pt_len, &tag,
            ciphertext + HDR_LEN, ct_body_len,
            NULL, 0) != 0)
    {
        fprintf(stderr, "Decryption failed — wrong passphrase or file corrupt\n");
        sodium_memzero(plain, pt_len + 1);
        free(plain);
        sodium_memzero(ciphertext, fsize);
        free(ciphertext);
        return -1;
    }

    plain[actual_pt_len] = '\0';
    sodium_memzero(ciphertext, fsize);
    free(ciphertext);

    *out = (char *)plain;
    return (long)actual_pt_len;
}

static int encrypt_store(const unsigned char key[KEY_LEN],
                         const char *plain, size_t len)
{
    size_t ct_len = HDR_LEN + len + TAG_LEN;
    unsigned char *ciphertext = malloc(ct_len);
    if (!ciphertext) return -1;

    crypto_secretstream_xchacha20poly1305_state st;
    crypto_secretstream_xchacha20poly1305_init_push(&st, ciphertext, key);

    unsigned long long actual_ct_len = 0;
    crypto_secretstream_xchacha20poly1305_push(
        &st,
        ciphertext + HDR_LEN, &actual_ct_len,
        (const unsigned char *)plain, len,
        NULL, 0,
        crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    FILE *fp = fopen(PASS_FILE, "wb");
    if (!fp) { sodium_memzero(ciphertext, ct_len); free(ciphertext); return -1; }

    size_t written = fwrite(ciphertext, 1, HDR_LEN + actual_ct_len, fp);
    fclose(fp);

    sodium_memzero(ciphertext, ct_len);
    free(ciphertext);

    return (written == HDR_LEN + actual_ct_len) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/*  First-time setup                                                   */
/* ------------------------------------------------------------------ */

static int first_time_setup(unsigned char key_out[KEY_LEN])
{
    char passPhrase[MAX_INPUT];
    char confirm[MAX_INPUT];
    char hash[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    printf("Welcome to PassoutManager!\n");

    get_password(passPhrase, sizeof(passPhrase), "Create master passphrase: ");
    get_password(confirm, sizeof(confirm), "Confirm master passphrase: ");

    if (strcmp(passPhrase, confirm) != 0) {
        fprintf(stderr, "Passphrases do not match\n");
        sodium_memzero(passPhrase, sizeof(passPhrase));
        sodium_memzero(confirm, sizeof(confirm));
        return -1;
    }
    sodium_memzero(confirm, sizeof(confirm));

    if (crypto_pwhash_str(hash, passPhrase, strlen(passPhrase),
                          crypto_pwhash_OPSLIMIT_MODERATE,
                          crypto_pwhash_MEMLIMIT_MODERATE) != 0)
    {
        fprintf(stderr, "Password hashing failed\n");
        sodium_memzero(passPhrase, sizeof(passPhrase));
        return -1;
    }

    randombytes_buf(salt, sizeof(salt));

    if (derive_key(key_out, passPhrase, salt) != 0) {
        fprintf(stderr, "Key derivation failed\n");
        sodium_memzero(passPhrase, sizeof(passPhrase));
        return -1;
    }
    sodium_memzero(passPhrase, sizeof(passPhrase));

    FILE *fp = fopen(META_FILE, "wb");
    if (!fp) { fprintf(stderr, "Cannot write %s\n", META_FILE); return -1; }
    fwrite(hash, 1, crypto_pwhash_STRBYTES, fp);
    fwrite(salt, 1, crypto_pwhash_SALTBYTES, fp);
    fclose(fp);

    if (encrypt_store(key_out, "", 0) != 0) {
        fprintf(stderr, "Failed to create encrypted store\n");
        return -1;
    }

    printf("Setup complete.\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Login                                                              */
/* ------------------------------------------------------------------ */

static bool login(unsigned char key_out[KEY_LEN])
{
    FILE *fp = fopen(META_FILE, "rb");
    if (!fp) { fprintf(stderr, "No master passphrase set.\n"); return false; }

    char hash[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    if (fread(hash, 1, crypto_pwhash_STRBYTES, fp) != crypto_pwhash_STRBYTES ||
        fread(salt, 1, crypto_pwhash_SALTBYTES, fp) != crypto_pwhash_SALTBYTES)
    {
        fprintf(stderr, "Corrupt metadata file\n");
        fclose(fp);
        return false;
    }
    fclose(fp);

    char pwd[MAX_INPUT];
    get_password(pwd, sizeof(pwd), "Enter master passphrase: ");

    bool ok = false;
    if (crypto_pwhash_str_verify(hash, pwd, strlen(pwd)) == 0) {
        if (derive_key(key_out, pwd, salt) == 0)
            ok = true;
    } else {
        printf("Wrong passphrase\n");
    }

    sodium_memzero(pwd, sizeof(pwd));
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Store operations                                                   */
/* ------------------------------------------------------------------ */

/* (rest of your file unchanged — omitted here for brevity in explanation, but in your actual copy keep everything exactly as you wrote it) */

static char *store_add_entry(const char *store,
                             const char *program,
                             const char *username,
                             const char *password)
{
    size_t old_len = strlen(store);

    size_t block_len = 1 + strlen(program) + 2 + 10 + strlen(username) + 2 + 10 + strlen(password) + 3;
    // newline + program + { + #USERNAME: + username + ; + &PASSWORD: + password + ; + }

    char *newstore = malloc(old_len + block_len + 1);
    if (!newstore) return NULL;

    memcpy(newstore, store, old_len);
    int n = snprintf(newstore + old_len, block_len + 1,
                     "\n%s{\n#USERNAME:%s;\n&PASSWORD:%s;\n}",
                     program, username, password);
    if (n < 0 || (size_t)n > block_len) {
        free(newstore);
        return NULL;
    }
    return newstore;
}

static int store_list_programs(const char *store, char programs[][MAX_INPUT], int maxprog)
{
    int count = 0;
    char *buf = strdup(store);
    if (!buf) return 0;

    char *line = strtok(buf, "\n");
    while (line && count < maxprog) {
        char *brace = strchr(line, '{');
        if (brace) {
            size_t name_len = (size_t)(brace - line);
            if (name_len > 0 && name_len < MAX_INPUT) {
                strncpy(programs[count], line, name_len);
                programs[count][name_len] = '\0';
                count++;
            }
        }
        line = strtok(NULL, "\n");
    }
    free(buf);
    return count;
}

static void store_print_entry(const char *store, const char *chosen_program)
{
    char *buf = strdup(store);
    if (!buf) return;

    bool inside = false;
    char *line = strtok(buf, "\n");

    while (line) {
        char *brace = strchr(line, '{');
        if (brace) {
            size_t name_len = (size_t)(brace - line);
            char name[MAX_INPUT] = {0};
            if (name_len < MAX_INPUT) {
                strncpy(name, line, name_len);
                name[name_len] = '\0';
                inside = (strcmp(name, chosen_program) == 0);
            }
            line = strtok(NULL, "\n");
            continue;
        }

        if (inside) {
            if (strncmp(line, "#USERNAME:", 10) == 0) {
                char tmp[MAX_INPUT];
                strncpy(tmp, line + 10, sizeof(tmp) - 1);
                tmp[sizeof(tmp) - 1] = '\0';
                tmp[strcspn(tmp, ";")] = '\0';
                printf("Username: %s\n", tmp);
            } else if (strncmp(line, "&PASSWORD:", 10) == 0) {
                char tmp[MAX_INPUT];
                strncpy(tmp, line + 10, sizeof(tmp) - 1);
                tmp[sizeof(tmp) - 1] = '\0';
                tmp[strcspn(tmp, ";")] = '\0';
                printf("Password: %s\n", tmp);
            } else if (strchr(line, '}')) {
                break;
            }
        }

        line = strtok(NULL, "\n");
    }

    sodium_memzero(buf, strlen(buf));
    free(buf);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    unsigned char key[KEY_LEN];
    sodium_memzero(key, sizeof(key));

    FILE *meta_test = fopen(META_FILE, "rb");
    if (!meta_test) {
        if (first_time_setup(key) != 0) { sodium_memzero(key, sizeof(key)); return 1; }
    } else {
        fclose(meta_test);
        if (!login(key)) { sodium_memzero(key, sizeof(key)); return 1; }
    }

    char input[MAX_INPUT];

    while (true) {
        printf("\n1. Read a password/program\n2. Add a new password/program\n3. Quit\nChoice: ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = '\0';

        if (strcmp(input, "3") == 0) break;

        if (strcmp(input, "2") == 0) {
            char program[MAX_INPUT], username[MAX_INPUT], password[MAX_INPUT];

            printf("Program name: "); fgets(program, sizeof(program), stdin); program[strcspn(program, "\n")] = '\0';
            printf("Username: "); fgets(username, sizeof(username), stdin); username[strcspn(username, "\n")] = '\0';
            get_password(password, sizeof(password), "Password: ");

            char *store = NULL;
            if (decrypt_store(key, &store) < 0) {
                fprintf(stderr, "Could not read store\n");
                sodium_memzero(password, sizeof(password));
                continue;
            }

            char *new_store = store_add_entry(store, program, username, password);
            sodium_memzero(store, strlen(store)); free(store);
            sodium_memzero(password, sizeof(password));

            if (!new_store) { fprintf(stderr, "Memory error\n"); continue; }

            if (encrypt_store(key, new_store, strlen(new_store)) != 0)
                fprintf(stderr, "Encryption failed — entry NOT saved\n");
            else
                printf("Entry saved (encrypted).\n");

            sodium_memzero(new_store, strlen(new_store)); free(new_store);
            continue;
        }

        if (strcmp(input, "1") == 0) {
            char *store = NULL;
            if (decrypt_store(key, &store) < 0) { fprintf(stderr, "Could not decrypt store\n"); continue; }

            char programs[MAX_PROGRAMS][MAX_INPUT];
            int prog_count = store_list_programs(store, programs, MAX_PROGRAMS);

            if (prog_count == 0) { printf("No saved programs.\n"); sodium_memzero(store, strlen(store)); free(store); continue; }

            printf("\nSelect a program:\n");
            for (int i = 0; i < prog_count; i++) printf("%d. %s\n", i + 1, programs[i]);

            printf("Choice: "); fflush(stdout);
            fgets(input, sizeof(input), stdin);
            int choice = atoi(input);

            if (choice < 1 || choice > prog_count) printf("Invalid choice\n");
            else store_print_entry(store, programs[choice - 1]);

            sodium_memzero(store, strlen(store)); free(store);
            continue;
        }

        printf("Unknown option.\n");
    }

    sodium_memzero(key, sizeof(key));
    printf("\nGoodbye!\n");
    return 0;
}