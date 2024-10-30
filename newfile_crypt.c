#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef DEBUG
#include <ctype.h>
#endif

#define PASS_LEN_MAX 256

unsigned long lrand(void);

int get_password(char* password, unsigned long* pass_len) {
    printf("Password: ");
    if (scanf("%255s", password) != 1) {
        return 1;
    }
    *pass_len = strlen(password);
    return 0;
}

int open_files(const char* file_path, FILE** file, FILE** temp, char** temp_path) {
    if (access(file_path, R_OK) != 0) {
        perror("Error accessing file");
        fprintf(stderr, "File path: %s\n", file_path);
        return 1;
    }

    *file = fopen(file_path, "rb");
    if (!*file) {
        perror("Error opening file");
        fprintf(stderr, "File path: %s\n", file_path);
        return 1;
    }

    unsigned long temp_len = strlen(file_path) + 1 + 32 + 6;
    *temp_path = malloc(temp_len + 1);
    if (!*temp_path) {
        perror("Error allocating memory");
        fclose(*file);
        return 1;
    }
    sprintf(*temp_path, "%s-%016lx%016lx.crypt", file_path, lrand(), lrand());
    *temp = fopen(*temp_path, "wb");
    if (!*temp) {
        perror("Error opening temporary file");
        free(*temp_path);
        fclose(*file);
        return 1;
    }
    return 0;
}

int encrypt_file(FILE* file, FILE* temp, const char* password, unsigned long pass_len) {
    unsigned char file_byte;
    unsigned long i = 0;
    while (1) {
        int file_res = fgetc(file);
        if (file_res < 0 || file_res > 255) {
            break;
        }

        file_byte = (unsigned char) file_res ^ password[i % pass_len];

#ifdef DEBUG
        char debug_char_before = isprint(file_res) ? file_res : ' ';
        char debug_char_after = isprint(file_byte) ? file_byte : ' ';
        printf("%c (0x%02x) -> %c (0x%02x)\n", debug_char_before, file_res, debug_char_after, file_byte);
#endif

        fputc((int) file_byte, temp);
        i++;
    }
    return 0;
}

int close_files(FILE* file, FILE* temp, const char* file_path, char* temp_path) {
    if (fclose(file) != 0) {
        perror("Error closing file");
        return 1;
    }

    if (fclose(temp) != 0) {
        perror("Error closing temporary file");
        return 1;
    }

    if (remove(file_path) != 0) {
        perror("Error removing original file");
        return 1;
    }

    if (rename(temp_path, file_path) != 0) {
        perror("Error renaming temporary file");
        return 1;
    }
    free(temp_path);
    return 0;
}

unsigned long lrand(void) {
    unsigned long rand;
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        perror("Error opening /dev/urandom");
        exit(1);
    }
    fread(&rand, sizeof(rand), 1, urandom);
    fclose(urandom);
    return rand;
}

int main() {
    char file_path[256];
    printf("Enter the file path: ");
    if (scanf("%255s", file_path) != 1) {
        fprintf(stderr, "Error reading file path\n");
        return 1;
    }

    char password[PASS_LEN_MAX];
    unsigned long pass_len;
    if (get_password(password, &pass_len) != 0) {
        return 1;
    }

    char* temp_path;
    FILE* file;
    FILE* temp;
    if (open_files(file_path, &file, &temp, &temp_path) != 0) {
        return 1;
    }

    if (encrypt_file(file, temp, password, pass_len) != 0) {
        return 1;
    }

    if (close_files(file, temp, file_path, temp_path) != 0) {
        return 1;
    }

    return 0;
}