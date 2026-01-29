#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define PASSES 7
#define BUFFER_SIZE 4096

static const unsigned char patterns[PASSES][3] = {
    {0x00, 0x00, 0x00},  // All zeros
    {0xFF, 0xFF, 0xFF},  // All ones
    {0x55, 0x55, 0x55},  // 01010101
    {0xAA, 0xAA, 0xAA},  // 10101010
    {0x92, 0x49, 0x24},  // Random pattern 1
    {0x49, 0x24, 0x92},  // Random pattern 2
    {0x24, 0x92, 0x49}   // Random pattern 3
};

int secure_delete(const char *filename) {
    struct stat st;
    if (stat(filename, &st) != 0) {
        perror("stat");
        return -1;
    }
    
    int fd = open(filename, O_WRONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    
    size_t filesize = st.st_size;
    unsigned char buffer[BUFFER_SIZE];
    
    // Multiple pass overwrite
    for (int pass = 0; pass < PASSES; pass++) {
        lseek(fd, 0, SEEK_SET);
        
        // Fill buffer with pattern
        for (int i = 0; i < BUFFER_SIZE; i++) {
            buffer[i] = patterns[pass][i % 3];
        }
        
        size_t written = 0;
        while (written < filesize) {
            size_t to_write = (filesize - written > BUFFER_SIZE) ? BUFFER_SIZE : filesize - written;
            if (write(fd, buffer, to_write) != to_write) {
                perror("write");
                close(fd);
                return -1;
            }
            written += to_write;
        }
        
        fdatasync(fd);
    }
    
    // Final random pass
    lseek(fd, 0, SEEK_SET);
    srand(time(NULL));
    size_t written = 0;
    while (written < filesize) {
        for (int i = 0; i < BUFFER_SIZE; i++) {
            buffer[i] = rand() % 256;
        }
        size_t to_write = (filesize - written > BUFFER_SIZE) ? BUFFER_SIZE : filesize - written;
        if (write(fd, buffer, to_write) != to_write) {
            perror("write");
            close(fd);
            return -1;
        }
        written += to_write;
    }
    
    fdatasync(fd);
    close(fd);
    
    // Rename file multiple times
    char temp_name[256];
    for (int i = 0; i < 10; i++) {
        snprintf(temp_name, sizeof(temp_name), "%d%d%d", rand(), rand(), rand());
        rename(filename, temp_name);
    }
    
    // Finally delete
    unlink(temp_name);
    
    return 0;
}
