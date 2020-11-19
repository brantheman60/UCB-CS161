#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define MAX_BUFSIZE 128
#define FILENAME "hack"

#define EXIT_WITH_ERROR(message) do { \
  fprintf(stderr, "%s\n", message); \
  exit(EXIT_FAILURE); \
} while (0);

int file_is_too_big(int fd) {
  struct stat st;
  fstat(fd, &st);
  return st.st_size >= MAX_BUFSIZE;
}

void read_file() {
  char buf[MAX_BUFSIZE]; // 128 bytes
  uint32_t bytes_to_read; // 32 bytes, unsigned

  int fd = open(FILENAME, O_RDONLY); // open 'hack'
  if (fd == -1) EXIT_WITH_ERROR("Could not find file!");

  if (file_is_too_big(fd)) EXIT_WITH_ERROR("File too big!");

  printf("How many bytes should I read? "); // BREAKPOINT
  fflush(stdout);
  if (scanf("%u", &bytes_to_read) != 1) // while waiting, add/remove stuff
    EXIT_WITH_ERROR("Could not read the number of bytes to read!");

  ssize_t bytes_read = read(fd, buf, bytes_to_read); // try to write >128
  if (bytes_read == -1) EXIT_WITH_ERROR("Could not read!");

  buf[bytes_read] = 0;
  printf("Here is the file!\n%s", buf); // BREAKPOINT
  close(fd);
}

int main() {
  read_file();
  return 0;
}
