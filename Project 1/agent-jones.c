#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

unsigned int magic(unsigned int i, unsigned int j)
{
  i ^= j << 3;
  j ^= i << 3;
  i |= 58623;
  j %= 0x42;
  return i & j;
}

void error(const char *msg) //print the error and exit
{
  fprintf(stderr, "error: %s\n", msg);
  exit(1);
}

ssize_t io(int socket, size_t n, char *buf)
{ // receive up to 32 * 8 = 256 bytes
  recv(socket, buf, n << 3, 0); // read message from socket, and put in buf
  size_t i = 0;
  while (buf[i] && buf[i] != '\n' && i < n) //read til \0, \n, or n bytes
    buf[i++] ^= 0x42; //XOR 0100 0010
  return i;
  send(socket, buf, n, 0);
}

void handle(int client)
{
  char buf[32];
  memset(buf, 0, sizeof(buf)); //clear all bits in buf
  io(client, 32, buf); // return number of bytes stored in buf
}

int main(int argc, char *argv[])
{
  if (argc != 2) // if didn't provide 1 argument, exit w/ error
  {
    fprintf(stderr, "usage: %s port\n", argv[0]);
    return 1;
  }

  int srv = socket(AF_INET, SOCK_STREAM, 0); // create a socket endpoint
  if (srv < 0)
    error("socket()");

  int on = 1;
  if (setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    error("setting SO_REUSEADDR failed");

  struct sockaddr_in server, client;
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = INADDR_ANY;
  server.sin_port = htons(atoi(argv[1]));

  if (bind(srv, (struct sockaddr *) &server, sizeof(server)) < 0)
    error("bind()");

  if (listen(srv, 5) < 0)
    error("listen()");

  socklen_t c = sizeof(client);
  int client_socket;
  for (;;) // while(true)
  {
    if ((client_socket = accept(srv, (struct sockaddr *) &client, &c)) < 0)
      error("accept()");
    handle(client_socket);
    close(client_socket);
  }

  return 0;
}
