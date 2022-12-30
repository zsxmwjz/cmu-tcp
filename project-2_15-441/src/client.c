/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements a simple CMU-TCP client. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmu_tcp.h"

void functionality(cmu_socket_t *sock) {
  uint8_t buf[9898];
  int read;
  FILE *fp;

  cmu_write(sock, "hi there", 8);
  cmu_write(sock, " https://www.youtube.com/watch?v=dQw4w9WgXcQ", 44);
  cmu_write(sock, " https://www.youtube.com/watch?v=Yb6dZ1IFlKc", 44);
  cmu_write(sock, " https://www.youtube.com/watch?v=xvFZjo5PgG0", 44);
  cmu_write(sock, " https://www.youtube.com/watch?v=8ybW48rKBME", 44);
  cmu_write(sock, " https://www.youtube.com/watch?v=xfr64zoBTAQ", 45);
  cmu_read(sock, buf, 200, NO_FLAG);

  cmu_write(sock, "hi there", 9);
  cmu_read(sock, buf, 200, NO_FLAG);
  printf("R: %s\n", buf);

  read = cmu_read(sock, buf, 200, NO_WAIT);
  printf("Read: %d\n", read);

  fp = fopen("/vagrant/project-2_15-441/src/cmu_tcp.c", "rb");
  read = 1;
  while (read > 0) {
    read = fread(buf, 1, 2000, fp);
    if (read > 0) {
      cmu_write(sock, buf, read);
    }
  }
}

void test_sendArray(cmu_socket_t *sock) {
  uint8_t arr[MAX_NETWORK_BUFFER];
  for(int i = 0; i < MAX_NETWORK_BUFFER; i++) arr[i] = i & 0xff;
  int round = 10;
  for(int i = 0; i < round; i++) {
    cmu_write(sock, arr, MAX_NETWORK_BUFFER * sizeof(uint8_t));
    printf("round %d: send 0 - %d\n",i,MAX_NETWORK_BUFFER-1);
  }
}

void test_totalTime(cmu_socket_t * sock) {
  uint8_t arr[MAX_NETWORK_BUFFER];
  for(int i = 0; i < MAX_NETWORK_BUFFER; i++) arr[i] = i & 0xff;
  int size = 32768;
  while(size > 0) {
    int length = (size < MAX_NETWORK_BUFFER) ? size : MAX_NETWORK_BUFFER;
    cmu_write(sock,arr,length);
    size -= length;
  }
}

int main() {
  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);

  if (cmu_socket(&socket, TCP_INITIATOR, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  // functionality(&socket);
  test_sendArray(&socket);
  // test_totalTime(&socket);

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
