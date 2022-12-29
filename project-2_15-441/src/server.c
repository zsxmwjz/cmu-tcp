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
 * This file implements a simple CMU-TCP server. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cmu_tcp.h"

#define BUF_SIZE 10000

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t *sock) {
  uint8_t buf[BUF_SIZE];
  FILE *fp;
  int n;

  n = cmu_read(sock, buf, BUF_SIZE, NO_FLAG);
  printf("R: %s\n", buf);
  printf("N: %d\n", n);
  cmu_write(sock, "hi there", 9);
  n = cmu_read(sock, buf, 200, NO_FLAG);
  printf("R: %s\n", buf);
  printf("N: %d\n", n);
  cmu_write(sock, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", 44);

  sleep(1);
  n = cmu_read(sock, buf, BUF_SIZE, NO_FLAG);
  printf("N: %d\n", n);
  fp = fopen("/tmp/file.c", "w");
  fwrite(buf, 1, n, fp);
  fclose(fp);
}

void test_sendArray(cmu_socket_t *sock) {
  int round = 10;
  for(int i = 0; i < round; i++) {
    sleep(3);
    uint8_t arr[MAX_NETWORK_BUFFER] = {0};
    int n = cmu_read(sock, arr, MAX_NETWORK_BUFFER * sizeof(uint8_t), NO_FLAG);
    printf("length: %d\n", n);
    int index;
    for(index = 0; index < MAX_NETWORK_BUFFER; index++) {
      if(arr[index] != (index & 0xff)) break;
    }
    if(index < MAX_NETWORK_BUFFER) {
      printf("wrong at %d, expected %d, got %d\n",index,index&0xff,arr[index]);
      return;
    }
  }
  printf("test_sendArray PASS\n");
}

void test_send_bigFile(cmu_socket_t *sock) {
  int sum = 0;
  FILE* fp = fopen("/tmp/bigFile.txt", "wb");
  while(sum < 10 * MAX_NETWORK_BUFFER) {
    sleep(1);
    uint8_t arr[MAX_NETWORK_BUFFER] = {0};
    int n = cmu_read(sock, arr, MAX_NETWORK_BUFFER * sizeof(uint8_t), NO_WAIT);
    sum += n;
    if(n > 0) {
      printf("length: %d\n", n);
      fwrite(arr, 1, n, fp);
    }
  }
  int read = 1;
  uint8_t receive[MAX_NETWORK_BUFFER] = {0};
  while (read > 0) {
    read = fread(receive, 1, MAX_NETWORK_BUFFER, fp);
    int index;
    for(index = 0; index < read; index++) {
      if(receive[index] != (index & 0xff)) break;
    }
    if(index < read) {
      printf("wrong at %d, expected %d, got %d\n",index,index&0xff,receive[index]);
      fclose(fp);
      return;
    }
  }
  printf("test_send_bigFile PASS\n");
  fclose(fp);
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

  if (cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  // functionality(&socket);
  // test_sendArray(&socket);
  test_send_bigFile(&socket);

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
