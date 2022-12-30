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
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

typedef enum {
  CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT,
  LISTEN, CLOSE_WAIT, LAST_ACK
} state_t;

state_t state = CLOSED;
int RTO = 1000;
int EstimatedRTT=WINDOW_INITIAL_RTT;
int DevRTT=0;
int num_received_fin = 0;

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0) {
  }
  result = after(sock->window.last_ack_received, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

/**
 * Send ACK packet of pkt.
 * 
 * @param sock The socket used for sending ack.
 * @param flag SYNC, FIN or 0
 */
void send_ack(cmu_socket_t *sock, uint8_t flag) {
  socklen_t conn_len = sizeof(sock->conn);
  uint32_t seq = sock->window.last_ack_received;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint8_t flags = ACK_FLAG_MASK | flag;
  uint16_t adv_window = 1;
  uint8_t *response_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, response_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  free(response_packet);
}

/**
 * TCP initiator sends an SYN packet.
 * 
 * @param sock TCP initiator
 */
void send_syn(cmu_socket_t *sock) {
  socklen_t conn_len = sizeof(sock->conn);
  uint32_t seq = sock->window.last_ack_received;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = 0;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint8_t flags = SYN_FLAG_MASK;
  uint16_t adv_window = 1;
  uint8_t *syn_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, syn_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  free(syn_packet);
}

/**
 * Send an FIN packet. Called when the TCP connection is closed.
 * 
 * @param sock The socket used for sending fin.
 */
void send_fin(cmu_socket_t *sock) {
  socklen_t conn_len = sizeof(sock->conn);
  uint32_t seq = sock->window.last_ack_received;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = 0;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint8_t flags = FIN_FLAG_MASK;
  uint16_t adv_window = 1;
  uint8_t *fin_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, fin_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  free(fin_packet);
}

uint32_t check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags);
/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  // 捎带：TCP中，一个报文在附带有效载荷（传输数据）的同时作为ACK。即使是单纯的ACK，也要设置seq。
  switch (flags) {
    case SYN_FLAG_MASK: {
      if(state == LISTEN && get_payload_len(pkt) == 0) {
        sock->window.next_seq_expected = get_seq(hdr) + 1;
        while(1){
          uint32_t synack_seq = sock->window.last_ack_received;
          send_ack(sock, SYN_FLAG_MASK);
          pthread_mutex_unlock(&(sock->recv_lock));
          check_for_data(sock,TIMEOUT); // 等待对SYNACK报文的确认
          if(has_been_acked(sock,synack_seq)) {
            break;
          }
        }
      }
      break;
    }
    case SYN_FLAG_MASK | ACK_FLAG_MASK: {
      if(sock->type == TCP_INITIATOR && (state == CLOSED || state == ESTABLISHED)) {
        uint32_t ack = get_ack(hdr);
        if(ack == sock->window.last_ack_received + 1 && get_payload_len(pkt) == 0) {
          sock->window.last_ack_received = ack;
          sock->window.next_seq_expected = get_seq(hdr) + 1;
          send_ack(sock,0);
        }
        state = ESTABLISHED;
      }
      break;
    }
    case ACK_FLAG_MASK: {
      if((sock->type == TCP_INITIATOR && state == ESTABLISHED)
        || (sock->type == TCP_LISTENER && state == ESTABLISHED)) {
        uint32_t ack = get_ack(hdr);
        if (after(ack, sock->window.last_ack_received)) {
          sock->window.last_ack_received = ack;
        }
      }
      else if(sock->type == TCP_LISTENER && state == LISTEN) {
        uint32_t seq = get_seq(hdr), ack = get_ack(hdr);
        if(seq == sock->window.next_seq_expected && ack == sock->window.last_ack_received + 1) {
          sock->window.last_ack_received = ack;
          state = ESTABLISHED;
        }
      }
      break;
    }
    case FIN_FLAG_MASK: {
      if(state == ESTABLISHED || state == LAST_ACK || state == FIN_WAIT_1
        || state == FIN_WAIT_2 || state == TIME_WAIT) {
          if(get_seq(hdr) == sock->window.next_seq_expected) {
            sock->window.next_seq_expected++;
            send_ack(sock,FIN_FLAG_MASK);
            num_received_fin++;
            if(state == ESTABLISHED) {
              state = CLOSE_WAIT;
              while(pthread_mutex_lock(&sock->death_lock)) {
              }
              sock->dying = 1;
              pthread_mutex_unlock(&sock->death_lock);
            }
          } else if(get_seq(hdr) < sock->window.next_seq_expected) {
            send_ack(sock,FIN_FLAG_MASK);
          } else send_ack(sock,0);
      }
      break;
    }
    case FIN_FLAG_MASK | ACK_FLAG_MASK: {
      if(state == FIN_WAIT_1 || state == LAST_ACK) {
        uint32_t ack = get_ack(hdr);
        if(ack == sock->window.last_ack_received + 1 && get_payload_len(pkt) == 0) {
          sock->window.last_ack_received = ack;
        }
      }
      break;
    }
    default: {
      if((sock->type == TCP_INITIATOR && state == ESTABLISHED)
        || (sock->type == TCP_LISTENER && state == ESTABLISHED)
        || state == FIN_WAIT_2) {

        uint32_t seq = get_seq(hdr);

        if (seq == sock->window.next_seq_expected) {
          sock->window.next_seq_expected = seq + get_payload_len(pkt);
          uint16_t payload_len = get_payload_len(pkt);
          uint8_t *payload = get_payload(pkt);

          // Make sure there is enough space in the buffer to store the payload.
          if(state != FIN_WAIT_2) {
            sock->received_buf =
                realloc(sock->received_buf, sock->received_len + payload_len);
            memcpy(sock->received_buf + sock->received_len, payload, payload_len);
            sock->received_len += payload_len;
          }
        }
  
        send_ack(sock,0);
      }
    }
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 * @return Plen of received packet.
 */
uint32_t check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after 3 seconds.
      int i=poll(&ack_fd, 1, RTO);
      if (i <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return plen;
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          free(msg);
          break;
        }
      }

      data_offset += payload_len;
    }
  }
}

/**
 * Perform the TCP three-way handshake.
 * 
 * @param sock The socket to perform handshake.
 */
void handshake(cmu_socket_t *sock) {
  switch (sock->type) {
    case TCP_INITIATOR: {
      while(1) {
        uint32_t sync_seq = sock->window.last_ack_received;
        send_syn(sock);
        check_for_data(sock,TIMEOUT); // 等待SYNACK报文
        if(has_been_acked(sock,sync_seq)) {
          break;
        }
      }
      state = ESTABLISHED;
      break;
    }
    case TCP_LISTENER: {
      state = LISTEN;
      while(state == LISTEN) {
        check_for_data(sock,NO_FLAG); // 等待SYN报文
      }
      break;
    }
    default : {}
  }
}

/**
 * Perform the TCP four-way wavehand.
 * 
 * @param sock The socket to perform wavehand.
 */
void wavehand(cmu_socket_t *sock) {
  int should_wait = 0;
  if(num_received_fin > 0) state = LAST_ACK;
  else {
    state = FIN_WAIT_1;
    should_wait = 1;
  }
  while(1) {
    uint32_t fin_seq = sock->window.last_ack_received;
    send_fin(sock);
    check_for_data(sock,TIMEOUT); // 等待FINACK报文
    if(has_been_acked(sock,fin_seq)) {
      break;
    }
  }
  if(num_received_fin == 0 || should_wait) {
    state = FIN_WAIT_2;
    while(num_received_fin == 0) {
      check_for_data(sock,NO_FLAG); // 等待对方的FIN报文到达
    }
    state = TIME_WAIT;
    do {
      RTO = 3000; // 30s内没收到重发的FIN报文，认为对方已收到FINACK
    } while(check_for_data(sock,TIMEOUT));
  }
  state = CLOSED;
}

/**
 * Breaks up the data into packets and sends packets in window.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void window_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  const int WINDOW_SIZE=WINDOW_INITIAL_WINDOW_SIZE/MSS;

  struct timeval start_time[WINDOW_SIZE], end_time;

  uint8_t *msg[WINDOW_SIZE];
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int created[WINDOW_SIZE];
  int sended[WINDOW_SIZE];
  uint32_t seq[WINDOW_SIZE];
  for(int i=0;i<WINDOW_SIZE;i++){
    created[i]=0;
    sended[i]=0;
    seq[i] = sock->window.last_ack_received;
  }

  int current_num=0;
  int end=0;

  int sockfd = sock->socket;

  uint16_t last_payload_len = 0;

  if (buf_len > 0) {
    while (end==0) {
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);

      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;
      uint32_t ack = seq[current_num%WINDOW_SIZE]+payload_len;

      int ack_wrong=0;
      if(created[current_num%WINDOW_SIZE]==0&&current_num!=0){
        seq[current_num%WINDOW_SIZE] = seq[(current_num-1)%WINDOW_SIZE]+last_payload_len;
      }

      if(created[current_num%WINDOW_SIZE]==0&&buf_len!=0){
        msg[current_num%WINDOW_SIZE] = create_packet(src, dst, seq[current_num%WINDOW_SIZE], ack, 
                                                    hlen, plen, flags, adv_window,
                                                    ext_len, ext_data, payload, payload_len);
        buf_len -= payload_len;
        data_offset += payload_len;
        created[current_num%WINDOW_SIZE]=1;
        last_payload_len=payload_len;
        //printf("newpkt:%d\n",current_num);
      }
      
      if(created[current_num%WINDOW_SIZE]==1){
        sendto(sockfd, msg[current_num % WINDOW_SIZE], plen, 0, (struct sockaddr *)&(sock->conn),
              conn_len);
        sended[current_num%WINDOW_SIZE]=1;     
        gettimeofday( &start_time[current_num%WINDOW_SIZE], NULL );
      }

      while(created[(current_num+1)%WINDOW_SIZE]==1&&sended[(current_num+1)%WINDOW_SIZE]==1){
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq[(current_num+1)%WINDOW_SIZE])) {
          created[(current_num+1)%WINDOW_SIZE]=0;
          sended[(current_num+1)%WINDOW_SIZE]=0;
          free(msg[(current_num+1)%WINDOW_SIZE]);
          //printf("acked:%d\n",(current_num+1));
          gettimeofday( &end_time, NULL );
          int timeuse = 1000 * ( end_time.tv_sec - start_time[(current_num+1)%WINDOW_SIZE].tv_sec ) + (end_time.tv_usec - start_time[(current_num+1)%WINDOW_SIZE].tv_usec)/1000;
          EstimatedRTT=0.875*EstimatedRTT+0.125*timeuse;//RTT估计
          DevRTT=0.75*DevRTT-0.25*MIN(EstimatedRTT-timeuse,timeuse-EstimatedRTT);
          RTO=EstimatedRTT+4*DevRTT;
          break;
        }
        else{
          if(ack_wrong<=WINDOW_SIZE-1){
            ack_wrong++;
            continue;
          }
          RTO *= 2;
          for(int i=0;i<WINDOW_SIZE;i++){
            sended[i]=0;
          }
          break;
        }
      }

      current_num++;
      
      if(buf_len==0){
        end=1;
        for(int i=0;i<WINDOW_SIZE;i++){
          if(created[(current_num+i)%WINDOW_SIZE]==1){
            while (1) {
              check_for_data(sock, TIMEOUT);
              if (has_been_acked(sock, seq[(current_num+i)%WINDOW_SIZE])) {
                free(msg[(current_num+i)%WINDOW_SIZE]);
                break;
              }
              sendto(sockfd, msg[(current_num+i)%WINDOW_SIZE], plen, 0, (struct sockaddr *)&(sock->conn),
                    conn_len);
            }
          }
        }
        //printf("end:%d,addr:%d\n",end,current_num);
      }

    }
  }
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  handshake(sock);

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      pthread_cond_signal(&(sock->wait_cond_write));
      //single_send(sock, data, buf_len);
      window_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond_read));
    }
  }

  wavehand(sock);

  pthread_exit(NULL);
  return NULL;
}
