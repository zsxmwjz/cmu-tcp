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

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

typedef enum {
  CLOSED, SYN_SENT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT,
  LISTEN, CLOSE_WAIT, LAST_ACK
} state_t;

state_t state = CLOSED;
int RTO = 1000;
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
 * @param pkt The pkt which will be acked.
 * @param flag SYNC, ACK, FIN or 0
 */
void send_ack(cmu_socket_t *sock, uint8_t *pkt, uint8_t flag) {
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
  uint32_t ack = get_seq((cmu_tcp_header_t*)pkt) + get_payload_len(pkt);
  if(flag == SYN_FLAG_MASK || flag == ACK_FLAG_MASK || flag == FIN_FLAG_MASK) ack++;
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
  uint8_t *syn_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                    ext_len, ext_data, payload, payload_len);

  sendto(sock->socket, syn_packet, plen, 0,
          (struct sockaddr *)&(sock->conn), conn_len);
  free(syn_packet);
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
          send_ack(sock,pkt,SYN_FLAG_MASK);
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
          send_ack(sock,pkt,ACK_FLAG_MASK);
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
        send_ack(sock,pkt,FIN_FLAG_MASK);
        num_received_fin++;
        if(state == ESTABLISHED) {
          state = CLOSE_WAIT;
          while(pthread_mutex_lock(&sock->death_lock)) {
          }
          sock->dying = 1;
          pthread_mutex_unlock(&sock->death_lock);
        }
      }
      break;
    }
    case FIN_FLAG_MASK | ACK_FLAG_MASK: {
      if(state == FIN_WAIT_1 || state == LAST_ACK) {
        uint32_t ack = get_ack(hdr);
        if(ack == sock->window.last_ack_received + 1 && get_payload_len(pkt) == 0) {
          sock->window.last_ack_received = ack;
          sock->window.next_seq_expected = get_seq(hdr) + 1;
        }
      }
      break;
    }
    default: {
      if((sock->type == TCP_INITIATOR && state == ESTABLISHED)
        || (sock->type == TCP_LISTENER && state == ESTABLISHED)
        || state == FIN_WAIT_2) {
        send_ack(sock,pkt,0);

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
      if (poll(&ack_fd, 1, RTO) <= 0) {
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
      RTO = 30000; // 30s内没收到重发的FIN报文，认为对方已收到FINACK
    } while(check_for_data(sock,TIMEOUT));
  }
  state = CLOSED;
}

/**
 * Breaks up the data into packets and sends two packets at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void window_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg[WINDOW_SIZE];
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int received[WINDOW_SIZE];
  for(int i=0;i<WINDOW_SIZE;i++){
    received[i]=0;
  }

  int current_num=0;
  int end=0;

  int sockfd = sock->socket;

  if (buf_len > 0) {
    while (end==0) {
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq[WINDOW_SIZE];
      seq[0] = sock->window.last_ack_received;
      uint32_t ack[WINDOW_SIZE];
      ack[0] = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;
      
      int i=current_num;
      do{
        if(received[i % WINDOW_SIZE]==1 && buf_len !=0){
          msg[i] = create_packet(src, dst, seq[i-current_num], ack[i-current_num], hlen, plen, flags, adv_window,
                                ext_len, ext_data, payload, payload_len);
          buf_len -= payload_len;
          payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);
          plen = hlen + payload_len;
          if(i-current_num+1<WINDOW_SIZE){
            seq[i-current_num+1]=seq[i-current_num]+payload_len;
            ack[i-current_num+1]=ack[i-current_num]+payload_len;
          }
          received[i % WINDOW_SIZE]=0;
        }
        else{
          break;
        }
        i++;
      }while(i % WINDOW_SIZE !=current_num);
      
      i=current_num;
      do{
        if(received[i % WINDOW_SIZE]==1)break;
        sendto(sockfd, msg[i % WINDOW_SIZE], plen, 0, (struct sockaddr *)&(sock->conn),
              conn_len);
        i++;
      }while(i % WINDOW_SIZE !=current_num);

      i=current_num;
      do{
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq[i-current_num])) {
          data_offset += payload_len;
          received[i % WINDOW_SIZE]=1;
        }
        else{
          current_num=i;
          break;
        }
        i++;
      }while(i % WINDOW_SIZE !=current_num);

      if(buf_len==0){
        end=1;
        for(i=0;i<WINDOW_SIZE;i++){
          if(received[i]==0){
            end=0;
          }
        }
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
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  wavehand(sock);

  pthread_exit(NULL);
  return NULL;
}
