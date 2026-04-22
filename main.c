#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <netinet/in.h>

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>


#define packed      __attribute__((packed))
#define unused(__x) (void) (__x)

#define moe_cast(__t, __p, __o) ((__t*) ((uint8_t*) (__p) + (__o)))
#define moe_assert(__cond)                                                              \
  do {                                                                                  \
    if (!(__cond)) {                                                                    \
      fprintf(stderr, "Assertion failed: %s, at %s:%d\n", #__cond, __FILE__, __LINE__); \
      exit(EXIT_FAILURE);                                                               \
    }                                                                                   \
  } while (0)

#define MOE_ERRORS_XXX()                                  \
  MOE_ERROR(1, CHKSUM, "Checksum mismatch")               \
  MOE_ERROR(2, INVPKT, "Malformed packet")                \
  MOE_ERROR(3, UPROTO, "Protocol unsupported")            \
                                                          \
  MOE_ERROR(4, NOMEM, "Memory allocation failed")         \
  MOE_ERROR(5, BUFOVF, "Buffer limit reached")            \
                                                          \
  MOE_ERROR(6, AGAIN, "Resource temporarily unavailable") \
  MOE_ERROR(7, INVST, "Invalid sequence of state")        \
  MOE_ERROR(8, CONREF, "Connection refused")              \
  MOE_ERROR(9, CONRST, "Connection reset by peer")        \
                                                          \
  MOE_ERROR(10, PKTDROP, "Packet silently dropped")       \
  MOE_ERROR(11, TIMEOUT, "Operation timed out")           \
                                                          \
  MOE_ERROR(12, UNIMPL, "Feature not implemented")

#define MSL_TIMEOUT 2000// this is for testing
#define MSS_SIZE    1460

#define INITIAL_RETRANSMIT_TIMEOUT 1000// ms
#define INITIAL_CWND_BYTES         (2 * MSS_SIZE)
#define MIN_SSTHRESH_BYTES         (2 * MSS_SIZE)

enum moe_error_t {
#define MOE_ERROR(code, name, msg) ME##name = code,
  MOE_ERRORS_XXX()
#undef MOE_ERROR
};

const char* moe_error_str(enum moe_error_t err) {
  switch (-err) {
#define MOE_ERROR(code, name, msg) \
  case ME##name:                   \
    return msg;
    MOE_ERRORS_XXX()
#undef MOE_ERROR
    default:
      return "Unknown error";
  }
}

#define LOG_DEBUG 0
#define LOG_INFO  1
#define LOG_WARN  2
#define LOG_ERR   3
#define LOG_MAX   4

#define LOG_LEVEL LOG_DEBUG

void moe_trace(int lvl, const char* fmt, ...) {
  if (lvl < LOG_LEVEL) return;

  switch (lvl) {
    case LOG_DEBUG:
      printf("[DBUG] ");
      break;
    case LOG_INFO:
      printf("[INFO] ");
      break;
    case LOG_WARN:
      printf("[WARN] ");
      break;
    case LOG_ERR:
      printf("[ERRO] ");
      break;
    default:
      printf("[????] ");
      break;
  }

  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}


int moe_tun_alloc(const char* dev) {
  struct ifreq ifr;
  int fd, err;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) return fd;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((err = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
    close(fd);
    return err;
  }

  return fd;
}

int moe_tun_configure(const char* dev, const char* ipaddr) {
  int sockfd;
  struct ifreq ifr;
  struct sockaddr_in* addr;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return -1;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  addr = (struct sockaddr_in*) &ifr.ifr_addr;
  addr->sin_family = AF_INET;
  inet_pton(AF_INET, ipaddr, &addr->sin_addr);
  if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) goto error;

  inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);
  if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) goto error;

  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) goto error;
  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
  if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) goto error;

  close(sockfd);
  return 0;

error:
  close(sockfd);
  return -1;
}

struct moe_iphdr {
  uint8_t ihl     : 4;
  uint8_t version : 4;

  uint8_t tos;

  uint16_t length;

  uint16_t identification;

  uint16_t frags;

  uint8_t ttl;
  uint8_t protocol;

  uint16_t checksum;

  uint32_t src_addr;
  uint32_t dst_addr;

  uint8_t rest[];
} packed;

struct moe_icmphdr {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;

  // todo: rest of ICMP ignored
  uint8_t rest[];
} packed;

struct moe_tcphdr {
  uint16_t src_port;
  uint16_t dst_port;

  uint32_t seq_num;
  uint32_t ack_num;

  uint8_t reserved    : 4;
  uint8_t data_offset : 4;

  // CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
  uint8_t flags;

  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;

  uint8_t rest[];
} packed;

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

uint16_t moe__checksum(void* data, size_t len) {
  uint16_t* buf = (uint16_t*) data;
  uint32_t sum = 0;

  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }
  if (len == 1) {
    sum += *(uint8_t*) buf;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t) ~sum;
}

bool moe__checksum_valid(void* data, size_t len) {
  uint16_t res = moe__checksum(data, len);
  return res == 0;
}

int moe__checksum_many(void** datas, size_t* lens, size_t count, uint16_t* out_checksum) {
  static uint8_t inline_buf[1600];

  size_t total_len = 0;
  for (size_t i = 0; i < count; i++) {
    total_len += lens[i];
  }

  uint8_t* buf;
  if (total_len > sizeof(inline_buf)) {
    buf = malloc(total_len);
    if (!buf) {
      return -MENOMEM;
    }
  } else {
    buf = inline_buf;
  }

  size_t offset = 0;
  for (size_t i = 0; i < count; i++) {
    memcpy(buf + offset, datas[i], lens[i]);
    offset += lens[i];
  }

  *out_checksum = moe__checksum(buf, total_len);
  if (buf != inline_buf) {
    free(buf);
  }

  return 0;
}

int moe__checksum_pseudo(struct moe_iphdr* ip_hdr, void* tcp_hdr, size_t tcp_len, uint16_t* out_checksum) {
  struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
  } packed pseudo_hdr;

  pseudo_hdr.src_addr = ip_hdr->src_addr;
  pseudo_hdr.dst_addr = ip_hdr->dst_addr;
  pseudo_hdr.zero = 0;
  pseudo_hdr.protocol = ip_hdr->protocol;
  pseudo_hdr.tcp_len = htons(tcp_len);

  void* datas[] = {&pseudo_hdr, tcp_hdr};
  size_t lens[] = {sizeof(pseudo_hdr), tcp_len};

  return moe__checksum_many(datas, lens, 2, out_checksum);
}

bool moe__checksum_ip_tcp_valid(struct moe_iphdr* ip_hdr) {
  if (ip_hdr->protocol != IPPROTO_TCP) {
    moe_trace(LOG_WARN, "Expected TCP protocol to be verified but got %d\n", ip_hdr->protocol);
    return false;
  }

  if (!moe__checksum_valid(ip_hdr, ip_hdr->ihl * sizeof(uint32_t))) {
    return false;
  }

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, ip_hdr, ip_hdr->ihl * sizeof(uint32_t));
  size_t tcp_len = ntohs(ip_hdr->length) - ip_hdr->ihl * sizeof(uint32_t);
  uint16_t checksum;
  if (moe__checksum_pseudo(ip_hdr, tcp_hdr, tcp_len, &checksum) < 0) {
    return false;
  }

  return checksum == 0;
}

static uint64_t moe__time_ms() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

static int moe__tcp_validate_packet(struct moe_iphdr* hdr, size_t pkt_size) {
  const size_t ip_hdr_min_len = sizeof(uint32_t) * 5;
  const size_t tcp_hdr_min_len = sizeof(uint32_t) * 5;

  if (pkt_size < ip_hdr_min_len) {
    return -MEINVPKT;
  }

  size_t ip_hdr_len = hdr->ihl * sizeof(uint32_t);
  if (ip_hdr_len < ip_hdr_min_len || ip_hdr_len > pkt_size) {
    return -MEINVPKT;
  }

  uint16_t ip_total_len = ntohs(hdr->length);
  if (ip_total_len < ip_hdr_len + tcp_hdr_min_len || ip_total_len > pkt_size) {
    return -MEINVPKT;
  }

  if (hdr->protocol != IPPROTO_TCP) {
    return -MEUPROTO;
  }

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, ip_hdr_len);
  size_t tcp_hdr_len = tcp_hdr->data_offset * sizeof(uint32_t);
  if (tcp_hdr_len < tcp_hdr_min_len || ip_hdr_len + tcp_hdr_len > ip_total_len) {
    return -MEINVPKT;
  }

  if (!moe__checksum_ip_tcp_valid(hdr)) {
    return -MECHKSUM;
  }

  return 0;
}

void moe__split_ip_octets(uint32_t ip, uint8_t* octets) {
  octets[0] = (ip >> 24) & 0xFF;
  octets[1] = (ip >> 16) & 0xFF;
  octets[2] = (ip >> 8) & 0xFF;
  octets[3] = ip & 0xFF;
}

int moe__stringify_ip(uint32_t ip, char* buf, size_t buf_size) {
  uint8_t octets[4];
  moe__split_ip_octets(ip, octets);
  return snprintf(buf, buf_size, "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]);
}

int moe__handle_icmp(int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  // IHL is number of 32b words in header
  struct moe_icmphdr* icmp_hdr = moe_cast(struct moe_icmphdr, hdr, hdr->ihl * sizeof(uint32_t));

  if (!moe__checksum_valid(icmp_hdr, pkt_size - hdr->ihl * sizeof(uint32_t))) {
    return -MECHKSUM;
  }

  if (icmp_hdr->type == 8) {
    // echo request
    uint8_t reply[pkt_size];
    memcpy(reply, hdr, pkt_size);

    struct moe_iphdr* reply_hdr = moe_cast(struct moe_iphdr, reply, 0);
    uint32_t tmp_addr = reply_hdr->src_addr;
    reply_hdr->src_addr = reply_hdr->dst_addr;
    reply_hdr->dst_addr = tmp_addr;

    reply_hdr->checksum = 0;
    reply_hdr->checksum = moe__checksum(reply_hdr, reply_hdr->ihl * sizeof(uint32_t));

    // echo reply
    struct moe_icmphdr* reply_icmp_hdr = moe_cast(struct moe_icmphdr, reply, reply_hdr->ihl * sizeof(uint32_t));
    reply_icmp_hdr->type = 0;

    // reset checksum before recalculating
    reply_icmp_hdr->checksum = 0;
    reply_icmp_hdr->checksum = moe__checksum(reply_icmp_hdr, pkt_size - reply_hdr->ihl * sizeof(uint32_t));

    if (write(dev_fd, reply, pkt_size) < 0) {
      return -MEINVPKT;
    }
  } else {
    return -MEUPROTO;
  }

  return 0;
}

enum moe_tcp_state_t {
  TCP_CLOSED = 0,
  TCP_LISTEN,
  TCP_SYN_SENT,
  TCP_SYN_RECEIVED,
  TCP_ESTABLISHED,
  TCP_FIN_WAIT_1,
  TCP_FIN_WAIT_2,
  TCP_CLOSE_WAIT,
  TCP_CLOSING,
  TCP_LAST_ACK,
  TCP_TIME_WAIT
};

#define DEFAULT_BUF_SIZE 32768
struct moe_tcp_sock {
  int sock_fd;

  enum moe_tcp_state_t state;

  // all in MSB-first network byte order
  uint32_t local_addr;
  uint16_t local_port;
  uint32_t remote_addr;
  uint16_t remote_port;

  uint32_t send_unack;
  uint32_t send_next;
  uint32_t recv_next;
  uint32_t send_buf_seq;

  uint32_t peer_window;
  uint32_t cwnd_bytes;
  uint32_t ssthresh_bytes;
  uint32_t dup_ack_count;

  size_t recv_buf_size;
  size_t send_buf_size;

  uint64_t timeout_dur;

  uint64_t close_time;     // for TIME_WAIT state
  uint64_t retransmit_time;// for retransmission timeout

  struct moe_tcp_sock* next;
  struct moe_tcp_sock* pending_next;

  uint8_t recv_buf[DEFAULT_BUF_SIZE];
  uint8_t send_buf[DEFAULT_BUF_SIZE];
};

// todo: recycle CLOSED sockets
struct moe_tcp_sock* moe__global_tcp_sock_list = NULL;

int moe_tcp_lib_init();
int moe_tcp_update(struct moe_iphdr* hdr, size_t pkt_size);
int moe_tcp_tick();
void moe_tcp_lib_cleanup();

int moe_tcp_sock_init(struct moe_tcp_sock** psock, int sock_fd);
int moe_tcp_sock_close(struct moe_tcp_sock* sock);
int moe_tcp_sock_send(struct moe_tcp_sock* sock, void* data, size_t len);
int moe_tcp_sock_recv(struct moe_tcp_sock* sock, void* buf, size_t len);
int moe_tcp_sock_connect(struct moe_tcp_sock* sock, const char* ip, uint16_t port);
int moe_tcp_sock_listen(struct moe_tcp_sock* sock, uint16_t port);
int moe_tcp_sock_accept(struct moe_tcp_sock* sock, struct moe_tcp_sock** out_sock);

static bool moe__tcp_seq_leq(uint32_t a, uint32_t b) {
  return (int32_t) (a - b) <= 0;
}

static bool moe__tcp_seq_lt(uint32_t a, uint32_t b) {
  return (int32_t) (a - b) < 0;
}

static bool moe__tcp_ack_in_window(uint32_t ack, uint32_t left, uint32_t right) {
  return moe__tcp_seq_leq(left, ack) && moe__tcp_seq_leq(ack, right);
}

static int moe__tcp_transmit(struct moe_tcp_sock* sock, void* data, size_t len, uint8_t flags, int dev_fd);

static uint16_t moe__tcp_advertised_window(const struct moe_tcp_sock* sock) {
  size_t free_space = sizeof(sock->recv_buf) - sock->recv_buf_size;
  if (free_space > UINT16_MAX) {
    free_space = UINT16_MAX;
  }
  return (uint16_t) free_space;
}

static size_t moe__tcp_send_allowance(const struct moe_tcp_sock* sock) {
  size_t inflight = sock->send_next - sock->send_unack;

  size_t cwnd_allowance = 0;
  if (sock->cwnd_bytes > inflight) {
    cwnd_allowance = sock->cwnd_bytes - inflight;
  }

  size_t peer_allowance = 0;
  if (sock->peer_window > inflight) {
    peer_allowance = sock->peer_window - inflight;
  }

  return cwnd_allowance < peer_allowance ? cwnd_allowance : peer_allowance;
}

static void moe__tcp_on_timeout(struct moe_tcp_sock* sock) {
  size_t half = sock->cwnd_bytes / 2;
  if (half < MIN_SSTHRESH_BYTES) {
    half = MIN_SSTHRESH_BYTES;
  }

  sock->ssthresh_bytes = half;
  sock->cwnd_bytes = INITIAL_CWND_BYTES;
  sock->dup_ack_count = 0;
}

static void moe__tcp_on_ack_advance(struct moe_tcp_sock* sock, size_t acked_len) {
  unused(acked_len);

  sock->dup_ack_count = 0;
  if (sock->cwnd_bytes < sock->ssthresh_bytes) {
    // slow start, exponential
    sock->cwnd_bytes += MSS_SIZE;
  } else {
    // congestion control, linear increase
    uint32_t increment = (MSS_SIZE * MSS_SIZE) / (sock->cwnd_bytes ? sock->cwnd_bytes : MSS_SIZE);
    if (increment == 0) {
      increment = 1;
    }
    sock->cwnd_bytes += increment;
  }
}

static int moe__tcp_fast_retransmit(struct moe_tcp_sock* sock, int dev_fd) {
  size_t unacked_len = sock->send_next - sock->send_unack;
  if (unacked_len == 0 || sock->send_buf_size == 0) {
    return 0;
  }

  size_t chunk_size = unacked_len < MSS_SIZE ? unacked_len : MSS_SIZE;
  if (moe__tcp_transmit(sock, sock->send_buf, chunk_size, TCP_FLAG_ACK, dev_fd) < 0) {
    return -MEINVPKT;
  }

  size_t half = sock->cwnd_bytes / 2;
  if (half < MIN_SSTHRESH_BYTES) {
    half = MIN_SSTHRESH_BYTES;
  }
  sock->ssthresh_bytes = half;
  sock->cwnd_bytes = sock->ssthresh_bytes;
  sock->dup_ack_count = 0;
  sock->timeout_dur = INITIAL_RETRANSMIT_TIMEOUT;
  sock->retransmit_time = moe__time_ms() + sock->timeout_dur;

  moe_trace(LOG_DEBUG, "Fast retransmit triggered, cwnd=%u, ssthresh=%u\n", sock->cwnd_bytes, sock->ssthresh_bytes);
  return 0;
}


// this does not increase send_next, caller should do that after sending data, if applicable (e.g. SYN, FIN)
static int moe__tcp_make_simple_response(const struct moe_tcp_sock* sock, uint8_t flags, int dev_fd) {
  uint8_t reply[40];
  memset(reply, 0, sizeof(reply));
  struct moe_iphdr* reply_hdr = moe_cast(struct moe_iphdr, reply, 0);
  reply_hdr->version = 4;
  reply_hdr->ihl = sizeof(struct moe_iphdr) / 4;
  reply_hdr->length = htons(sizeof(struct moe_iphdr) + sizeof(struct moe_tcphdr));
  reply_hdr->ttl = 64;
  reply_hdr->protocol = IPPROTO_TCP;
  reply_hdr->src_addr = sock->local_addr;
  reply_hdr->dst_addr = sock->remote_addr;
  reply_hdr->checksum = 0;
  reply_hdr->checksum = moe__checksum(reply_hdr, reply_hdr->ihl * sizeof(uint32_t));

  struct moe_tcphdr* reply_tcp_hdr = moe_cast(struct moe_tcphdr, reply, reply_hdr->ihl * sizeof(uint32_t));
  reply_tcp_hdr->src_port = sock->local_port;
  reply_tcp_hdr->dst_port = sock->remote_port;
  reply_tcp_hdr->seq_num = htonl(sock->send_next);
  reply_tcp_hdr->ack_num = htonl(sock->recv_next);
  reply_tcp_hdr->data_offset = sizeof(struct moe_tcphdr) / 4;
  reply_tcp_hdr->flags = flags;
  reply_tcp_hdr->window = htons(moe__tcp_advertised_window(sock));
  reply_tcp_hdr->checksum = 0;

  uint16_t reply_tcp_checksum;
  if (moe__checksum_pseudo(reply_hdr, reply_tcp_hdr, sizeof(struct moe_tcphdr), &reply_tcp_checksum) < 0) {
    return -MENOMEM;
  }
  reply_tcp_hdr->checksum = reply_tcp_checksum;
  if (write(dev_fd, reply, sizeof(reply)) < 0) {
    return -MEINVPKT;
  }

  return 0;
}

// this function does not increase send_next,
// caller should do that after sending data
static int moe__tcp_transmit(struct moe_tcp_sock* sock, void* data, size_t len, uint8_t flags, int dev_fd) {
  static uint8_t small_buf[1520];
  size_t total_size = sizeof(struct moe_iphdr) + sizeof(struct moe_tcphdr) + len;
  uint8_t* packet;
  if (total_size <= sizeof(small_buf)) {
    packet = small_buf;
  } else {
    packet = malloc(total_size);
    if (!packet) {
      return -MENOMEM;
    }
  }

  struct moe_iphdr* ip_hdr = moe_cast(struct moe_iphdr, packet, 0);
  ip_hdr->version = 4;
  ip_hdr->ihl = sizeof(struct moe_iphdr) / 4;
  ip_hdr->length = htons(total_size);
  ip_hdr->ttl = 64;
  ip_hdr->protocol = IPPROTO_TCP;
  ip_hdr->src_addr = sock->local_addr;
  ip_hdr->dst_addr = sock->remote_addr;
  ip_hdr->checksum = 0;
  ip_hdr->checksum = moe__checksum(ip_hdr, ip_hdr->ihl * sizeof(uint32_t));

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, packet, ip_hdr->ihl * sizeof(uint32_t));
  tcp_hdr->src_port = sock->local_port;
  tcp_hdr->dst_port = sock->remote_port;
  tcp_hdr->seq_num = htonl(sock->send_next);
  tcp_hdr->ack_num = htonl(sock->recv_next);
  tcp_hdr->data_offset = sizeof(struct moe_tcphdr) / 4;
  tcp_hdr->flags = flags;
  tcp_hdr->window = htons(moe__tcp_advertised_window(sock));
  tcp_hdr->checksum = 0;
  memcpy((uint8_t*) tcp_hdr + tcp_hdr->data_offset * sizeof(uint32_t), data, len);
  uint16_t tcp_checksum;
  if (moe__checksum_pseudo(ip_hdr, tcp_hdr, sizeof(struct moe_tcphdr) + len, &tcp_checksum) < 0) {
    if (packet != small_buf) {
      free(packet);
    }
    return -MENOMEM;
  }
  tcp_hdr->checksum = tcp_checksum;

  if (write(dev_fd, packet, total_size) < 0) {
    if (packet != small_buf) {
      free(packet);
    }
    return -MEINVPKT;
  }

  if (packet != small_buf) {
    free(packet);
  }

  return 0;
}

int moe_tcp_sock_init(struct moe_tcp_sock** psock, int sock_fd) {
  *psock = malloc(sizeof(struct moe_tcp_sock));
  if (!*psock) {
    return -MENOMEM;
  }

  struct moe_tcp_sock* sock = *psock;
  sock->sock_fd = sock_fd;
  sock->state = TCP_CLOSED;
  sock->local_addr = 0;
  sock->local_port = 0;
  sock->remote_addr = 0;
  sock->remote_port = 0;
  sock->send_unack = 0;
  sock->send_next = 0;
  sock->recv_next = 0;
  sock->send_buf_seq = 0;
  sock->peer_window = DEFAULT_BUF_SIZE;
  sock->cwnd_bytes = INITIAL_CWND_BYTES;
  sock->ssthresh_bytes = DEFAULT_BUF_SIZE;
  sock->dup_ack_count = 0;
  sock->recv_buf_size = 0;
  sock->send_buf_size = 0;
  sock->timeout_dur = INITIAL_RETRANSMIT_TIMEOUT;
  sock->close_time = 0;
  sock->retransmit_time = 0;
  sock->next = NULL;
  sock->pending_next = NULL;

  sock->next = moe__global_tcp_sock_list;
  moe__global_tcp_sock_list = sock;

  return 0;
}

int moe_tcp_sock_close(struct moe_tcp_sock* sock) {
  // actively close
  moe_trace(LOG_DEBUG, "Usr active close: state=%d\n", sock->state);

  if (sock->state == TCP_CLOSED) {
    return -MEINVST;
  }

  if (sock->state == TCP_LISTEN) {
    // just close it
    sock->state = TCP_CLOSED;
    return 0;
  }

  if (sock->state != TCP_ESTABLISHED && sock->state != TCP_CLOSE_WAIT) {
    // invalid state for active close
    return -MEINVST;
  }

  // send FIN, transition to FIN_WAIT_1
  // todo: handle if any unsent or unacknowledged data exists
  if (moe__tcp_make_simple_response(sock, TCP_FLAG_FIN | TCP_FLAG_ACK, sock->sock_fd) < 0) {
    return -MEINVPKT;
  }
  sock->send_next += 1;// FIN consumes one sequence number

  if (sock->state == TCP_ESTABLISHED) {
    sock->state = TCP_FIN_WAIT_1;
  } else if (sock->state == TCP_CLOSE_WAIT) {
    sock->state = TCP_LAST_ACK;
  }

  return 0;
}

int moe_tcp_sock_send(struct moe_tcp_sock* sock, void* data, size_t len) {
  moe_trace(LOG_DEBUG, "Usr send: len=%zu\n", len);

  // buffers data and send immediately

  if (sock->state != TCP_ESTABLISHED) {
    return -MEINVST;
  }

  if (sock->send_buf_size + len > sizeof(sock->send_buf)) {
    return -MEBUFOVF;
  }

  memcpy(sock->send_buf + sock->send_buf_size, data, len);
  sock->send_buf_size += len;

  // send immediately
  size_t sent_offset = sock->send_next - sock->send_buf_seq;
  if (sent_offset > sock->send_buf_size) {
    return -MEINVST;
  }

  ssize_t send_len = sock->send_buf_size - sent_offset;
  size_t allowance = moe__tcp_send_allowance(sock);
  if (allowance == 0) {
    return 0;
  }
  if ((size_t) send_len > allowance) {
    send_len = allowance;
  }

  while (send_len > 0) {
    size_t chunk_size = send_len < MSS_SIZE ? send_len : MSS_SIZE;
    int err = moe__tcp_transmit(sock, sock->send_buf + sent_offset, chunk_size, TCP_FLAG_ACK | TCP_FLAG_PSH, sock->sock_fd);

    if (err < 0) {
      return err;
    }
    sock->send_next += chunk_size;
    sent_offset += chunk_size;
    send_len -= chunk_size;
  }

  sock->timeout_dur = INITIAL_RETRANSMIT_TIMEOUT;// reset timeout duration
  sock->retransmit_time = moe__time_ms() + sock->timeout_dur;

  return 0;
}

int moe_tcp_sock_recv(struct moe_tcp_sock* sock, void* buf, size_t len) {
  // todo: this is suboptimal, use ring buffers instead
  if (sock->recv_buf_size == 0) {
    if (sock->state == TCP_CLOSE_WAIT || sock->state == TCP_LAST_ACK) {
      // connection is closing and no buffered data remains
      return 0;
    }

    // no data available
    return -MEAGAIN;
  }

  moe_trace(LOG_DEBUG, "Usr recv: requested len=%zu, available=%zu\n", len, sock->recv_buf_size);

  size_t to_copy = len < sock->recv_buf_size ? len : sock->recv_buf_size;
  memcpy(buf, sock->recv_buf, to_copy);

  // shift the remaining data to the front of the buffer
  memmove(sock->recv_buf, sock->recv_buf + to_copy, sock->recv_buf_size - to_copy);
  sock->recv_buf_size -= to_copy;

  return to_copy;
}

int moe_tcp_sock_connect(struct moe_tcp_sock* sock, const char* ip, uint16_t port) {
  // send SYN, transition to SYN_SENT
  if (moe__tcp_make_simple_response(sock, TCP_FLAG_SYN, sock->sock_fd) < 0) {
    return -MEINVPKT;
  }

  moe_trace(LOG_DEBUG, "Usr connect: ip=%s, port=%d\n", ip, port);

  sock->state = TCP_SYN_SENT;
  return 0;
}

int moe_tcp_sock_listen(struct moe_tcp_sock* sock, uint16_t port) {
  sock->state = TCP_LISTEN;
  sock->local_port = htons(port);
  return 0;
}

int moe_tcp_sock_accept(struct moe_tcp_sock* sock, struct moe_tcp_sock** out_sock) {
  if (sock->state != TCP_LISTEN) {
    // invalid state
    return -MEINVST;
  }

  if (!sock->pending_next) {
    // no pending connections
    return -MEAGAIN;
  }

  // accept the first pending connection
  struct moe_tcp_sock* prev_pending = NULL;
  struct moe_tcp_sock* pending_sock = sock->pending_next;
  while (pending_sock && pending_sock->state != TCP_ESTABLISHED) {
    prev_pending = pending_sock;
    pending_sock = pending_sock->pending_next;
  }

  if (!pending_sock) {
    // no pending connections in SYN_RECEIVED state
    return -MEAGAIN;
  }

  moe_trace(LOG_DEBUG, "Usr accept: state=%d\n", sock->state);

  *out_sock = pending_sock;
  if (prev_pending) {
    prev_pending->pending_next = pending_sock->pending_next;
  } else {
    sock->pending_next = pending_sock->pending_next;
  }
  pending_sock->pending_next = NULL;

  return 0;
}

static int moe__tcp_sock_handle_closed(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  // nothing special to do here

  unused(sock);
  unused(dev_fd);
  unused(hdr);
  unused(pkt_size);

  return 0;
}

static int moe__random_number() {
  // todo: better random number generator
  return rand();
}

static int moe__tcp_sock_handle_listen(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));

  // todo: check other flags, handle RST, ACK, etc properly
  if (tcp_hdr->flags & TCP_FLAG_SYN) {
    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received SYN from %s:%d\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    // SYN, create a new socket in SYN_RECEIVED state

    struct moe_tcp_sock* new_sock;

    // zero-init, mount to global list
    if (moe_tcp_sock_init(&new_sock, dev_fd) < 0) {
      return -MENOMEM;
    }

    new_sock->state = TCP_SYN_RECEIVED;
    new_sock->local_addr = hdr->dst_addr;
    new_sock->local_port = tcp_hdr->dst_port;
    new_sock->remote_addr = hdr->src_addr;
    new_sock->remote_port = tcp_hdr->src_port;
    new_sock->send_unack = moe__random_number();
    new_sock->send_next = new_sock->send_unack;
    new_sock->send_buf_seq = new_sock->send_unack;
    new_sock->peer_window = ntohs(tcp_hdr->window);
    if (new_sock->peer_window == 0) {
      new_sock->peer_window = 1;
    }
    new_sock->cwnd_bytes = INITIAL_CWND_BYTES;
    new_sock->ssthresh_bytes = DEFAULT_BUF_SIZE;
    new_sock->dup_ack_count = 0;
    new_sock->recv_next = ntohl(tcp_hdr->seq_num) + 1;

    if (moe__tcp_make_simple_response(new_sock, TCP_FLAG_SYN | TCP_FLAG_ACK, dev_fd) < 0) {
      free(new_sock);
      return -MEINVPKT;
    }

    new_sock->send_next += 1;// SYN consumes one sequence number
    new_sock->state = TCP_SYN_RECEIVED;

    new_sock->pending_next = sock->pending_next;
    sock->pending_next = new_sock;
  }

  return 0;
}

static int moe__tcp_sock_handle_established(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  size_t data_len = ntohs(hdr->length) - hdr->ihl * sizeof(uint32_t) - tcp_hdr->data_offset * sizeof(uint32_t);

  if (tcp_hdr->flags & TCP_FLAG_RST) {
    // Abort!!
    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received RST from %s:%d, connection aborted\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    sock->state = TCP_CLOSED;
    return -MECONRST;
  }

  if (data_len > 0) {
    if (sock->recv_next != ntohl(tcp_hdr->seq_num)) {
      // out-of-order packet, drop it before any ACK-side state mutation
      // todo: allow receiving out-of-order packets in window
      moe_trace(LOG_WARN, "Out-of-order packet, expected seq_num %u but got %u, dropping\n", sock->recv_next, ntohl(tcp_hdr->seq_num));
      return -MEPKTDROP;
    }

    if (sock->recv_buf_size + data_len > sizeof(sock->recv_buf)) {
      // overflow, drop the data before any ACK-side state mutation
      moe_trace(LOG_WARN, "Receive buffer overflow, dropping data\n");
      return -MEBUFOVF;
    }

    if (!(tcp_hdr->flags & TCP_FLAG_ACK)) {
      // in established state, payload-carrying segments must carry ACK
      moe_trace(LOG_WARN, "Received data segment without ACK flag, dropping\n");
      return -MEINVPKT;
    }
  }

  if (tcp_hdr->flags & TCP_FLAG_ACK) {
    sock->peer_window = ntohs(tcp_hdr->window);
    uint32_t incoming_ack = ntohl(tcp_hdr->ack_num);
    if (moe__tcp_seq_lt(incoming_ack, sock->send_unack)) {
      moe_trace(
        LOG_DEBUG, "Received stale ACK %u below SND.UNA %u, ignoring\n",
        incoming_ack,
        sock->send_unack);
    } else if (incoming_ack == sock->send_unack) {
      sock->dup_ack_count += 1;
      if (sock->dup_ack_count >= 3) {
        int fr_err = moe__tcp_fast_retransmit(sock, dev_fd);
        if (fr_err < 0) {
          return fr_err;
        }
      }
    } else if (moe__tcp_seq_lt(sock->send_next, incoming_ack)) {
      moe_trace(
        LOG_WARN, "Received ACK %u beyond SND.NXT %u, dropping\n",
        incoming_ack,
        sock->send_next);
      return -MEINVPKT;
    } else if (moe__tcp_ack_in_window(incoming_ack, sock->send_unack, sock->send_next)) {
      uint32_t acked_u32 = incoming_ack - sock->send_unack;
      if (acked_u32 > 0) {
        size_t acked_len = acked_u32;
        if (acked_len > sock->send_buf_size) {
          acked_len = sock->send_buf_size;
        }
        memmove(sock->send_buf, sock->send_buf + acked_len, sock->send_buf_size - acked_len);
        sock->send_buf_size -= acked_len;
        sock->send_unack = incoming_ack;
        sock->send_buf_seq = sock->send_unack;
        moe__tcp_on_ack_advance(sock, acked_len);
        sock->timeout_dur = INITIAL_RETRANSMIT_TIMEOUT;
        sock->retransmit_time = moe__time_ms() + sock->timeout_dur;
      }
    }
  }

  if (data_len > 0) {
    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received data from %s:%d, len=%zu, offset=%dB\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port),
      data_len,
      tcp_hdr->data_offset * sizeof(uint32_t));

    // todo: check if the data_len corresponds to the actual payload length

    memcpy(sock->recv_buf + sock->recv_buf_size, (uint8_t*) tcp_hdr + tcp_hdr->data_offset * sizeof(uint32_t), data_len);
    sock->recv_buf_size += data_len;
    sock->recv_next += data_len;

    // reset retransmission timer on valid progress/data
    sock->timeout_dur = INITIAL_RETRANSMIT_TIMEOUT;
    sock->retransmit_time = moe__time_ms() + sock->timeout_dur;

    return moe__tcp_make_simple_response(sock, TCP_FLAG_ACK, dev_fd);
  }

  return 0;
}

static int moe__tcp_sock_handle_syn_sent(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  if ((tcp_hdr->flags & TCP_FLAG_SYN) && (tcp_hdr->flags & TCP_FLAG_ACK)) {
    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received SYN-ACK from %s:%d\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    // send ACK, transition to ESTABLISHED
    sock->recv_next = ntohl(tcp_hdr->seq_num) + 1;
    if (moe__tcp_make_simple_response(sock, TCP_FLAG_ACK, dev_fd) < 0) {
      return -MEINVPKT;
    }

    sock->state = TCP_ESTABLISHED;

    return 0;
  }

  return 0;
}

static int moe__tcp_sock_handle_syn_received(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(dev_fd);
  unused(pkt_size);

  // todo: validation

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  if (tcp_hdr->flags & TCP_FLAG_ACK) {
    if (ntohl(tcp_hdr->ack_num) != sock->send_next) {
      moe_trace(LOG_WARN, "Received ACK with unexpected ack_num %u, expected %u\n", ntohl(tcp_hdr->ack_num), sock->send_next);
      return -MEINVPKT;
    }

    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received ACK from %s:%d, connection established\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    sock->recv_next = ntohl(tcp_hdr->seq_num);
    sock->state = TCP_ESTABLISHED;
  } else if (tcp_hdr->flags & TCP_FLAG_RST) {
    // return to LISTEN state
    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received RST from %s:%d, returning to LISTEN state\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    sock->state = TCP_LISTEN;
    return -MECONRST;
  }

  return 0;
}

// todo: in FIN_WAIT_* states, we can still receive data, ACKS, etc
static int moe__tcp_sock_handle_fin_wait_1(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(dev_fd);
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  if (tcp_hdr->flags & TCP_FLAG_ACK) {
    if (ntohl(tcp_hdr->ack_num) != sock->send_next) {
      moe_trace(LOG_WARN, "Received ACK with unexpected ack_num %u, expected %u\n", ntohl(tcp_hdr->ack_num), sock->send_next);
      return -MEINVPKT;
    }

    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received ACK for FIN from %s:%d\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    sock->state = TCP_FIN_WAIT_2;
  } else if (tcp_hdr->flags & TCP_FLAG_FIN) {
    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received FIN from %s:%d\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    // send ACK, transition to CLOSING
    if (moe__tcp_make_simple_response(sock, TCP_FLAG_ACK, dev_fd) < 0) {
      return -MEINVPKT;
    }
    sock->state = TCP_CLOSING;
  }

  return 0;
}

static int moe__tcp_sock_handle_fin_wait_2(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  if (tcp_hdr->flags & TCP_FLAG_FIN) {
    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received FIN from %s:%d\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    // send ACK, transition to TIME_WAIT
    if (moe__tcp_make_simple_response(sock, TCP_FLAG_ACK, dev_fd) < 0) {
      return -MEINVPKT;
    }
    sock->state = TCP_TIME_WAIT;
    sock->close_time = moe__time_ms() + 2 * MSL_TIMEOUT;// current time + 2 * MSL
  }

  return 0;
}

static int moe__tcp_sock_handle_close_wait(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(sock);
  unused(dev_fd);
  unused(hdr);
  unused(pkt_size);

  // this state requires user to actively close the connection,
  // nothing special to do here

  return 0;
}

static int moe__tcp_sock_handle_closing(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(dev_fd);
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  if (tcp_hdr->flags & TCP_FLAG_ACK) {
    if (ntohl(tcp_hdr->ack_num) != sock->send_next) {
      moe_trace(LOG_WARN, "Received ACK with unexpected ack_num %u, expected %u\n", ntohl(tcp_hdr->ack_num), sock->send_next);
      return -MEINVPKT;
    }

    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received ACK for FIN from %s:%d\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    sock->state = TCP_TIME_WAIT;
    sock->close_time = moe__time_ms() + 2 * MSL_TIMEOUT;// current time + 2 * MSL
  }

  return 0;
}

static int moe__tcp_sock_handle_last_ack(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(dev_fd);
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  if (tcp_hdr->flags & TCP_FLAG_ACK) {
    if (ntohl(tcp_hdr->ack_num) != sock->send_next) {
      moe_trace(LOG_WARN, "Received ACK with unexpected ack_num %u, expected %u\n", ntohl(tcp_hdr->ack_num), sock->send_next);
      return -MEINVPKT;
    }

    char src_ip_str[16];
    moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
    moe_trace(
      LOG_DEBUG, "Received ACK for FIN from %s:%d, connection closed\n",
      src_ip_str,
      ntohs(tcp_hdr->src_port));

    sock->state = TCP_CLOSED;
  }

  return 0;
}

static int moe__tcp_sock_handle_time_wait(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(dev_fd);
  unused(hdr);
  unused(pkt_size);

  if (moe__time_ms() > sock->close_time) {
    // close the socket after TIME_WAIT timeout
    sock->state = TCP_CLOSED;
    moe_trace(LOG_DEBUG, "Socket closed after TIME_WAIT timeout\n");
  }

  return 0;
}

static int moe__tcp_sock_handle_fin_received(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(pkt_size);

  struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
  if (!(tcp_hdr->flags & TCP_FLAG_FIN)) {
    return 0;
  }

  if (sock->state != TCP_ESTABLISHED) {
    // FIN for other states is handled in their dedicated handlers or ignored.
    return 0;
  }

  if (ntohl(tcp_hdr->seq_num) != sock->recv_next) {
    moe_trace(LOG_WARN, "Received out-of-order FIN, expected seq_num %u but got %u, dropping\n", sock->recv_next, ntohl(tcp_hdr->seq_num));
    return -MEPKTDROP;
  }

  char src_ip_str[16];
  moe__stringify_ip(ntohl(hdr->src_addr), src_ip_str, sizeof(src_ip_str));
  moe_trace(
    LOG_DEBUG, "Received FIN from %s:%d\n",
    src_ip_str,
    ntohs(tcp_hdr->src_port));

  // send ACK for FIN
  sock->recv_next += 1;// FIN consumes one sequence number
  if (moe__tcp_make_simple_response(sock, TCP_FLAG_ACK, dev_fd) < 0) {
    return -MEINVPKT;
  }

  sock->state = TCP_CLOSE_WAIT;

  return 1;
}

int moe__tcp_sock_handle_send(struct moe_tcp_sock* sock, int dev_fd, uint64_t now_ms) {
  unused(dev_fd);

  if (sock->send_buf_size == 0) {
    // nothing to send
    return 0;
  }

  if (sock->state != TCP_ESTABLISHED) {
    moe_trace(LOG_WARN, "Attempting to send data in non-ESTABLISHED state %d\n", sock->state);
    return -MEINVST;
  }

  size_t unacked_len = sock->send_next - sock->send_unack;
  if (unacked_len == 0) {
    // waiting for new data to send
    return 0;
  }

  if (now_ms < sock->retransmit_time) {
    // not yet time to retransmit
    return 0;
  }

  moe_trace(LOG_DEBUG, "Retransmission timeout, resending unacknowledged data\n");
  // set next retransmission time
  sock->retransmit_time = now_ms + sock->timeout_dur;
  sock->timeout_dur *= 2;// exp backoff
  moe__tcp_on_timeout(sock);

  ssize_t to_send = unacked_len < sock->send_buf_size ? unacked_len : sock->send_buf_size;
  size_t offset = 0;
  while (to_send > 0) {
    size_t chunk_size = to_send < MSS_SIZE ? to_send : MSS_SIZE;
    if (moe__tcp_transmit(sock, sock->send_buf + offset, chunk_size, TCP_FLAG_ACK, dev_fd) < 0) {
      return -MEINVPKT;
    }
    // this does not increment send_next,
    // this is done in user call moe_tcp_sock_send
    to_send -= chunk_size;
    offset += chunk_size;
  }

  return 0;
}

int moe__tcp_sock_handle(struct moe_tcp_sock* sock, int dev_fd, struct moe_iphdr* hdr, size_t pkt_size) {
  unused(dev_fd);

  int err;

  err = moe__tcp_sock_handle_fin_received(sock, dev_fd, hdr, pkt_size);
  if (err < 0) {
    return err;
  } else if (err > 0) {
    // if FIN is received and handled, no need to further process the packet
    return 0;
  }

  switch (sock->state) {
    case TCP_CLOSED:
      if ((err = moe__tcp_sock_handle_closed(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_LISTEN:
      if ((err = moe__tcp_sock_handle_listen(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_SYN_SENT:
      if ((err = moe__tcp_sock_handle_syn_sent(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_SYN_RECEIVED:
      if ((err = moe__tcp_sock_handle_syn_received(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_ESTABLISHED:
      if ((err = moe__tcp_sock_handle_established(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_FIN_WAIT_1:
      if ((err = moe__tcp_sock_handle_fin_wait_1(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_FIN_WAIT_2:
      if ((err = moe__tcp_sock_handle_fin_wait_2(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_CLOSE_WAIT:
      if ((err = moe__tcp_sock_handle_close_wait(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_CLOSING:
      if ((err = moe__tcp_sock_handle_closing(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_LAST_ACK:
      if ((err = moe__tcp_sock_handle_last_ack(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
    case TCP_TIME_WAIT:
      if ((err = moe__tcp_sock_handle_time_wait(sock, dev_fd, hdr, pkt_size)) < 0) return err;
      break;
  }

  err = moe__tcp_sock_handle_send(sock, dev_fd, moe__time_ms());
  if (err < 0) {
    return err;
  }

  return 0;
}

static int moe__tcp_sock_gc() {
  struct moe_tcp_sock* prev = NULL;
  struct moe_tcp_sock* sock = moe__global_tcp_sock_list;
  while (sock) {
    if (sock->state == TCP_CLOSED) {
      // remove from list and free
      if (prev) {
        prev->next = sock->next;
      } else {
        moe__global_tcp_sock_list = sock->next;
      }
      struct moe_tcp_sock* to_free = sock;
      sock = sock->next;

      char local_ip_str[16], remote_ip_str[16];
      moe__stringify_ip(ntohl(to_free->local_addr), local_ip_str, sizeof(local_ip_str));
      moe__stringify_ip(ntohl(to_free->remote_addr), remote_ip_str, sizeof(remote_ip_str));
      moe_trace(LOG_DEBUG, "Garbage collected closed socket, local-ep: %s:%d, remote-ep: %s:%d\n",
                local_ip_str, ntohs(to_free->local_port), remote_ip_str, ntohs(to_free->remote_port));

      free(to_free);
    } else {
      prev = sock;
      sock = sock->next;
    }
  }

  return 0;
}

int moe_tcp_lib_init() {
  if (moe__global_tcp_sock_list) {
    moe_trace(LOG_WARN, "TCP library already initialized\n");
    moe_tcp_lib_cleanup();
    return -MEINVST;
  }

  moe__global_tcp_sock_list = NULL;

  // seed the RNG
  srand(time(NULL));

  return 0;
}

void moe_tcp_lib_cleanup() {
  struct moe_tcp_sock* sock = moe__global_tcp_sock_list;
  while (sock) {
    struct moe_tcp_sock* next = sock->next;
    free(sock);
    sock = next;
  }
  moe__global_tcp_sock_list = NULL;
}

int moe_tcp_update(struct moe_iphdr* hdr, size_t pkt_size) {
  int validation_err = moe__tcp_validate_packet(hdr, pkt_size);
  if (validation_err < 0) {
    return validation_err;
  }

  // find the corresponding socket
  struct moe_tcp_sock* sock = moe__global_tcp_sock_list;
  struct moe_tcp_sock* listening_sock = NULL;
  while (sock) {
    struct moe_tcphdr* tcp_hdr = moe_cast(struct moe_tcphdr, hdr, hdr->ihl * sizeof(uint32_t));
    if (sock->local_addr == hdr->dst_addr && sock->remote_addr == hdr->src_addr &&
        sock->local_port == tcp_hdr->dst_port && sock->remote_port == tcp_hdr->src_port) {
      // match both addr & port connections with known remote endpoint
      break;
    }

    if (sock->state == TCP_LISTEN && sock->local_port == tcp_hdr->dst_port) {
      // for listening sockets, match only on local port,
      // check later
      listening_sock = sock;
    }

    sock = sock->next;
  }

  if (!sock && listening_sock) {
    // if no exact match, use the listening sock if available
    sock = listening_sock;
  }

  if (!sock) {
    // no matching socket, drop the packet
    moe_trace(LOG_WARN, "No matching socket for incoming packet, dropping\n");
    return -MEPKTDROP;
  }

  return moe__tcp_sock_handle(sock, sock->sock_fd, hdr, pkt_size);
}

int moe_tcp_tick() {
  int err;
  struct moe_tcp_sock* sock = moe__global_tcp_sock_list;
  bool has_closed_sock = false;
  uint64_t now_ms = moe__time_ms();
  while (sock) {
    if (sock->state == TCP_TIME_WAIT && now_ms > sock->close_time) {
      sock->state = TCP_CLOSED;
      moe_trace(LOG_DEBUG, "Socket closed after TIME_WAIT timeout\n");
    }

    err = moe__tcp_sock_handle_send(sock, sock->sock_fd, now_ms);
    if (err < 0 && err != -MEINVST) {
      return err;
    }

    if (sock->state == TCP_CLOSED) {
      has_closed_sock = true;
    }

    sock = sock->next;
  }

  if (has_closed_sock) {
    moe__tcp_sock_gc();
  }

  return 0;
}

int main() {
  int tun_fd;
  char buf[2048];

  if ((tun_fd = moe_tun_alloc("tun0")) < 0) return EXIT_FAILURE;
  moe_tun_configure("tun0", "192.168.100.1");
  moe_tcp_lib_init();

  struct moe_tcp_sock* listen_sock;
  moe_tcp_sock_init(&listen_sock, tun_fd);
  moe_tcp_sock_listen(listen_sock, 8080);

  struct moe_tcp_sock* client_sock = NULL;

  moe_trace(LOG_INFO, "Server listening on 192.168.100.3:8080...\n");

  struct pollfd pfd;
  pfd.fd = tun_fd;
  pfd.events = POLLIN;

  while (1) {
    int poll_res = poll(&pfd, 1, 50);
    if (poll_res < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    if (poll_res > 0) {
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        break;
      }

      if (pfd.revents & POLLIN) {
        int nread = read(tun_fd, buf, sizeof(buf));
        if (nread <= 0) break;

        struct moe_iphdr* ip_hdr = (struct moe_iphdr*) buf;
        if (ip_hdr->version != 4) {
          continue;
        }

        if (ip_hdr->protocol == IPPROTO_ICMP) {
          moe__handle_icmp(tun_fd, ip_hdr, nread);
        } else if (ip_hdr->protocol == IPPROTO_TCP) {
          moe_tcp_update(ip_hdr, nread);
        }
      }
    }

    if (moe_tcp_tick() < 0) {
      break;
    }

    if (!client_sock) {
      if (moe_tcp_sock_accept(listen_sock, &client_sock) == 0) {
        moe_trace(LOG_INFO, "Client connected.\n");
      }
    }

    if (client_sock) {
      uint8_t data[1024];
      int n = moe_tcp_sock_recv(client_sock, data, sizeof(data));

      if (n > 0) {
        moe_tcp_sock_send(client_sock, data, n);
      } else if (n == 0) {
        moe_trace(LOG_INFO, "Client disconnected.\n");
        moe_tcp_sock_close(client_sock);
        client_sock = NULL;
      }
    }
  }

  moe_tcp_lib_cleanup();
  return 0;
}
