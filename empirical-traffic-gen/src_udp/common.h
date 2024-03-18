#ifndef __common_h
#define __common_h

#include <stdlib.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* prototypes */
unsigned int read_exact(int fd, char *buf, size_t count, 
		size_t max_per_read, bool dummy_buf);
unsigned int write_exact(int fd, const struct sockaddr_in6 *cliaddr, const char *buf, size_t count, 
		 size_t max_per_write, bool dummy_buf);
void error(const char *msg);

#endif
