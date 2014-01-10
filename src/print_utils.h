#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <xtables.h>
#include <string.h>
#include <libiptc/libiptc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>




struct options opts;

struct options{
    struct sockaddr * src;
    struct sockaddr * dst;
};
int getipaddr(char * name, struct sockaddr * sin,int family); 

int rule_match(const struct ipt_entry *e);

static void print_iface(char letter, const char *iface, const unsigned char *mask, int invert);
void print_mask(const struct in_addr *mask);
void print_ip(char letter,const struct in_addr *ip, const struct in_addr *mask);
void print_rule4(const struct ipt_entry *e,
                struct xtc_handle *h, const char *chain);
void print_chain(struct xtc_handle *h, const char *chain);
int print_table(const char *tablename);

