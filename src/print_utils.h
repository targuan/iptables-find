#include <netinet/in.h>
#include <libiptc/libiptc.h>
#include <xtables.h>


void print_iface(char letter, const char *iface, const unsigned char *mask, int invert);
void print_mask(const struct in_addr *mask);
void print_ip(char letter,const struct in_addr *ip, const struct in_addr *mask);
void print_ip4rule(const struct ipt_entry *e, struct xtc_handle *h, const char *chain);
void print_chain(struct xtc_handle *h, const char *chain, int (*rule_checker)(void*));
int print_table(const char *tablename, int (*rule_checker)(void*));

