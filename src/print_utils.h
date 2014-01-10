#ifndef PRINT_UTILS_H
#define	PRINT_UTILS_H

#ifdef	__cplusplus
extern "C" {
#endif






#include <netinet/in.h>
#include <libiptc/libiptc.h>
#include <xtables.h>

    struct print_table_opts {
        int (*rule_checker)(void*);
    };
    
    
    void print_table(const char *tablename, void *opts);
    void print_chain(struct xtc_handle *h, const char *chain, void *);

    void print_iface(char letter, const char *iface, const unsigned char *mask, int invert);
    void print_mask(const struct in_addr *mask);
    void print_ip(char letter, const struct in_addr *ip, const struct in_addr *mask);
    void print_ip4rule(const struct ipt_entry *e, struct xtc_handle *h, const char *chain);



#ifdef	__cplusplus
}
#endif

#endif