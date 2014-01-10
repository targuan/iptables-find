#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include "print_utils.h"
#include "iterators.h"


struct options opts;

struct options {
    struct sockaddr * src;
    struct sockaddr * dst;
};

int getipaddr(char * name, struct sockaddr * sin, int family) {
    struct addrinfo * res;
    struct addrinfo * info;
    struct addrinfo hints = {0};
    int error;
    int found = 0;

    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = family;

    error = getaddrinfo(name, NULL, &hints, &res);
    if (error != 0) {
        if (error == EAI_SYSTEM) {
            perror("getaddrinfo");
        } else {
            fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
        }
        return -1;
    } else {
        for (info = res; info != NULL && found == 0; info = info->ai_next) {
            switch (info->ai_addr->sa_family) {
                case AF_INET:
                case AF_INET6:
                    memcpy(sin, info->ai_addr, info->ai_addrlen);
                    found = 1;
                    break;
            }
        }

        freeaddrinfo(res);
    }
    if (found == 1) {
        return 0;
    } else {
        return -2;
    }
}

int rule_matcher(void *arg) {
    int rval = 1;

    uint32_t opt_saddr, opt_daddr;

    uint32_t rul_saddr, rul_smsk, rul_daddr, rul_dmsk;

    struct ipt_entry *e = (struct ipt_entry *) arg;

    rul_smsk = e->ip.smsk.s_addr;
    rul_saddr = e->ip.src.s_addr;

    rul_dmsk = e->ip.dmsk.s_addr;
    rul_daddr = e->ip.dst.s_addr;

    opt_saddr = ((struct sockaddr_in*) opts.src)->sin_addr.s_addr;
    opt_saddr = opt_saddr & rul_smsk;

    opt_daddr = ((struct sockaddr_in*) opts.dst)->sin_addr.s_addr;
    opt_daddr = opt_daddr & rul_dmsk;

    if (opt_saddr != 0) {
        rval &= (opt_saddr == rul_saddr);
    }
    if (opt_daddr != 0) {
        rval &= (opt_daddr == rul_daddr);
    }
    return rval;
    //return (opt_saddr == rul_saddr) && (opt_daddr == rul_daddr);
}

int main(int argc, char **argv) {
    char c;
    struct sockaddr_in *sin;
    char *tablename = NULL;
    struct print_table_opts ptopts;

    opts.src = calloc(sizeof (struct sockaddr_storage), 1);
    opts.dst = calloc(sizeof (struct sockaddr_storage), 1);


    while ((c = getopt(argc, argv, "s:d:t:")) != -1) {
        switch (c) {
            case 's':
                getipaddr(optarg, opts.src, AF_INET);
                break;
            case 'd':
                getipaddr(optarg, opts.dst, AF_INET);
                break;
            case 't':
                tablename = malloc(sizeof (char)*XT_TABLE_MAXNAMELEN + 1);
                strncpy(tablename, optarg, XT_TABLE_MAXNAMELEN);
                tablename[XT_TABLE_MAXNAMELEN] = '\0';
                break;
        }
    }
    ptopts.rule_checker = rule_matcher;
    
    if (tablename == NULL) {
        for_each_table(&print_table, (void*) &ptopts);
    } else {
        print_table(tablename, (void*)&ptopts);
    }
    return 0;
}


