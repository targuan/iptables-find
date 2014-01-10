#include "print_utils.h"


int getipaddr(char * name, struct sockaddr * sin,int family) {
    struct addrinfo * res;
    struct addrinfo * info;
    struct addrinfo hints = {0};
    int error;
    int found = 0;

    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = family;

    error = getaddrinfo(name,NULL,&hints,&res);
    if (error != 0)
    {
        if (error == EAI_SYSTEM)
        {
            perror("getaddrinfo");
        }
        else
        {
            fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
        }
        return -1;
    }
    else {
        for(info = res;info != NULL && found == 0; info = info->ai_next) {
            switch(info->ai_addr->sa_family) {
                case AF_INET:
                case AF_INET6:
                    memcpy(sin,info->ai_addr,info->ai_addrlen);
                    found = 1;
                    break;
            }
        }

        freeaddrinfo(res);
    }
    if(found == 1){
        return 0;
    }
    else {
        return -2;
    }
}

int rule_match(const struct ipt_entry *e)
{
    struct sockaddr_in *sin;
    uint32_t saddr;
    uint32_t srule;
    uint32_t mrule;

    sin = (struct sockaddr_in *)opts.src;
    mrule = e->ip.smsk.s_addr;
    srule = e->ip.src.s_addr;
    saddr = sin->sin_addr.s_addr;

    saddr =  saddr&mrule;


    return saddr==srule;
}

static void print_iface(char letter, const char *iface, const unsigned char *mask, int invert)
{
    unsigned int i;

    if (mask[0] == 0)
        return;

    printf(" -%c %s", letter, invert ? "! " : "");

    for (i = 0; i < IFNAMSIZ; i++) {
        if (mask[i] != 0) {
            if (iface[i] != '\0')
                printf("%c", iface[i]);
        } else {
            /* we can access iface[i-1] here, because
            * a few lines above we make sure that mask[0] != 0 */
            if (iface[i-1] != '\0')
                printf("+");
            break;
        }
    }

    printf(" ");
}

void print_mask(const struct in_addr *mask)
{
    uint32_t bits,hmask = ntohl(mask->s_addr);
    int i=32;

    if (hmask == 0xFFFFFFFFU) {
        printf("/32");
        return;
    }
    bits = 0xFFFFFFFEU;
    while (--i >= 0 && hmask != bits)
        bits <<= 1;
    printf("/%u",i);
}

void print_ip(char letter,const struct in_addr *ip, const struct in_addr *mask)
{
    struct sockaddr_in in_ip;
    struct sockaddr_in in_msk;
    char host[NI_MAXHOST], msk[NI_MAXHOST], service[NI_MAXSERV];

    in_ip.sin_family = AF_INET;
    in_ip.sin_addr.s_addr = ip->s_addr;

    getnameinfo((struct sockaddr*)&in_ip,sizeof(struct sockaddr_in),
            host, NI_MAXHOST,
                    service, NI_MAXSERV, NI_NUMERICSERV|NI_NUMERICHOST);
    printf(" -%c %s",letter,host);
    print_mask(mask);
}


/* We want this to be readable, so only print out neccessary fields.
 * Because that's the kind of world I want to live in.  */
void print_rule4(const struct ipt_entry *e,
                struct xtc_handle *h, const char *chain)
{
    const struct xt_entry_target *t;
    const char *target_name;


    // print chain name
    printf("-A %s", chain);
    // Print IP part.
    print_ip('s',&(e->ip.src),&(e->ip.smsk));

    print_ip('d',&(e->ip.dst),&(e->ip.dmsk));

    print_iface('i',e->ip.iniface,e->ip.iniface_mask,e->ip.invflags & IPT_INV_VIA_IN);

    print_iface('o',e->ip.outiface,e->ip.outiface_mask,e->ip.invflags & IPT_INV_VIA_OUT);

    printf(" -p %d",e->ip.proto);
    // Print target name and targinfo part
    target_name = iptc_get_target(e, h);

    printf(" -j %s", target_name);

    printf("\n");

}

void print_chain(struct xtc_handle *h, const char *chain)
{
    const struct ipt_entry *e;
    int first_match = 1;

    e = iptc_first_rule(chain, h);
    while(e) {
        if(rule_match(e)) {
	    if(first_match) {
	        first_match = 0;
		
     		printf("CHAIN %s\n",chain);
	    }
            print_rule4(e, h, chain);
        }
        e = iptc_next_rule(e, h);
    }
}

int print_table(const char *tablename)
{
    struct xtc_handle *h;
    const char* chain = NULL;

    h = iptc_init(tablename);

    if (h == NULL) {
            xtables_load_ko(xtables_modprobe_program, false);
            h = iptc_init(tablename);
    }
    if (!h)
            xtables_error(OTHER_PROBLEM, "Cannot initialize: %s\n",
                       iptc_strerror(errno));

    printf("TABLE %s:\n",tablename);

    for (chain = iptc_first_chain(h);
        chain;
        chain = iptc_next_chain(h)) {
        print_chain(h,chain);
    }

    iptc_free(h);
    return 1;
}



