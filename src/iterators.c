#include <stdlib.h>
#include <xtables.h>
#include <stdio.h>
#include <string.h>
#include "iterators.h"

void for_each_table(void (*func)(const char *, void*), void *func_opts) {
    FILE *procfile = NULL;
    char tablename[XT_TABLE_MAXNAMELEN + 1];

    procfile = fopen("/proc/net/ip_tables_names", "re");
    if (!procfile) {
        perror("Can't get tables names");
        exit(1);
    }

    while (fgets(tablename, sizeof (tablename), procfile)) {
        if (tablename[strlen(tablename) - 1] != '\n') {
            perror("Badly formed tablename\n");
            exit(1);
        }

        tablename[strlen(tablename) - 1] = '\0';
        func(tablename, func_opts);
    }

    fclose(procfile);

}

void for_each_chain(struct xtc_handle *h, void (*func)(struct xtc_handle *, const char *, void *), void *func_opts) {
    const char* chain = NULL;
    
    for (chain = iptc_first_chain(h);
            chain;
            chain = iptc_next_chain(h)) {
        func(h, chain, func_opts);
    }
}