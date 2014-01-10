#ifndef ITERATORS_H
#define	ITERATORS_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <libiptc/libiptc.h>

    void for_each_table(void (*func)(const char *, void*), void *func_opts);
    void for_each_chain(struct xtc_handle *h, void (*func)(struct xtc_handle *, const char *, void *), void *func_opts);


#ifdef	__cplusplus
}
#endif

#endif

