/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:31 +0800
 */
#ifndef _NATCAP_KNOCK_H_
#define _NATCAP_KNOCK_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include "natcap.h"

extern unsigned short knock_port;

extern void natcap_knock_info_select(__be32 ip, __be16 port, struct tuple *dst);

int natcap_knock_init(void);
void natcap_knock_exit(void);

#endif /* _NATCAP_KNOCK_H_ */
