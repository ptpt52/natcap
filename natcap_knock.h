/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:31 +0800
 *
 * This file is part of the natcap.
 *
 * natcap is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * natcap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with natcap; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#ifndef _NATCAP_KNOCK_H_
#define _NATCAP_KNOCK_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include "natcap.h"

extern unsigned short knock_port;
extern unsigned int knock_flood;
extern unsigned short knock_encryption;
extern unsigned char knock_tcp_encode;
extern unsigned char knock_udp_encode;

extern void natcap_knock_info_select(__be32 ip, __be16 port, struct tuple *dst);

int natcap_knock_init(void);
void natcap_knock_exit(void);

#endif /* _NATCAP_KNOCK_H_ */
