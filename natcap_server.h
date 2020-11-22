/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:37 +0800
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
#ifndef _NATCAP_SERVER_H_
#define _NATCAP_SERVER_H_

extern unsigned int server_flow_stop;
extern unsigned int user_mark_natcap_mask;

extern int dns_server_node_add(__be32 ip);
extern void dns_server_node_clean(void);

int natcap_server_init(void);

void natcap_server_exit(void);

extern char *auth_http_redirect_url;

#endif /* _NATCAP_SERVER_H_ */
