/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Sun, 05 Jun 2016 16:24:37 +0800
 */
#ifndef _NATCAP_SERVER_H_
#define _NATCAP_SERVER_H_

extern int dns_server_node_add(__be32 ip);
extern void dns_server_node_clean(void);

int natcap_server_init(void);

void natcap_server_exit(void);

extern char *auth_http_redirect_url;

#endif /* _NATCAP_SERVER_H_ */
