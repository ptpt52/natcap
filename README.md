# natcap

TCP flow establishing connection
--------------------------------

![Image of TCP flow establishing connection](https://raw.githubusercontent.com/ptpt52/natcap/master/natcap_seq.png)


How router works
----------------

https://github.com/ptpt52/natcap/blob/master/docs/multi_conn.pdf

TCP encode headers
------------------

https://github.com/ptpt52/natcap/blob/master/docs/natcap_tcp_type1.pdf
https://github.com/ptpt52/natcap/blob/master/docs/natcap_tcp_type2.pdf
https://github.com/ptpt52/natcap/blob/master/docs/natcap_tcp_type3.pdf

Install on Ubuntu
------------------------------

Install essential packages
```sh
sudo apt-get install build-essential ipset libev-dev
sudo apt-get build-dep linux-image-`uname -r`
sudo apt-get install lua5.1 lua-cjson lua-bitop ipcalc
```

Get the source code
```sh
git clone https://github.com/ptpt52/natcap.git
```

Build and run as client
```sh
cd natcap
make && make -C natcapd
#edit client.sh change server line
sudo ./client.sh
```

Build and run as server
```sh
cd natcap
make && make -C natcapd
sudo ./server.sh
```

## License

```
Copyright: 2012, Chen Minqiang <ptpt52@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
```

## Donate
Buy me a beer!

[<img src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif">](https://paypal.me/ptpt52)
