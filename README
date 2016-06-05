# natcap

client:
dir=0 pre_routing encode dnat
dir=0 local_out encode dnat
dir=1 post_routing decode
dir=1 local_in decode


server:
dir=0 pre_routing decode dnat
dir=1 post_routing encode

without natcap:
client_A[A>B]======>router_A1[A>B,SNAT,A1>B]====================================================[A1>B]server_B
client_A[A<B]<======router_A1[A<B,DNAT,A1<B]<===================================================[A1<B]server_B
with natcap:
client_A[A>B]===>[A>B,encode,DNAT,A>X]router_A1[A<X,SNAT,A1>X]===>[A1>X,decode,DNAT,A1>B]server_X[A1>B,SNAT,X>B]===>[X>B]server_B
client_A[A<B]===>[A<B,SNAT,decode,A<X]router_A1[A<X,DNAT,A1<X]===>[A1<X,SNAT,encode,A1<B]server_X[A1<B,DNAT,X<B]<===[X<B]server_B
