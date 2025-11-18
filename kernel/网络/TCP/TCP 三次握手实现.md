# 1. 客户端调用```connect```接口，发送 SYN 报文，进入 SYN_SENT 状态：

## tcp_v4_connect
```c
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
                          sk->sk_bound_dev_if, IPPROTO_TCP, orig_sport,
                          orig_dport, sk);
    ...
    tcp_set_state(sk, TCP_SYN_SENT);
    ......
    // 初始化写序列号
    if (likely(!tp->repair)) {
        if (!tp->write_seq)
            WRITE_ONCE(tp->write_seq, secure_tcp_seq(inet->inet_saddr,
                                                     inet->inet_daddr,
                                                     inet->inet_sport,
                                                     usin->sin_port));
    }
    ......
    tcp_connect(sk);
}
```

## tcp_connect

```C
int tcp_connect(struct sock *sk)
{
    .....
    tcp_connect_init(sk);
    ......
    buff = tcp_stream_alloc_skb(sk, sk->sk_allocation, true);
    tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
    tcp_ecn_send_syn(sk, buff);
    tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);

    // 发送报文
    err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) : tcp_transmit_skb(sk,  , 1, sk->sk_allocation);

    // 重置重传定时器
    inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
}
```
