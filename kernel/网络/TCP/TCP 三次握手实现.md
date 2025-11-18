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

# 2. 服务端收到 SYN 报文，进入
## tcp_v4_rcv
```C
int tcp_v4_rcv(struct sk_buff *skb)
{
    ......
    if (sk->sk_state == TCP_LISTEN) {
        ret = tcp_v4_do_rcv(sk, skb);
		goto put_and_return;
    }
}
```

## tcp_v4_do_rcv
```C
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
    ......
    if (sk->sk_state == TCP_LISTEN) {
		struct sock *nsk = tcp_v4_cookie_check(sk, skb);

		if (!nsk)
			goto discard;
		if (nsk != sk) {
			if (tcp_child_process(sk, nsk, skb)) {
				rsk = nsk;
				goto reset;
			}
			return 0;
		}
    }

}
```
## tcp_rcv_state_process

```C
int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb)
{
    switch (sk->sk_state) {
    ......
    case TCP_LISTEN:
    if (th->ack)                                                   // LISTEN状态下收到ACK报文，返回1，发送 RST 报文重置对端连接
			return 1;

		if (th->rst) {                                             // 收到RST报文，直接丢弃
			SKB_DR_SET(reason, TCP_RESET);
			goto discard;
		}
		if (th->syn) {                                             // 收到 SYN 报文
			if (th->fin) {
				SKB_DR_SET(reason, TCP_FLAGS);
				goto discard;
			}
			rcu_read_lock();
			local_bh_disable();
			acceptable = icsk->icsk_af_ops->conn_request(sk, skb) >= 0;
			local_bh_enable();
			rcu_read_unlock();

			if (!acceptable)
				return 1;
			consume_skb(skb);
			return 0;
		}
		SKB_DR_SET(reason, TCP_FLAGS);
		goto discard;
    ......
}
```

## tcp_v4_conn_request

```C
int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
    if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))   // 收到 广播或者单播报文
		goto drop;

	return tcp_conn_request(&tcp_request_sock_ops, &tcp_request_sock_ipv4_ops, sk, skb);
}

```

## tcp_conn_request

```C
int tcp_conn_request(struct request_sock_ops *rsk_ops,
		             const struct tcp_request_sock_ops *af_ops,
		             struct sock *sk, struct sk_buff *skb)
{
    ......
    if ((syncookies == 2 || inet_csk_reqsk_queue_is_full(sk)) && !isn) {
    }
}
```
