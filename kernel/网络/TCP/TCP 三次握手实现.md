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
    syncookies = READ_ONCE(net->ipv4.sysctl_tcp_syncookies);
    // 1. (强制启用SYN Cookie机制 或者 半连接/全连接队列已满)
    if ((syncookies == 2 || inet_csk_reqsk_queue_is_full(sk)) && !isn) {
        want_cookie = tcp_syn_flood_action(sk, rsk_ops->slab_name);
		if (!want_cookie)
			goto drop;
    }
    // 2. 当前的半连接队列长度超过允许的最大半连接（SYN_RECV 状态）队列长度
    if (sk_acceptq_is_full(sk)) {
        NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
        goto drop;
    }
    // 3. fen
    req = inet_reqsk_alloc(rsk_ops, sk, !want_cookie);
    ......
    tcp_openreq_init(req, &tmp_opt, skb, sk);
    // 4.
    if (fastopen_sk) {
        af_ops->send_synack(fastopen_sk, dst, &fl, req, &foc, TCP_SYNACK_FASTOPEN, skb);
        if (!inet_csk_reqsk_queue_add(sk, req, fastopen_sk)) {      // 将 完整的半连接插入到 SYN Queue（半连接队列）
            reqsk_fastopen_remove(fastopen_sk, req, false);
            ......
            goto drop_and_free;
        }
    } else {
        if (!want_cookie) {       //  不需要开启 Cookie 验证
            req->timeout = tcp_timeout_init((struct sock *)req));
            inet_csk_reqsk_queue_hash_add(sk, req, req->timeout);
        }
        af_ops->send_synack(sk, dst, &fl, req, &foc, !want_cookie ? TCP_SYNACK_NORMAL : TCP_SYNACK_COOKIE, skb);
        if (want_cookie) {
            reqsk_free(req);
            return 0;
        }
    }
}
```


TCP Cookie 解决问题：

1. SYN 洪水攻击风险：服务器收到客户端 SYN 后，会创建半连接（存入 SYN Queue）并回复 SYN + ACK，若客户端不回复 ACK ，半连接会占用资源直到超时，导致服务器拒绝服务；

2. 短连接资源浪费：大量 HTTP 短连接的场景，服务器维护完整连接转；

## tcp_openreq_init

# 3. 客户端收到服务器发送的 SYN + ACK 报文

客户端对应sock连接状态为```SYN_SENT```态。


## 3.1 tcp_v4_rcv

```C
int tcp_v4_rcv(struct sk_buff *skb)
{
}
```

## 3.2 tcp_v4_do_rcv

```C
int tcp_v4_do_rcv()
{
    ......
    if (sk->sk_state == TCP_ESTABLISHED) {
        ......
        return 0;
    }
    ......
    if (sk_state == TCP_LISTEN) {
        ......
    } else
       sock_rps_save_rxhash(sk, skb);
    if (tcp_rcv_state_process(sk, skb) {
        rsk = sk;
        goto reet'
    }
    return 0;
    ......
}
```

## 3.3 rcp_rcv_state_prpcess

```C
int tcp_rcv_state_process(struct sock *sk, struct sk_buff *skb)
{
    ......
    swicth (sk=>sk_state) {
    case TCP_CLOSE:
        ......
    case TCP_LISTEN:
        ......
    case TCP_SYN_SENT:
        tp->rx_opt.saw_tstamp = 0;
        tcp_mstamp_refresh(tp);
        queued = tcp_rcv_synsent_state_process(sk, skb, th);
        if (queued >= 0)
           return queued;
        tcp_urg(sk, skb, th);
        __kfree_skb(skb);
        tcp_data_snd_check(sk);
        return 0;
    }
}
```

## 3.4 tcp_rcv_synsent_state_process

```C
static int tcp_rcv_synsent_state_process(struct sock *sk, struct sk_buff *skb, const struct tcphdr *th)
{
     ......
     tcp_parse_options(sock_net(sk), skb, &tp->rx_opt, 0, &foc);
     if (th->ack) {
        // 序列号检查
        if (!after(TCP_SKB_CB(skb)->ack_seq, tp->snd_una) ||
            after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {
            if (icsk->icsk_retransmits == 0) {
				inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, TCP_TIMEOUT_MIN, TCP_RTO_MAX);
                goto reset_and_undo;
            }
        }
        //
        if (tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr &&
		    !between(tp->rx_opt.rcv_tsecr, tp->retrans_stamp,
			     tcp_time_stamp_ts(tp))) {
			NET_INC_STATS(sock_net(sk),
					LINUX_MIB_PAWSACTIVEREJECTED);
			goto reset_and_undo;
		}

        if (th->rst) {
			tcp_reset(sk, skb);
consume:
			__kfree_skb(skb);
		}

		if (!th->syn) {
			SKB_DR_SET(reason, TCP_FLAGS);
			goto discard_and_undo;
		}
        tcp_ecn_rcv_synack(tp, th);

		tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
		tcp_try_undo_spurious_syn(sk);
		tcp_ack(sk, skb, FLAG_SLOWPATH);

        .....
		tcp_finish_connect(sk, skb);
		.....
		tcp_send_ack(sk);
		return -1;
    }

	if (th->rst) {
		SKB_DR_SET(reason, TCP_RESET);
		goto discard_and_undo;
	}
    // PAWS 校验
	if (tp->rx_opt.ts_recent_stamp && tp->rx_opt.saw_tstamp &&
	    tcp_paws_reject(&tp->rx_opt, 0)) {
		SKB_DR_SET(reason, TCP_RFC7323_PAWS);
		goto discard_and_undo;
	}
    // TCP_SENT状态下收到SYN 报文（不带ACK）
    if (th->syn) {
        tcp_set_state(sk, TCP_SYN_RECV);
		......
		tcp_send_synack(sk);
	}

}
```

1. SYN SENT 状态下收到 RST 报文，清除sock中存储的选项，并丢弃报文

2. PAWS 校验

3. 客户端 在 SYN_SENT 状态下收到 AYN 报文，会进入 SYN_RECV 状态，这个对应两个两个连接同时发起场景；

## 3.5 tcp_finish_connect

```C
void tcp_finish_connect(struct sock* sk, struct sk_buff* skb)
{
	tcp_ao_finish_connect(sk, skb);
	tcp_set_state(sk, TCP_ESTABLISHED);                                      // 设置 TCP 状态为 ESTABLISHED
	icsk->icsk_ack.lrcvtime = tcp_jiffies32;

    ......
    if (sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_alive_timer(sk, keepalive_time_when(tp));
	.....
}
```

# 4. 服务器在半连接状态下收到 AYN + ACK报文

## 4.1 tcp_v4_rcv

```C
int tcp_v4_rcv(struct sk_buff *skb)
{
	......
    if (sk->sk_state == TCP_NEW_SYN_RECV) {
		struct request_sock *req = inet_reqsk(sk);
		sk = req->rsk_listener;
		......
		if (!tcp_filter(sk, skb)) {
			tcp_v4_fill_cb(skb, iph, th);
			nsk = tcp_check_req(sk, skb, req, false, &req_stolen);
		} else {
		}
		if (!nsk) {
			......
		}
		if (nsk == sk) {
			reqsk_put(req);
			tcp_v4_restore_cb(skb);
		} else if (tcp_child_process(sk, nsk, skb)) {
			tcp_v4_send_reset(nsk, skbb)
		}
	}
}
```

## 4.2 tcp_check_req

```C
struct sock *tcp_check_req(struct sock *sk, struct sk_buff *skb,
			               struct request_sock *req,
			               bool fastopen, bool *req_stolen)
{
	......
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn &&
	    flg == TCP_FLAG_SYN &&
		!paws_reject) {
		......
	}
	//
	if ((flg & TCP_FLAG_ACK) && !fastopen &&
	    (TCP_SKB_CB(skb)->ack_seq !=
	     tcp_rsk(req)->snt_isn + 1))
		return sk;
	.....
	child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL,
							 req, &own_req);
	if (!child)
		goto listen_overflow;
	......
	return inet_csk_complete_hashdance(sk, child, req, own_req);
}
```

## 4.3 tcp_v4_syn_recv_sock

```C
struct sock *tcp_v4_syn_recv_sock(const struct sock *sk, struct sk_buff *skb,
			                	  struct request_sock *req,
								  struct dst_entry *dst,
								  struct request_sock *req_unhash,
								  bool *own_req)
{
	......
	if (sk_acceptq_is_full(sk))
		goto exit_overflow;

	newsk = tcp_create_openreq_child(sk, req, skb);
	if (!newsk)
		goto exit_nonewsk;
}
```

## 4.4 tcp_create_openreq_child


