# Receive Packet
## __netif_receive_skb_core()

static int __netif_receive_skb_core(struct sk_buff *skb, bool pfmemalloc)  
{  
	struct net_device *orig_dev;  
	skb_reset_network_header(skb);  
	if (!skb_transport_header_was_set(skb))
		skb_reset_transport_header(skb);  
	skb_reset_mac_len(skb);  
	skb->skb_iif = skb->dev->ifindex;  
	list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list)  
	{	//跟據協議交給network 層作處理, 例ip, arp  
		if (pt_prev)	ret = deliver_skb(skb, pt_prev, orig_dev);	  		pt_prev = ptype;  
	}  
}  

## deliver_skb ()

static inline int deliver_skb(struct sk_buff *skb,struct packet_type *pt_prev,			      struct net_device *orig_dev)
{
	if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC)))
	return -ENOMEM;
	atomic_inc(&skb->users);
	return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}

//pt_prev->func(skb, skb->dev, pt_prev, orig_dev);

//跟據不同的protocol 做不同的處理, 例:ip_rcv, arp_rcv


## ip_rcv()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/0_ip_rcv.png)

##ip_rcv_finish()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/1_ip_rcv_finish.png)
ip_route_input_noref函數中已經知道要轉發封包還是本機接收
dst_input()調用到rtable.dst_entry->input()，根據路由不同，因應情況呼叫ip_forward/ip_local_deliver
	ip_forward -> ip_forward_finish -> ip_output
	ip_local_deliver -> ip_local_deliver_finish

##ip_local_deliver()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/2_ip_local_deliver.png)

###ip_defrag()
ip_defrag() 的處理流程
ip_defrag() -> ip_find() -> ip_frag_queue() -> ip_frag_reasm() 

ip_find()：創建queue
ip_frag_queue()：等待所有封包分片
ip_frag_reasm()：把封包組合起來

##ip_local_deliver_finish()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/3_ip_local_deliver_finish.png)

/*
__skb_pull()：
刪去ip header

rcu_dereference()：
檢查封包屬於哪一種protocol

ret = ipprot-> handler()：
封包進入udp tcp傳輸層
*/

#Send Packet
##ip_queue_xmit

tcp_write_xmit (alloc skb) 
|->  tcp_transmit_skb (skb_push(skb, tcp_header_size))
      |-> ip_queue_xmit (daddr = inet->inet_daddr, 嘗試查找路由緩存, 增加ip header)
	|-> ip_local_out()

int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);	struct rtable *rt;
	rt = skb_rtable(skb);				//routing cache
	rt = ip_route_output_ports(net, fl4, sk,
				   daddr, inet->inet_saddr,
				   inet->inet_dport,
				   inet->inet_sport,
				   sk->sk_protocol,
				   RT_CONN_FLAGS(sk),
				   sk->sk_bound_dev_if);
	 skb_dst_set_noref(skb, &rt->dst);
	 res = ip_local_out(net, sk, skb);
}

//.start_fw = iwl_trans_pcie_start_fw

##__ip_route_output_key_hash
struct rtable *__ip_route_output_key_hash(struct net *net, struct flowi4 *fl4,
					  int mp_hash)
{
	struct net_device *dev_out = NULL;
	struct rtable *rth;

	dev_out = __ip_dev_find(net, fl4->saddr, false);
	rth = __mkroute_output(&res, fl4, orig_oif, dev_out, flags);
	return rth;

}
//ip_route_output_ports() -> ip_route_output_flow() -> __ip_route_output_key_hash() 

##ip_local_out()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/4_ip_local_out.png)

/* 調用網絡過濾器檢查封包是否可以發送 */ 
err = __ip_local_out(net, sk, skb);
/* 當err為1時，表明本地產生的數據經過HOOK函數NF_IP_LOCAL_OUT進行路由選擇處理。在此調用dst_output來進行下一步處理 */ 
/* dst.h dst_output 即 ip_output() */ 

##ip_output()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/5_ip_output.png)
// 檢查 iptable 有沒有設定甚麼條件, 沒有的話直接到 ip_finish_output() 
return NF_HOOK_COND()

##ip_finish_output()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/6_ip_finish_output.png)

//調用ip_fragment() 對封包做分片後發送，或直接調用ip_finish_output2() 發送

##ip_do_fragment()
如果4層將封包分片了， 那麼就會把這些封包放到SKB的frag_list鍊錶中， 因此我們這里首先先判斷frag_list鍊錶是否為空，為空的話我們將會進行slow path切片

一般用快速切片的都是經由4層的ip_append_data和ip_push_pending函數（UDP） 將封包已經切片好的，或者是TCP層已經切片好的封包，才會用快速切片

切片時，每切一片就會立即發送出去，發送出去後不會暫存在記憶體中

###ip_do_fragment() – fast path
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/7_ip_do_fragment.png)

/*發送分片 output 就是 ip_finish_output2()*/ 
err = output(net, sk, skb2);

###ip_do_fragment() – slow path
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/8_ip_do_fragment-slow%20path.png)

/* 開始分片，開始為迴圈處理，每一個分片創建一個skb buffer */

![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/9_ip_do_fragment-slow%20path2.png)

/*
* 發送分片 output就
* 是 ip_finish_output2()
*/ 
err = output(net, sk, skb2);

##ip_finish_output2()
鄰居子系統: 路由子系統確定了封包要發送到的IP地址， 而在將封包提交給鏈路層之前，還需要知道目的主機的Mac的地址，這就是鄰居子系統做的事情

調用__ipv4_neigh_lookup_noref進行鄰居子系統的表查找，IPv4的主要是ARP表，查找到的ARP表，則調用dst_neigh_output -> neigh_hh_output -> dev_queue_xmit進行封包發送
 
如果沒有查找到，則調用__neigh_create -> arp_constructor進行發送等函數的裝載，最後也調用dst_neigh_output

##neigh_hh_output()
![image](https://github.com/MKHEYHEYHEY/linux_network_trace_code/blob/master/ip_network/pic/10_neigh_hh_output.png)

/*把 eth header 複制到sk_buffer的封包，再調用dev_queue_xmit進行硬件發送*/

##dev_queue_xmit()
int dev_queue_xmit(struct sk_buff *skb)
{	return __dev_queue_xmit(skb, NULL);	}

static int __dev_queue_xmit(struct sk_buff *skb, void *accel_priv)
{
	struct net_device *dev = skb->dev;	//*
	struct netdev_queue *txq;
	skb_reset_mac_header(skb);
	if (q->enqueue) 
	{	rc = __dev_xmit_skb(skb, q, dev, txq);	goto out;	}	//*
	skb = dev_hard_start_xmit(skb, dev, txq, &rc);	//*
}

//path:net\mac80211\rx.c
//.start_fw = iwl_trans_pcie_start_fw,

##dev_hard_start_xmit()
struct sk_buff *dev_hard_start_xmit
			(struct sk_buff *first, struct net_device *dev,
			 struct netdev_queue *txq, int *ret)
{
	struct sk_buff *skb = first;
	int rc = NETDEV_TX_OK;
	while (skb) 
	{
		struct sk_buff *next = skb->next;
		skb->next = NULL;
		rc = xmit_one(skb, dev, txq, next != NULL);	//*
	}
}

##xmit_one()
static int xmit_one(struct sk_buff *skb, struct net_device *dev,
		    struct netdev_queue *txq, bool more)
{
	unsigned int len;
	int rc;
	if (!list_empty(&ptype_all) || !list_empty(&dev->ptype_all))
		dev_queue_xmit_nit(skb, dev);

	rc = netdev_start_xmit(skb, dev, txq, more);
}

##netdev_start_xmit()
static inline netdev_tx_t netdev_start_xmit (struct sk_buff *skb, 
	struct net_device *dev, struct netdev_queue *txq, bool more)
{
	const struct net_device_ops *ops = dev->netdev_ops;	//*
	int rc;
	rc = __netdev_start_xmit(ops, skb, dev, more);
	if (rc == NETDEV_TX_OK)
		txq_trans_update(txq);
	return rc;
}
static inline netdev_tx_t __netdev_start_xmit(ops, skb, dev, more)
{
	skb->xmit_more = more ? 1 : 0;
	return ops->ndo_start_xmit(skb, dev);	//*
}

##net\mac80211\Iface.c
static const struct net_device_ops ieee80211_dataif_ops = {
	.ndo_open		= ieee80211_open,
	.ndo_stop		= ieee80211_stop,
	.ndo_uninit		= ieee80211_uninit,
	.ndo_start_xmit		= ieee80211_subif_start_xmit,	//*
	.ndo_set_rx_mode	= ieee80211_set_multicast_list,
	.ndo_set_mac_address 	= ieee80211_change_mac,
	.ndo_select_queue	= ieee80211_netdev_select_queue,
	.ndo_get_stats64	= ieee80211_get_stats64,
};

##net\mac80211\Iface.c
void __ieee80211_subif_start_xmit
	(struct sk_buff *skb, struct net_device *dev, u32 info_flags)
{
	struct sk_buff *next;
	next = skb;
	while (next) {
		skb = next;
		next = skb->next;
		skb->prev = NULL;
		skb->next = NULL;
		skb = ieee80211_build_hdr(sdata, skb, info_flags, sta);
		if (IS_ERR(skb))	goto out;
		ieee80211_tx_stats(dev, skb->len);
		ieee80211_xmit(sdata, sta, skb);	//*
	}
}

##net\mac80211\Iface.c
const struct ieee80211_ops iwl_mvm_hw_ops = 
{
	.tx = iwl_mvm_mac_tx,
	.ampdu_action = iwl_mvm_mac_ampdu_action,
	.start = iwl_mvm_mac_start,
	.reconfig_complete = iwl_mvm_mac_reconfig_complete,
	.stop = iwl_mvm_mac_stop,
	.add_interface = iwl_mvm_mac_add_interface,
	......
}

##iwl_mvm_mac_tx
static void iwl_mvm_mac_tx(struct ieee80211_hw *hw,
			   struct ieee80211_tx_control *control,
			   struct sk_buff *skb)
{ 
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);
	struct ieee80211_sta *sta = control->sta;
	 struct ieee80211_hdr *hdr = (void *)skb->data;
	
	 iwl_mvm_tx_skb(mvm, skb, sta);	//*
}

##iwl_mvm_tx_skb()
int iwl_mvm_tx_skb(struct iwl_mvm *mvm, struct sk_buff *skb,
		   struct ieee80211_sta *sta)
{
	struct iwl_mvm_sta *mvmsta = iwl_mvm_sta_from_mac80211(sta);
	struct ieee80211_tx_info *skb_info = IEEE80211_SKB_CB(skb);
	struct ieee80211_tx_info info;
	while (!skb_queue_empty(&mpdus_skbs)) 
	{
		skb = __skb_dequeue(&mpdus_skbs);
		ret = iwl_mvm_tx_mpdu(mvm, skb, &info, sta);
	}
	
}

##iwl_mvm_tx_mpdu()
static int iwl_mvm_tx_mpdu(struct iwl_mvm *mvm, struct sk_buff *skb,
			   struct ieee80211_tx_info *info,
			   struct ieee80211_sta *sta)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct iwl_mvm_sta *mvmsta;
		
}
