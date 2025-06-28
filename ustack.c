#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <unistd.h>

int g_dpdkd_port_id = 0;
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

#define NUM_MBUFS     2048
#define BURST_SIZE     128

int main(int argc, char *argv[])
{
    // 初始化DPDK环境
    if(rte_eal_init(argc, argv) < 0){
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0){
        rte_exit(EXIT_FAILURE, "No support eth found\n");
    }

    printf("nb_sys_ports: %d\n", nb_sys_ports);

    /*创建内存池*/
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", NUM_MBUFS, 0/*cache size*/, 0/*private size*/, RTE_MBUF_DEFAULT_BUF_SIZE/*pkt_room_size*/, rte_socket_id()/* `rte_socket_id()` 来获取当前线程所在的NUMA节点，然后在该节点上分配内存池*/);
    if(!mbuf_pool){
        rte_exit(EXIT_FAILURE, "Could not create mbuf_pool\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(g_dpdkd_port_id, &dev_info);

    const int num_rx_queue = 1;
    const int num_tx_queue = 0;
    struct rte_eth_conf port_conf = port_conf_default;
    if(rte_eth_dev_configure(g_dpdkd_port_id, num_rx_queue, num_tx_queue, &port_conf) < 0){
        rte_exit(EXIT_FAILURE, "rte eth dev configure failed\n");
    }

    if(rte_eth_rx_queue_setup(g_dpdkd_port_id, 0/*rx id*/, 128, rte_eth_dev_socket_id(g_dpdkd_port_id)/*网卡所属物理NUMA节点*/, NULL/*接收配置*/, mbuf_pool) < 0){
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    if(rte_eth_dev_start(g_dpdkd_port_id) < 0){
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
    printf("dev start success\n");
    while(1){
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned int nb_received = rte_eth_rx_burst(g_dpdkd_port_id, 0/*rx id队列0*/, mbufs, BURST_SIZE);
        if(nb_received > BURST_SIZE){
            rte_exit(EXIT_FAILURE, "Error with rte_eth_rx burst\n");
        }
/*
+--------------+-------------+---------------------+---------------+
|    ethhdr    |    iphdr    |    udphdr/tcphdr    |    payload    |
+--------------+-------------+---------------------+---------------+
*/
        unsigned int i = 0;
        for(i = 0; i < nb_received; i++){
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            if(iphdr->next_proto_id == IPPROTO_UDP){
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
                uint16_t length = udphdr->dgram_len;
                printf("length: %d, content: %s\n", length, (char *)(udphdr + 1));
            }
        }
        sleep(1);
    }

    return 0;
}
