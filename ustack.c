#include <stdio.h>
#include <rte_eal.h>    /*DPDK环境抽象层*/
#include <rte_ethdev.h> /*DPDK网卡抽象层*/
#include <arpa/inet.h>  /*网络地址转换*/
#include <rte_ether.h>  /*以太网协议*/
#include <unistd.h>     /*posix系统调用如sleep*/

int g_dpdkd_port_id = 0; /*默认使用网卡端口0，端口0代表系统中的第一个可用网卡，
                            DPDK为每个绑定的网卡分配从0开始的连续ID*/
static const struct rte_eth_conf port_conf_default = { 
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN} /*设置最大接受包长度
                                                        1518字节，标准以太网帧*/
};
/*
+-----------------+--------------+---------------+--------------------+-------------+
|目的MAC地址(6字节)|源MAC地址(6字节)|以太网类型(2字节)|IP数据包(46-1500字节)|CRC校验(4字节)|
+-----------------+--------------+---------------+--------------------+------------+
长度/类型： 2 个字节（16 位）。

如果值 ≤ 1500：表示 长度，即后面“数据”字段包含的字节数。

如果值 ≥ 1536：表示 类型，即封装在“数据”字段中的上层协议是什么
（例如：0x0800 表示 IPv4，0x0806 表示 ARP，0x86DD 表示 IPv6）。这是最常见的情况。
*/

/*NUM_MBUFS定义了内存池rte_mempool中预分配的rte_mbuf结构体的总数量
*rte_mbuf是DPDK中用于描述数据包的缓冲区结构体，每个rte_mbuf结构体
*都包含一个缓冲区指针，指向实际存储数据包的内存区域，以及一些用于管理
*缓冲区的元数据，如缓冲区大小、缓冲区状态等。
*数据缓冲区大小由data_room_size参数指定，默认为2048字节
*/
#define NUM_MBUFS     2048  /*内存池缓冲区数量，就像内存池停车场的总车位*/

/*这个宏定义了DPDK应用从RX队列中一次轮询尝试读取的最大数据包的数量*/
#define BURST_SIZE     128  /*一次接收/发送的缓冲区数量，每次最多能进停车场的车辆数*/

#if 0
int main(int argc, char *argv[])
{
    // 初始化DPDK环境
    /*初始化Environment Abstraction Layer （EAL）*/
    if(rte_eal_init(argc, argv) < 0){
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    /*获取可用网卡数量*/
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0){
        rte_exit(EXIT_FAILURE, "No support eth found\n");
    }

    printf("nb_sys_ports: %d\n", nb_sys_ports);

    /*创建内存池*/
    /*
    *   rte_pktmbuf_pool_create()函数用于创建一个内存池，该内存池用于存储rte_mbuf结构体
    *   rte_mbuf结构体是DPDK中用于描述数据包的缓冲区结构体，每个rte_mbuf结构体
    *   都包含一个缓冲区指针，指向实际存储数据包的内存区域，以及一些用于管理
    *   缓冲区的元数据，如缓冲区大小、缓冲区状态等。
    *   数据缓冲区大小由data_room_size参数指定，默认为2048字节
    *   mbuf_pool参数指定了内存池的名称，这个名称在后续的代码中可以用来引用这个内存池。
    *   cache_size参数指定了每个CPU核心的缓存大小，这个参数可以用来优化内存池的性能， 0表示禁用缓存。
    *   private_size参数指定了每个rte_mbuf结构体中私有数据的大小，这个参数可以用来存储一些额外的信息， 0表示禁用私有数据。
    *   RTE_MBUF_DEFAULT_BUF_SIZE参数指定了每个缓冲区的默认大小（2048 + 128）字节，128位dpdk mbuf头部开销
    *   rte_socket_id()函数用于获取当前线程所在的NUMA节点，然后在该节点上分配内存池
    */
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", NUM_MBUFS, 0/*cache size*/, 0/*private size*/, RTE_MBUF_DEFAULT_BUF_SIZE/*pkt_room_size*/, rte_socket_id()/* `rte_socket_id()` 来获取当前线程所在的NUMA节点，然后在该节点上分配内存池*/);
    if(!mbuf_pool){
        rte_exit(EXIT_FAILURE, "Could not create mbuf_pool\n");
    }

    /*获取网卡信息*/
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(g_dpdkd_port_id, &dev_info);

    /*配置网卡*/
    const int num_rx_queue = 1; /*网卡接收队列数量*/
    const int num_tx_queue = 0; /*0个发送队列数量，纯接收应用*/
    struct rte_eth_conf port_conf = port_conf_default; /*使用默认配置*/

    /*配置网卡端口*/
    if(rte_eth_dev_configure(g_dpdkd_port_id, num_rx_queue, num_tx_queue, &port_conf) < 0){
        rte_exit(EXIT_FAILURE, "rte eth dev configure failed\n");
    }

    /*配置网卡接收队列*/
    /*rte_eth_rx_queue_setup()函数用于配置网卡接收队列，该函数会为指定的网卡端口和接收队列分配内存，并设置接收队列的参数。*/
    /*rte_eth_dev_socket_id(g_dpdkd_port_id)函数用于获取网卡所属的物理NUMA节点，然后在该节点上分配内存池*/
    /*mbuf_pool参数指定了用于存储接收到的数据包的内存池，这个内存池是在前面创建的。*/
    if(rte_eth_rx_queue_setup(g_dpdkd_port_id, 0/*rx id*/, 128, rte_eth_dev_socket_id(g_dpdkd_port_id)/*网卡所属物理NUMA节点*/, NULL/*接收配置*/, mbuf_pool) < 0){
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    /*启动网卡*/
    if(rte_eth_dev_start(g_dpdkd_port_id) < 0){
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
    printf("dev start success\n");
    while(1){
        /*报文缓冲区数组*/
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned int nb_received = rte_eth_rx_burst(g_dpdkd_port_id, 0/*rx id队列0*/, mbufs, BURST_SIZE);
        /*不应超过请求数量*/
        if(nb_received > BURST_SIZE){
            rte_exit(EXIT_FAILURE, "Error with rte_eth_rx burst\n");
        }
/*
+--------------+-------------+---------------------+---------------+
|    ethhdr    |    iphdr    |    udphdr/tcphdr    |    payload    |
+--------------+-------------+---------------------+---------------+
+---------------+---------------+------------------+---------------+
| Ethernet Header|  IPv4 Header  |    UDP Header    |    Payload    |
+---------------+---------------+------------------+---------------+
| 14 bytes      | 20 bytes      | 8 bytes          | N bytes       |
+---------------+---------------+------------------+---------------+
^               ^               ^                  ^
|               |               |                  |
ehdr            iphdr           udphdr             payload
(rte_pktmbuf_mtod) (rte_pktmbuf_mtod_offset) (iphdr+1)       (udphdr+1)
*/
        unsigned int i = 0;
        /*处理每个收到的包*/
        for(i = 0; i < nb_received; i++){
            /*获取以太网头，rte_pktmbuf_mtod将mbuf转化为参数指定的数据结构*/
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            /*检查是否为IPV4包*/
            /*rte_cpu_to_be_16就是将16位主机字节序转换为网络字节序*/
            if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
                continue;
            }

            /*rte_pktmbuf_mtod_offset是带偏移量的mbuf转换宏
            *参数1：mbuf指针
            *参数2：目标数据结构类型
            *参数3：偏移量
            */
            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            /*next_proto_id：IP头中的协议类型字段（1字节）*/
            if(iphdr->next_proto_id == IPPROTO_UDP){
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);/*跳过IP头，获取UDP头起始位置*/
                uint16_t length = udphdr->dgram_len; /*获取UDP数据包长度*/
                printf("length: %d, content: %s\n", length, (char *)(udphdr + 1)); /*获取UDP数据部分起始位置并打印*/
            }
        }
        sleep(1);
    }

    return 0;
}
#else
typedef void (*packet_handler_fn)(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf);

struct protocol_handler{
    packet_handler_fn handler;
};

#define ENABLE_SEND 1

#if ENABLE_SEND
uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];

uint32_t g_src_ip;
uint32_t g_dst_ip;

uint16_t g_src_port;
uint16_t g_dst_port;
#endif

int ustack_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t length)
{
    struct rte_ether_hdr *ehdr = (struct rte_ether_hdr *)msg;
    rte_memcpy(ehdr->s_addr, g_src_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ehdr->d_addr, g_dst_mac, RTE_ETHER_ADDR_LEN);
    ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    /*字段解释：
    Version（版本）：4位字段，表示IP协议的版本。IPv4的版本号是4，IPv6的版本号是6。
    IHL（Internet Header Length）：4位字段，表示IP头的长度，以32位字为单位。最小值是5（20字节），
    最大值是15,代表15个32字节（60字节）。
    Type of Service（服务类型）：8位字段，用于指定数据包的优先级和服务质量。
    Total Length（总长度）：16位字段，表示整个IP数据包的总长度，包括IP头和数据部分，以字节为单位。
    Identification（标识）：16位字段，用于标识数据包的标识符，通常用于分片和重组。
    Flags（标志）：3位字段，用于控制分片行为。包括是否允许分片（DF）和是否为最后一个分片（MF）。
    Fragment Offset（片偏移）：13位字段，表示分片在原始数据包中的偏移量。
    TTL（生存时间）：8位字段，表示数据包在网络中的最大生存时间，以跳数为单位。
    Protocol（协议）：8位字段，表示数据包的上层协议类型，如TCP（6）、UDP（17）等。
    Header Checksum（头部校验和）：16位字段，用于校验IP头的完整性。
    Source Address（源地址）：32位字段，表示数据包的源IP地址。
    Destination Address（目的地址）：32位字段，表示数据包的目的IP地址。
    Options（选项）：可变长度字段，用于提供额外的选项，如路由信息等。
    Padding（填充）：用于确保IP头的长度是32位的倍数。*/
    iphdr->version_ihl = 0x45;/*版本4，头部长度20字节*/
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(length - sizeof(struct rte_ether_hdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->time_to_live = 64;
    iphdr->header_checksum = 0;
    iphdr->dst_addr = g_dst_ip;
    iphdr->src_addr = g_src_ip;
    iphdr->header_checksum = rte_ipv4_cksum(iphdr);

    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udphdr->src_port = g_src_port;
    udphdr->dst_port = g_dst_port;
    uint16_t udp_len = length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udphdr->dgram_len = htons(udp_len);
    rte_memcpy((char*)(udphdr + 1), data, udp_len - sizeof(struct rte_udp_hdr));
    
    udphdr->dgram_cksum = 0;
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);
    return length;
}

struct rte_mbuf* ustack_send(struct rte_mempool *mbuf_pool, unsigned char *data, uint16_t length)
{
    const unsigned total_length = length + sizeof(struct rte_ether_hdr) + 
    sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(*mbuf_pool);

    if(mbuf == NULL){
        rte_exit(EXIT_FAILURE, "rte pktmbuf alloc failed\n");
    }

    mbuf.pkt_len = total_length;
    mbuf.data_len = length;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    ustack_encode_udp_pkt(pktdata, data, total_length);

    return mbuf;
}

static void udp_handler_fun(struct rte_mempool *mbuf_pool, struct rte_mbuf *mbuf)
{
    /*获取以太网头，rte_pktmbuf_mtod将mbuf转化为参数指定的数据结构*/
    struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    /*检查是否为IPV4包*/
    /*rte_cpu_to_be_16就是将16位主机字节序转换为网络字节序*/
    if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
        return;
    }

    /*rte_pktmbuf_mtod_offset是带偏移量的mbuf转换宏
    *参数1：mbuf指针
    *参数2：目标数据结构类型
    *参数3：偏移量
    */
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    /*next_proto_id：IP头中的协议类型字段（1字节）*/
    if(iphdr->next_proto_id == IPPROTO_UDP){
        struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);/*跳过IP头，获取UDP头起始位置*/
        uint16_t length = udphdr->dgram_len; /*获取UDP数据包长度*/
        printf("length: %d, content: %s\n", length, (char *)(udphdr + 1)); /*获取UDP数据部分起始位置并打印*/
        /*这里length是网络字节序，实际数值为udp头8字节加数据长度*/
        uint16_t length = ntohs(udphdr->dgram_len) - sizeof(struct rte_udp_hdr);
        
#if ENABLE_SEND
        /*发送回包*/
        rte_memcpy(g_dst_mac, ehdr->s_addr, RTE_ETHER_ADDR_LEN);
        rte_memcpy(g_src_mac, ehdr->d_addr, RTE_ETHER_ADDR_LEN);
        rte_memcpy(&g_dst_ip, iphdr->src_addr, sizeof(uint32_t));
        rte_memcpy(&g_src_ip, iphdr->dst_addr, sizeof(uint32_t));
        rte_memcpy(&g_dst_port, &udphdr->dst_port, sizeof(uint16_t));
        rte_memcpy(&g_src_port, &udphdr->src_port, sizeof(uint16_t));
        ustack_send(mbuf_pool, (char *)(udphdr + 1), length);
        
#endif
    
    }
}

struct protocol_handler udp_handler = {
    .handler = udp_handler_fun,
};

#define MAX_HANDLERS 10
static struct protocol_handler *handlers[MAX_HANDLERS];
static int handler_count = 0;

void register_handler(struct protocol_handler *handler)
{
    if(handler_count < MAX_HANDLERS){
        handlers[handler_count++] = handler;
    }
}

void process_packet(struct rte_mempool *mbuf_pool, struct rte_mbuf **mbufs, uint16_t num_packets)
{
    for(int i = 0; i < num_packets; i++){
        for(int h = 0; h < handler_count; h++){
            handlers[h]->handler(mbuf_pool, mbufs[i]);
        }
        rte_pktmbuf_free(mbufs[i]);
    }
}

void init_dpdk(int argc, char*argv[], struct rte_mempool **mbuf_pool)
{
    // 初始化DPDK环境
    /*初始化Environment Abstraction Layer （EAL）*/
    if(rte_eal_init(argc, argv) < 0){
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    /*获取可用网卡数量*/
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0){
        rte_exit(EXIT_FAILURE, "No support eth found\n");
    }

    printf("nb_sys_ports: %d\n", nb_sys_ports);

    /*创建内存池*/
    /*
    *   rte_pktmbuf_pool_create()函数用于创建一个内存池，该内存池用于存储rte_mbuf结构体
    *   rte_mbuf结构体是DPDK中用于描述数据包的缓冲区结构体，每个rte_mbuf结构体
    *   都包含一个缓冲区指针，指向实际存储数据包的内存区域，以及一些用于管理
    *   缓冲区的元数据，如缓冲区大小、缓冲区状态等。
    *   数据缓冲区大小由data_room_size参数指定，默认为2048字节
    *   mbuf_pool参数指定了内存池的名称，这个名称在后续的代码中可以用来引用这个内存池。
    *   cache_size参数指定了每个CPU核心的缓存大小，这个参数可以用来优化内存池的性能， 0表示禁用缓存。
    *   private_size参数指定了每个rte_mbuf结构体中私有数据的大小，这个参数可以用来存储一些额外的信息， 0表示禁用私有数据。
    *   RTE_MBUF_DEFAULT_BUF_SIZE参数指定了每个缓冲区的默认大小（2048 + 128）字节，128位dpdk mbuf头部开销
    *   rte_socket_id()函数用于获取当前线程所在的NUMA节点，然后在该节点上分配内存池
    */
    *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", NUM_MBUFS, 0/*cache size*/, 0/*private size*/, RTE_MBUF_DEFAULT_BUF_SIZE/*pkt_room_size*/, rte_socket_id()/* `rte_socket_id()` 来获取当前线程所在的NUMA节点，然后在该节点上分配内存池*/);
    if(!mbuf_pool){
        rte_exit(EXIT_FAILURE, "Could not create mbuf_pool\n");
    }

    /*获取网卡信息*/
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(g_dpdkd_port_id, &dev_info);

    /*配置网卡*/
    const int num_rx_queue = 1; /*网卡接收队列数量*/
    const int num_tx_queue = 0; /*0个发送队列数量，纯接收应用*/
    struct rte_eth_conf port_conf = port_conf_default; /*使用默认配置*/

    /*配置网卡端口*/
    if(rte_eth_dev_configure(g_dpdkd_port_id, num_rx_queue, num_tx_queue, &port_conf) < 0){
        rte_exit(EXIT_FAILURE, "rte eth dev configure failed\n");
    }

    /*配置网卡接收队列*/
    /*rte_eth_rx_queue_setup()函数用于配置网卡接收队列，该函数会为指定的网卡端口和接收队列分配内存，并设置接收队列的参数。*/
    /*rte_eth_dev_socket_id(g_dpdkd_port_id)函数用于获取网卡所属的物理NUMA节点，然后在该节点上分配内存池*/
    /*mbuf_pool参数指定了用于存储接收到的数据包的内存池，这个内存池是在前面创建的。*/
    if(rte_eth_rx_queue_setup(g_dpdkd_port_id, 0/*rx id*/, 128, rte_eth_dev_socket_id(g_dpdkd_port_id)/*网卡所属物理NUMA节点*/, NULL/*接收配置*/, mbuf_pool) < 0){
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    /*启动网卡*/
    if(rte_eth_dev_start(g_dpdkd_port_id) < 0){
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

void init_application()
{
    register_handler(&udp_handler);
}

int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    init_dpdk(argc, argv, &mbuf_pool);
    init_application();
    while(1){
        struct rte_mbuf *mbufs[BURST_SIZE];
        /*
        "burst"的含义：
        突发接收：一次性尝试从网卡接收多个数据包（而不是单个包）
        批处理：减少系统调用/硬件交互次数，提高吞吐量
        零拷贝：数据直接从NIC（网卡）DMA到内存，避免内核拷贝
        */
         unsigned int nb_received = rte_eth_rx_burst(g_dpdkd_port_id, 0/*rx id队列0*/, mbufs, BURST_SIZE);
        /*不应超过请求数量*/
        if(nb_received > BURST_SIZE){
            rte_exit(EXIT_FAILURE, "Error with rte_eth_rx burst\n");
        }
        process_packet(mbuf_pool, mbufs, nb_received);
    }
    return 0;
}
#endif
