/******************************************************************************************************************
**ref: https://stackoverflow.com/questions/44150093/nfhook-netfilter-error-assignment-from-incompatible-pointer-type
https://www.cnblogs.com/virusolf/p/5297573.html
https://blog.csdn.net/stone8761/article/details/72821733
****************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/version.h>
 
static void
IP2Str(char *ipaddr, int size, uint32_t ip)
{
        snprintf(ipaddr, size, "%d.%d.%d.%d", ( ip >> 24 ) & 0xff
                                        , ( ip >> 16 ) & 0xff
                                        , ( ip >> 8 ) & 0xff
                                        , ip & 0xff);
}

 
unsigned int
my_hook_fun(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
        

        struct iphdr *iph;
        char ipaddr[17];

        //******************new added*************************
        printk(KERN_INFO "Packet Direction: %s-->%s\n", state->in->name, state->out==NULL?"null":state->out->name);
 
        if( unlikely(!skb) ) {
                return NF_ACCEPT;
        }
 
        iph = ip_hdr(skb);
        if( unlikely(!iph) ) {
                return NF_ACCEPT;
        }
 
        if( likely(iph->protocol != IPPROTO_ICMP) ) {
                return NF_ACCEPT;
        }
 
        memset(ipaddr, 0, sizeof(ipaddr));
        IP2Str(ipaddr, sizeof(ipaddr), ntohl(iph->saddr));
        if( strcmp(ipaddr, "100.100.100.1") == 0 ) 
        {
                printk(KERN_INFO "receive ping from 100.100.100.1\n");
        }
 
        return NF_ACCEPT;
}
 
static struct nf_hook_ops my_hook_ops = {
        .hook           = my_hook_fun,          //hook处理函数
        .pf             = PF_INET,              //协议类型
        .hooknum        = NF_BR_PRE_ROUTING,    //hook注册点
        .priority       = NF_IP_PRI_FIRST,      //优先级
};
 
static void
hello_cleanup(void)
{
        //nf_unregister_hook(&my_hook_ops);

        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
        nf_unregister_net_hook(&init_net, &my_hook_ops);
        #else
        nf_unregister_hook(&my_hook_ops);
        #endif
}
 
static __init int hello_init(void)
{
        
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
                if(nf_register_net_hook(&init_net, &my_hook_ops) !=0){
        #else
                if(nf_register_hook(&my_hook_ops) !=0){
        #endif
 
       // if ( nf_register_hook(&my_hook_ops) != 0 ) {
                printk(KERN_WARNING "register hook error!\n");
                goto err;
        }
        printk(KERN_ALERT "hello init success!\n");
        return 0;
 
err:
        hello_cleanup();
        return -1;
}
 
static __exit void hello_exit(void)
{
        hello_cleanup();
        printk(KERN_WARNING "helloworld exit!\n");
}
 
module_init(hello_init);
module_exit(hello_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("NEWPLAN");