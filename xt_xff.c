#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_string.h>
#include <linux/textsearch.h>

#include <linux/ip.h>
#include <linux/tcp.h>

#include "xff_info.h"

MODULE_AUTHOR("Dyluck <cz@de3eb.cn>");
MODULE_DESCRIPTION("Xtables: http X-Forwarded-For matching");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_xff");
MODULE_ALIAS("ip6t_xff");

#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr) \
  ((unsigned char *)&addr)[0],                  \
    ((unsigned char *)&addr)[1],                \
    ((unsigned char *)&addr)[2],                \
    ((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr)                            \
  ((unsigned char *)&addr)[3],                  \
    ((unsigned char *)&addr)[2],                \
    ((unsigned char *)&addr)[1],                \
    ((unsigned char *)&addr)[0]
#endif

#define TS_SKB_CB(state)	((struct skb_seq_state *) &((state)->cb))
static bool
xff_match(struct sk_buff *skb, const struct xt_string_info *conf,
			struct ts_state *state) {
	int offset,from = conf->from_offset, to = conf->to_offset;
	int len,i,n,mbit;
	u8 ch;
	unsigned int ipn = 0, *pipn;
	bool matched = false;
	u8 const *data = NULL;

	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr*)(((void*)iph) + (iph->ihl << 2));
	printk(KERN_INFO "# xff match %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d\n", IPQUAD(iph->saddr), ntohs(tcph->source), IPQUAD(iph->daddr), ntohs(tcph->dest));

	offset = skb_find_text(skb, from,
			     to, conf->config);//, state);
	if(offset == UINT_MAX)
		return matched;

	memset(state, 0, sizeof(struct ts_state));
	offset += 17; // length of 'X-Forwarded-For: '
	skb_prepare_seq_read(skb, from+offset, from+offset+16, TS_SKB_CB(state));
	len = skb_seq_read(0, &data, TS_SKB_CB(state));
	for(i=0,n=0;i<len;i++) {
		ch = *(data + i);
		if (ch >= '0' && ch <= '9') {
			n = n*10 + (ch - '0');
		} else if (ch == '.' && n < 256) {
			ipn = ipn*256 + n;
			n = 0;
		} else if(ch == ' '){
			continue;
		} else {
			break;
		}
	}
	ipn = ipn*256 + n;
	if(conf->u.v1.flags & XT_XFF_FLAG_REPLACE_SRC) {
		iph->saddr = ((unsigned char *)&ipn)[0]<<24|((unsigned char *)&ipn)[1]<<16|((unsigned char *)&ipn)[2]<<8|((unsigned char *)&ipn)[3];
		printk(KERN_INFO "# copy xff %u.%u.%u.%u into src\n", IPQUAD(iph->saddr));
	}
	if(data != NULL && len > 0 && conf->patlen == 5) {
		mbit = 32-conf->pattern[0];
		pipn = (unsigned *)&conf->pattern[1];
		printk(KERN_INFO "# xff match: block:0x%08x target:0x%08x mbit:%d\n", *pipn, ipn, mbit);
		if(((*pipn)>>mbit) == (ipn>>mbit))
			matched = true;
		printk(KERN_INFO "# xff match: datalen:%d iplen:%d ip:'%.*s' %s\n", len, i, i, data,matched?"hit":"pass");
	}
	skb_abort_seq_read(TS_SKB_CB(state));
	return matched;
}

static bool
xff_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_string_info *conf = par->matchinfo;
	struct ts_state state;
	bool invert;

	memset(&state, 0, sizeof(struct ts_state));
	invert = conf->u.v1.flags & XT_STRING_FLAG_INVERT;

	return xff_match((struct sk_buff *)skb, conf, &state) ^ invert;
}

#define STRING_TEXT_PRIV(m) ((struct xt_string_info *)(m))

static int xff_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_string_info *conf = par->matchinfo;
	struct ts_config *ts_conf;
	char *xffpattern = "X-Forwarded-For: ";
	int flags = TS_AUTOLOAD;

	/* Damn, can't handle this case properly with iptables... */
	if (conf->from_offset > conf->to_offset)
		return -EINVAL;
	if (conf->algo[XT_STRING_MAX_ALGO_NAME_SIZE - 1] != '\0')
		return -EINVAL;
	if (conf->patlen != 5)
		return -EINVAL;
	if (conf->pattern[0] > 32 || conf->pattern[0] <= 0)
		return -EINVAL;
	if (conf->u.v1.flags &
	    ~(XT_STRING_FLAG_IGNORECASE | XT_STRING_FLAG_INVERT | XT_XFF_FLAG_CIDR | XT_XFF_FLAG_REPLACE_SRC))
		return -EINVAL;
	if (conf->u.v1.flags & XT_STRING_FLAG_IGNORECASE)
		flags |= TS_IGNORECASE;
	ts_conf = textsearch_prepare(conf->algo, xffpattern, strlen(xffpattern),
				     GFP_KERNEL, flags);

	if (IS_ERR(ts_conf))
		return PTR_ERR(ts_conf);

	conf->config = ts_conf;
	return 0;
}

static void xff_mt_destroy(const struct xt_mtdtor_param *par)
{
	textsearch_destroy(STRING_TEXT_PRIV(par->matchinfo)->config);
}

static struct xt_match xt_xff_mt_reg __read_mostly = {
	.name       = "xff",
	.revision   = 1,
	.family     = NFPROTO_UNSPEC,
	.checkentry = xff_mt_check,
	.match      = xff_mt,
	.destroy    = xff_mt_destroy,
	.matchsize  = sizeof(struct xt_string_info),
	.me         = THIS_MODULE,
};

static int __init xff_mt_init(void)
{
	printk(KERN_INFO "# xff match init.\n");
	return xt_register_match(&xt_xff_mt_reg);
}

static void __exit xff_mt_exit(void)
{
	printk(KERN_INFO "# xff match exit.\n");
	xt_unregister_match(&xt_xff_mt_reg);
}

module_init(xff_mt_init);
module_exit(xff_mt_exit);
