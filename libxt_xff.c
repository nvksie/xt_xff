#define _GNU_SOURCE 1 /* strnlen for older glibcs */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <xtables.h>
#include <linux/netfilter/xt_string.h>

#include "xff_info.h"

enum {
	O_FROM = 0,
	O_TO,
	O_ALGO,
	O_ICASE,
	O_CIDR,
	O_REPLACE_SRC,
	F_CIDR        = 1 << O_CIDR,
};

static void xff_help(void)
{
	printf(
"xff match options:\n"
"--from                       Offset to start searching from\n"
"--to                         Offset to stop searching\n"
"--algo                       Algorithm\n"
"--icase                      Ignore case for X-Forwarded-For (default: 0)\n"
"[!] --cidr string            Match xff ip block in a packet\n"
"--fsrc                       replace src with X-Forwarded-For\n");
}

#define s struct xt_string_info
static const struct xt_option_entry xff_opts[] = {
	{.name = "from", .id = O_FROM, .type = XTTYPE_UINT16,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, from_offset)},
	{.name = "to", .id = O_TO, .type = XTTYPE_UINT16,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, to_offset)},
	{.name = "algo", .id = O_ALGO, .type = XTTYPE_STRING,
	 .flags = XTOPT_MAND | XTOPT_PUT, XTOPT_POINTER(s, algo)},
	{.name = "cidr", .id = O_CIDR, .type = XTTYPE_STRING,
	 .flags = XTOPT_INVERT},
	{.name = "fsrc", .id = O_REPLACE_SRC, .type = XTTYPE_NONE},
	{.name = "icase", .id = O_ICASE, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};
#undef s

static void xff_init(struct xt_entry_match *m)
{
	struct xt_string_info *i = (struct xt_string_info *) m->data;
	i->to_offset = UINT16_MAX;
}

static void
parse_cidr(const char *s, struct xt_string_info *info)
{	
	unsigned ip[4],mask;
	int ret;

	ret = sscanf(s, "%u.%u.%u.%u/%u",
				&ip[0],
				&ip[1],
				&ip[2],
				&ip[3], &mask);
	if(ret == 4) {
		info->pattern[0] = 32;
	} else if(ret == 5 && mask > 0 && mask <= 32 &&
		ip[0] < 256 &&
		ip[1] < 256 &&
		ip[2] < 256 &&
		ip[3] < 256) {
		info->pattern[0] = mask;
	} else {
		xtables_error(PARAMETER_PROBLEM, "invalid cidr format \"%s\"", s);
	}
	info->pattern[4] = ip[0];
	info->pattern[3] = ip[1];
	info->pattern[2] = ip[2];
	info->pattern[1] = ip[3];
	info->patlen = 5;
}



static void xff_parse(struct xt_option_call *cb)
{
	struct xt_string_info *stringinfo = cb->data;
	const unsigned int revision = (*cb->match)->u.user.revision;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_CIDR:
		parse_cidr(cb->arg, stringinfo);
		if (cb->invert) {
			if (revision == 0)
				stringinfo->u.v0.invert = 1;
			else
				stringinfo->u.v1.flags |= XT_STRING_FLAG_INVERT;
		}
		break;
	case O_REPLACE_SRC:
		stringinfo->u.v1.flags |= XT_XFF_FLAG_REPLACE_SRC;
		break;
	case O_ICASE:
		if (revision == 0)
			xtables_error(VERSION_PROBLEM,
				   "Kernel doesn't support ignore case");
		else
			stringinfo->u.v1.flags |= XT_STRING_FLAG_IGNORECASE;
		break;
	}
}

static void xff_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_CIDR))
		xtables_error(PARAMETER_PROBLEM,
			   "xff match: You must specify `--cidr'");
}


static void
print_cidr(const char *str, const unsigned short int len)
{
	unsigned int i;
	printf("%u.%u.%u.%u", (unsigned char)str[4],(unsigned char)str[3],(unsigned char)str[2],(unsigned char)str[1]);
	if(str[0] < 32 && str[0] > 0)
		printf("/%u", (unsigned char)str[0]);
}

static void
xff_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	const struct xt_string_info *info =
	    (const struct xt_string_info*) match->data;
	const int revision = match->u.user.revision;
	int invert = (revision == 0 ? info->u.v0.invert :
				    info->u.v1.flags & XT_STRING_FLAG_INVERT);

	printf(" xff match %s", invert ? "!" : "");
	print_cidr(info->pattern, info->patlen);
	printf(" ALGO %s", info->algo);
	if (info->from_offset != 0)
		printf(" FROM %u", info->from_offset);
	if (info->to_offset != 0)
		printf(" TO %u", info->to_offset);
	if (revision > 0 && info->u.v1.flags & XT_STRING_FLAG_IGNORECASE)
		printf(" ICASE");
	if (info->u.v1.flags & XT_XFF_FLAG_REPLACE_SRC)
		printf(" REPLACE_SRC");
}

static void xff_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_string_info *info =
	    (const struct xt_string_info*) match->data;
	const int revision = match->u.user.revision;
	int invert = (revision == 0 ? info->u.v0.invert :
				    info->u.v1.flags & XT_STRING_FLAG_INVERT);

	printf("%s --cidr ", (invert) ? " !": "");
	print_cidr(info->pattern, info->patlen);
	printf(" --algo %s", info->algo);
	if (info->from_offset != 0)
		printf(" --from %u", info->from_offset);
	if (info->to_offset != 0)
		printf(" --to %u", info->to_offset);
	if (revision > 0 && info->u.v1.flags & XT_STRING_FLAG_IGNORECASE)
		printf(" --icase");
	if (info->u.v1.flags & XT_XFF_FLAG_REPLACE_SRC)
		printf(" --fsrc");
}


static struct xtables_match xff_mt_reg[] = {
	{
		.name          = "xff",
		.revision      = 0,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_string_info)),
		.userspacesize = offsetof(struct xt_string_info, config),
		.help          = xff_help,
		.init          = xff_init,
		.print         = xff_print,
		.save          = xff_save,
		.x6_parse      = xff_parse,
		.x6_fcheck     = xff_check,
		.x6_options    = xff_opts,
	},
	{
		.name          = "xff",
		.revision      = 1,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_string_info)),
		.userspacesize = offsetof(struct xt_string_info, config),
		.help          = xff_help,
		.init          = xff_init,
		.print         = xff_print,
		.save          = xff_save,
		.x6_parse      = xff_parse,
		.x6_fcheck     = xff_check,
		.x6_options    = xff_opts,
	},
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

void _init(void)
{
	xtables_register_matches(xff_mt_reg, ARRAY_SIZE(xff_mt_reg));
}
