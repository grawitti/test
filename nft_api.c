#include <string.h>
#include <nftables/libnftables.h>
#include <jansson.h>

int save_to_file(const char *file_name, const char *output)
{
    FILE *f = fopen(file_name, "w");
    if (f == NULL)
    {
        printf("cannot open file: %s\n", file_name);
        return 1;
    }
    else
    {
        fprintf(f, output);
    }
    fclose(f);
    return 0;
}

void clear_bufers(const char *buf)
{
    fflush(stdout);
    char *p = (char *)buf;
    if (strlen(p))
        memset(p, 0, strlen(p));
}

int nft_get_output(struct nft_ctx *nft)
{
    int rc = 0;
    const char *output = nft_ctx_get_output_buffer(nft);
    save_to_file("nftables.json", output);

    if (strlen(output))
    {
        printf("\nThis is the current ruleset:\n| ");
        const char *p;
        for (p = output; *(p + 1); p++)
        {
            if (*p == '\n')
                printf("\n| ");
            else
                putchar(*p);
        }
        putchar('\n');
        rc = 0;
    }
    else
    {
        printf("\nCurrent ruleset is empty.\n");
        rc - 1;
    }
    if (strlen(output))
        clear_bufers(output);

    return rc;
}

json_t *nft_json_extract_array(struct nft_ctx *nft)
{
    char list_cmd[] = "list ruleset";

    // run nft command
    if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, list_cmd, sizeof(list_cmd)))
        return NULL;

    // Get nft JSON output bufer
    const char *nft_json_out = nft_ctx_get_output_buffer(nft);

    json_error_t error;
    // parse JSON output to *root
    json_t *root = json_loads(nft_json_out, 0, &error);
    if (!root)
    {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return NULL;
    }

    json_t *nft_array;
    // Extract JSON array "nftables" to *nft_array
    if (json_unpack(root, "{so}", "nftables", &nft_array) != 0)
        return NULL;

    return nft_array;
}

// return 0 if exist table, -1 if not exist table, or error
int nft_json_is_exists(struct nft_ctx *nft, const char *family, const char *tb_name, const char *ch_name)
{
    json_t *nft_array, *value;
    if (!(nft_array = nft_json_extract_array(nft)))
        return -1;

    json_error_t error;
    size_t index;
    uint8_t ex_chain, ex_table = 0;
    ex_chain = (ch_name) ? 0 : 1;
    json_array_foreach(nft_array, index, value)
    {
        // Find table
        if (json_unpack_ex(value, &error, JSON_VALIDATE_ONLY, "{s{}}", "table") == 0)
        {
            const char *tfamily, *tname;
            json_unpack(value, "{s{s:s}}", "table", "family", &tfamily);
            json_unpack(value, "{s{s:s}}", "table", "name", &tname);
            if ((strcmp(tname, tb_name) == 0) && (strcmp(tfamily, family) == 0))
                ex_table = 1;

            continue;
        }

        // Find chain
        if (ch_name)
        {
            if (json_unpack_ex(value, &error, JSON_VALIDATE_ONLY, "{s{}}", "chain") == 0)
            {
                const char *chname, *tname, *chfamily;
                json_unpack(value, "{s{s:s}}", "chain", "family", &chfamily);
                json_unpack(value, "{s{s:s}}", "chain", "table", &tname);
                json_unpack(value, "{s{s:s}}", "chain", "name", &chname);
                if (!strcmp(chname, ch_name) && !strcmp(tname, tb_name) && !strcmp(chfamily, family))
                    ex_chain = 1;

                continue;
            }
        }
    }
    return (ex_chain && ex_table) ? 0 : -1;
}

json_t *nft_json_add_table(const char *family, const char *tb_name, json_error_t *err)
{
    return json_pack_ex(err, 0, "{s{s{s:s, s:s}}}",
                        "add", "table",
                        "family", family,
                        "name", tb_name);
}

json_t *nft_json_add_chain(const char *family,
                           const char *tb_name,
                           const char *ch_name,
                           const char *type,
                           const char *hook,
                           const uint32_t prio,
                           const char *policy,
                           json_error_t *err)
{
    return json_pack_ex(err, 0, "{s{s{s:s, s:s, s:s, s:s, s:s, s:i, s:s}}}",
                        "add", "chain",
                        "family", family,
                        "table", tb_name,
                        "name", ch_name,
                        "type", type,
                        "hook", hook,
                        "prio", prio,
                        "policy", policy);
}

json_t *nft_json_build_expr_msq(const char *oifname)
{
    json_t *nft_st_match = json_pack("{s{s{s:s}, s:s}}",
                                 "match", "left",
                                 "meta", "oifname",
                                 "right",
                                 oifname);
    json_t *nft_expr = json_array();
    if(json_array_append(nft_expr, nft_st_match) != 0){
        printf("error: building statement match\n");
        return NULL;
    }

    nft_st_match = json_pack("{s:n}", "counter");
    if(json_array_append(nft_expr, nft_st_match) != 0){
        printf("error: building statement counter\n");
        return NULL;
    }

    // nft_st_match = json_pack("{s{s:n}}", "masquerade", "random");
    // if(json_array_append(nft_expr, nft_st_match) != 0){
    //     printf("error: building statement masq\n");
    //     return NULL;
    // }

    return nft_expr;
}

json_t *nft_json_add_rule(const char *family,
                           const char *tb_name,
                           const char *ch_name,
                           const uint32_t handle,
                           json_t *expr,
                           json_error_t *err)
{
    json_t *jt_nft_rule = json_pack_ex(err , 0, "{s{s{s:s, s:s, s:s, s:i, so}}}",
                                    "add", "rule",
                                    "family", family,
                                    "table", tb_name,
                                    "chain", ch_name,
                                    "handle", handle,
                                    "expr", expr);

    // json_dumpf(jt_nft_rule, stdout, JSON_INDENT(4));

    if(!jt_nft_rule)
        printf("%s\n", err->text);

    return jt_nft_rule;
}

int main()
{
    struct nft_ctx *nft;
    int rc = 0;

    nft = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!nft)
        return -1;

    nft_ctx_output_set_json(nft, 1);

    const char *family = "ip";
    const char *tb_name = "nat";
    const char *ch_name = "POSTROUTING";
    if (nft_json_is_exists(nft, family, tb_name, NULL) != 0)
    {
        printf("not found table: %s, or chain: %s \n", tb_name, ch_name);
        return -1;
    }

    json_error_t err;
    json_t *jt_nft_array = json_array();
    json_t *jt_nft_elem = json_object();
    jt_nft_elem = nft_json_add_table("ip", "mytable", &err);
    if (json_array_append(jt_nft_array, jt_nft_elem) != 0)
    {
        fprintf(stderr, "JSON error: %s\n", err.text);
        rc = -1;
    }

    jt_nft_elem = nft_json_add_chain("ip",
                                     "mytable",
                                     "OUTPUT",
                                     "nat",
                                     "output",
                                     200,
                                     "accept",
                                     &err);
    if (json_array_append(jt_nft_array, jt_nft_elem) != 0)
    {
        fprintf(stderr, "JSON error: %s\n", err.text);
        rc = -1;
    }

    json_t *nft_expr = nft_json_build_expr_msq("enp6s0");
    if(!nft_expr)
        return -1;

    jt_nft_elem = nft_json_add_rule("ip",
                                     "mytable",
                                     "OUTPUT",
                                     11,
                                     nft_expr,
                                     &err);

    if (json_array_append(jt_nft_array, jt_nft_elem) != 0)
    {
        fprintf(stderr, "JSON error: %s\n", err.text);
        rc = -1;
    }

    json_t *root = json_object();
    json_object_set(root, "nftables", jt_nft_array);

    json_dumpf(root, stdout, JSON_INDENT(4));
    json_dump_file(root, "nftables.json", JSON_INDENT(4));

    char *list_cmd = json_dumps(root, 0);

    if (rc == 0)
    {
        if (nft_ctx_buffer_output(nft) || nft_run_cmd_from_buffer(nft, list_cmd, 0))
            return -1;

        if (rc != 1)
            nft_get_output(nft);
    }

    nft_ctx_unbuffer_output(nft);
    nft_ctx_free(nft);
    return 0;
}