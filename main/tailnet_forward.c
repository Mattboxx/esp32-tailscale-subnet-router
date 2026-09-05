#include "tailnet_forward.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/inet.h"
#include "lwip/ip4.h"
#include "lwip/prot/ip.h"
#include "microlink.h"
#include "nvs.h"
#include "nvs_params.h"
#include "portmap.h"
#include "tailscale_config.h"
#include "netif_hooks.h"
#include "web_ui.h"

#define NVS_KEY "tn_fwd"
#define STORE_MAGIC 0x544e4631u

typedef struct { uint32_t magic; tailnet_forward_rule_t rules[TAILNET_FORWARD_MAX]; } store_t;
static tailnet_forward_rule_t s_rules[TAILNET_FORWARD_MAX];
static tailnet_forward_runtime_t s_runtime[TAILNET_FORWARD_MAX];
static int s_count;
static bool s_loaded;
static SemaphoreHandle_t s_lock;
#define LOCK() do { if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY); } while (0)
#define UNLOCK() do { if (s_lock) xSemaphoreGive(s_lock); } while (0)

static bool cgnat(uint32_t hbo) { return (hbo & 0xffc00000u) == 0x64400000u; }
static bool hostname_valid(const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (!n || n >= TAILNET_FORWARD_DEST_LEN) return false;
    for (size_t i=0;i<n;i++) if (!(isalnum((unsigned char)s[i]) || s[i]=='-' || s[i]=='.')) return false;
    return s[0]!='.' && s[n-1]!='.';
}

esp_err_t tailnet_forward_parse_cidr(const char *text, uint32_t *network, uint8_t *prefix) {
    if (!text || !network || !prefix) return ESP_ERR_INVALID_ARG;
    char copy[32]; strlcpy(copy,text,sizeof copy); char *slash=strchr(copy,'/');
    if (!slash) return ESP_ERR_INVALID_ARG;
    *slash++=0;
    char *end=NULL; long p=strtol(slash,&end,10); ip4_addr_t a;
    if (!*slash || *end || p<0 || p>32 || !ip4addr_aton(copy,&a)) return ESP_ERR_INVALID_ARG;
    uint32_t h=lwip_ntohl(a.addr), mask=p==0?0:(p==32?0xffffffffu:0xffffffffu<<(32-p));
    *network=h&mask; *prefix=(uint8_t)p; return ESP_OK;
}
void tailnet_forward_format_cidr(uint32_t n,uint8_t p,char *out,size_t z) {
    snprintf(out,z,"%u.%u.%u.%u/%u",(unsigned)(n>>24),(unsigned)((n>>16)&255),(unsigned)((n>>8)&255),(unsigned)(n&255),p);
}

static bool resolve_rule(int i) {
    tailnet_forward_rule_t *r=&s_rules[i]; tailnet_forward_runtime_t *rt=&s_runtime[i];
    uint32_t previous=rt->resolved_ip; bool was_installed=rt->installed;
    rt->error[0]=0;
    if (!r->enabled) { rt->resolved_ip=0;rt->installed=false;strlcpy(rt->error,"disabled",sizeof rt->error);return false; }
    if (!tailscale_connected || !tailscale_get_microlink()) { rt->resolved_ip=0;rt->installed=false;strlcpy(rt->error,"Tailnet offline",sizeof rt->error);return false; }
    ip4_addr_t a; uint32_t h=0;
    if (ip4addr_aton(r->destination,&a)) h=lwip_ntohl(a.addr);
    else { microlink_t *ml=tailscale_get_microlink(); if (!tailscale_connected || !ml) { rt->resolved_ip=0;rt->installed=false;strlcpy(rt->error,"Tailnet offline",sizeof rt->error);return false; } h=microlink_resolve(ml,r->destination); }
    if (!cgnat(h)) { rt->resolved_ip=0;rt->installed=false;strlcpy(rt->error,"not a Tailnet IPv4 address",sizeof rt->error);return false; }
    rt->resolved_ip=h;rt->installed=(previous==h)&&was_installed;return true;
}
static void manager(void *arg) {
    (void)arg;
    for (;;) {
        bool changed=false;
        LOCK();
        for(int i=0;i<s_count;i++){uint32_t old=s_runtime[i].resolved_ip;resolve_rule(i);if(old!=s_runtime[i].resolved_ip)changed=true;}
        UNLOCK();
        netif_hooks_refresh(); if(changed)portmap_install_all(); vTaskDelay(pdMS_TO_TICKS(3000));
    }
}
void tailnet_forward_init(void) {
    if(s_loaded)return;
    if(!s_lock)s_lock=xSemaphoreCreateMutex();
    memset(s_rules,0,sizeof s_rules);memset(s_runtime,0,sizeof s_runtime);
    store_t st={0};size_t len=sizeof st;nvs_handle_t nvs;
    if(nvs_open(NVS_NAMESPACE,NVS_READONLY,&nvs)==ESP_OK){if(nvs_get_blob(nvs,NVS_KEY,&st,&len)==ESP_OK&&len==sizeof st&&st.magic==STORE_MAGIC){memcpy(s_rules,st.rules,sizeof s_rules);for(int i=0;i<TAILNET_FORWARD_MAX;i++)if(s_rules[i].valid)s_count++;}nvs_close(nvs);}
    s_loaded=true;xTaskCreate(manager,"tn_forward",4096,NULL,4,NULL);
}
int tailnet_forward_count(void){if(!s_loaded)tailnet_forward_init();LOCK();int n=s_count;UNLOCK();return n;}
bool tailnet_forward_get(int i,tailnet_forward_rule_t *r,tailnet_forward_runtime_t *rt){if(!s_loaded)tailnet_forward_init();LOCK();bool ok=i>=0&&i<s_count&&s_rules[i].valid;if(ok){if(r)*r=s_rules[i];if(rt)*rt=s_runtime[i];}UNLOCK();return ok;}
bool tailnet_forward_listen_conflicts(uint8_t proto,uint16_t port){LOCK();bool found=false;for(int i=0;i<s_count;i++)if(s_rules[i].valid&&s_rules[i].enabled&&s_rules[i].proto==proto&&s_rules[i].listen_port==port){found=true;break;}UNLOCK();return found;}

esp_err_t tailnet_forward_set_all(const tailnet_forward_rule_t *rules,int count,char *error,size_t en) {
    if(!rules||count<0||count>TAILNET_FORWARD_MAX)return ESP_ERR_INVALID_ARG;
    for(int i=0;i<count;i++){
        const tailnet_forward_rule_t *r=&rules[i];
        if(!r->valid||(r->proto!=6&&r->proto!=17)||!r->listen_port||!r->destination_port||r->source_prefix>32||!hostname_valid(r->destination)){if(error)snprintf(error,en,"Invalid rule %d",i+1);return ESP_ERR_INVALID_ARG;}
        ip4_addr_t a;if(ip4addr_aton(r->destination,&a)&&!cgnat(lwip_ntohl(a.addr))){if(error)snprintf(error,en,"Rule %d destination must be in 100.64.0.0/10",i+1);return ESP_ERR_INVALID_ARG;}
        for(int j=0;j<i;j++)if(rules[j].enabled&&r->enabled&&rules[j].proto==r->proto&&rules[j].listen_port==r->listen_port){if(error)snprintf(error,en,"Duplicate listen port in rule %d",i+1);return ESP_ERR_INVALID_STATE;}
        if(r->enabled&&portmap_listen_conflicts(r->proto,r->listen_port)){if(error)snprintf(error,en,"Rule %d conflicts with AP-side forwarding",i+1);return ESP_ERR_INVALID_STATE;}
        if(r->enabled&&r->proto==TAILNET_FORWARD_PROTO_TCP&&r->listen_port==web_ui_configured_port()){if(error)snprintf(error,en,"Rule %d conflicts with the Web UI port",i+1);return ESP_ERR_INVALID_STATE;}
    }
    store_t st={.magic=STORE_MAGIC};memcpy(st.rules,rules,count*sizeof rules[0]);nvs_handle_t nvs;esp_err_t err=nvs_open(NVS_NAMESPACE,NVS_READWRITE,&nvs);
    if(err==ESP_OK){err=nvs_set_blob(nvs,NVS_KEY,&st,sizeof st);if(err==ESP_OK)err=nvs_commit(nvs);nvs_close(nvs);}if(err!=ESP_OK)return err;
    LOCK();
    memset(s_rules,0,sizeof s_rules);memset(s_runtime,0,sizeof s_runtime);memcpy(s_rules,rules,count*sizeof rules[0]);s_count=count;
    for(int i=0;i<count;i++)resolve_rule(i);
    UNLOCK();
    portmap_install_all();return ESP_OK;
}
esp_err_t tailnet_forward_set_enabled(int i,bool enabled){tailnet_forward_rule_t copy[TAILNET_FORWARD_MAX];LOCK();if(i<0||i>=s_count){UNLOCK();return ESP_ERR_INVALID_ARG;}int count=s_count;memcpy(copy,s_rules,sizeof copy);UNLOCK();copy[i].enabled=enabled;char e[64];return tailnet_forward_set_all(copy,count,e,sizeof e);}
bool tailnet_forward_get_mapping(int i,uint8_t *proto,uint16_t *listen,uint32_t *dest,uint16_t *dport){LOCK();bool ok=i>=0&&i<s_count&&s_rules[i].valid&&s_rules[i].enabled&&s_runtime[i].resolved_ip;if(ok){*proto=s_rules[i].proto;*listen=s_rules[i].listen_port;*dest=lwip_htonl(s_runtime[i].resolved_ip);*dport=s_rules[i].destination_port;}UNLOCK();return ok;}
void tailnet_forward_prepare_install(void){LOCK();for(int i=0;i<s_count;i++)s_runtime[i].installed=false;UNLOCK();}
void tailnet_forward_mark_installed(int i,bool ok,const char *err){LOCK();if(i>=0&&i<s_count){s_runtime[i].installed=ok;if(err)strlcpy(s_runtime[i].error,err,sizeof s_runtime[i].error);else if(ok)s_runtime[i].error[0]=0;}UNLOCK();}

static bool packet_fields(struct pbuf *p,bool eth,uint32_t *src,uint8_t *proto,uint16_t *dport){
    size_t off=eth?14:0;if(!p||p->len<off+24)return false;uint8_t *b=p->payload;if(eth&&(b[12]!=8||b[13]!=0))return false;
    struct ip_hdr *ip=(struct ip_hdr *)(b+off);if(IPH_V(ip)!=4||(lwip_ntohs(IPH_OFFSET(ip))&IP_OFFMASK))return false;
    uint16_t ihl=IPH_HL(ip)*4;if(ihl<20||p->len<off+ihl+4)return false;*proto=IPH_PROTO(ip);if(*proto!=6&&*proto!=17)return false;
    memcpy(dport,b+off+ihl+2,2);*dport=lwip_ntohs(*dport);*src=lwip_ntohl(ip->src.addr);return true;
}
bool tailnet_forward_allow_uplink_packet(struct pbuf *p){uint32_t src;uint8_t proto;uint16_t dp;if(!packet_fields(p,true,&src,&proto,&dp))return true;LOCK();for(int i=0;i<s_count;i++)if(s_rules[i].valid&&s_rules[i].enabled&&s_rules[i].proto==proto&&s_rules[i].listen_port==dp){uint32_t mask=s_rules[i].source_prefix==0?0:(s_rules[i].source_prefix==32?0xffffffffu:0xffffffffu<<(32-s_rules[i].source_prefix));bool ok=s_runtime[i].installed&&((src&mask)==s_rules[i].source_network);if(ok)s_runtime[i].accepted_packets++;else s_runtime[i].blocked_packets++;UNLOCK();return ok;}UNLOCK();return true;}
bool tailnet_forward_allow_non_uplink_packet(struct pbuf *p,bool eth){uint32_t src;uint8_t proto;uint16_t dp;if(!packet_fields(p,eth,&src,&proto,&dp))return true;return !tailnet_forward_listen_conflicts(proto,dp);}
bool tailnet_forward_is_routed_target(uint8_t proto,uint32_t dst,uint16_t port){uint32_t h=lwip_ntohl(dst);LOCK();bool found=false;for(int i=0;i<s_count;i++)if(s_runtime[i].installed&&s_rules[i].proto==proto&&s_runtime[i].resolved_ip==h&&s_rules[i].destination_port==port){found=true;break;}UNLOCK();return found;}
bool tailnet_forward_is_routed_response(uint8_t proto,uint32_t src,uint16_t port){return tailnet_forward_is_routed_target(proto,src,port);}
void tailnet_forward_totals(uint32_t *enabled,uint32_t *installed,uint32_t *accepted,uint32_t *blocked){uint32_t e=0,n=0,a=0,b=0;LOCK();for(int i=0;i<s_count;i++){if(s_rules[i].enabled)e++;if(s_runtime[i].installed)n++;a+=s_runtime[i].accepted_packets;b+=s_runtime[i].blocked_packets;}UNLOCK();if(enabled)*enabled=e;if(installed)*installed=n;if(accepted)*accepted=a;if(blocked)*blocked=b;}
