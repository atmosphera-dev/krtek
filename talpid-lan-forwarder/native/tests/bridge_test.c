/* Independent wire fixtures/oracle. Including the port makes its fixed-table
 * accounting observable without expanding the production ABI. */
#include "../krtek_lwip.c"
#include <assert.h>

static unsigned checks;
static uint8_t segment[65536], received[65536], covered[65536], packet[65536];
static size_t expected_length, received_length, output_count, completes;
static uint16_t expected_mtu;
static uint8_t family;
static uint8_t protocol=17;
static uint64_t expected_scope;
static uint8_t app4[16] = {172,27,1,1}, peer4[16] = {192,168,50,9};
static uint8_t app6[16] = {0xfd,0xf0,0xce,0x4a,0x80,0x1d,0,0,0,0,0,0,0x1,0x72,0x27,1};
static uint8_t peer6[16] = {0xfd,0x12,0,0,0,0,0,0,0,0,0,0,0,0,0,9};

static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void put16(uint8_t *p, size_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static void put32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v; }
static uint32_t sum_bytes(uint32_t sum, const uint8_t *p, size_t n)
{
    size_t i;
    for (i=0; i+1<n; i+=2) sum += get16(p+i);
    if (i<n) sum += (uint32_t)p[i] << 8;
    return sum;
}
static uint16_t finish(uint32_t sum)
{ while (sum>>16) sum=(sum&65535)+(sum>>16); return (uint16_t)~sum; }
static uint16_t udp_checksum(const uint8_t *p, size_t n, int reverse)
{
    uint32_t sum=protocol+(uint32_t)n;
    const uint8_t *a=family==4?app4:app6, *b=family==4?peer4:peer6;
    LWIP_UNUSED_ARG(reverse); /* pseudoheader sum is commutative */
    sum=sum_bytes(sum,a,family==4?4:16); sum=sum_bytes(sum,b,family==4?4:16);
    return finish(sum_bytes(sum,p,n));
}
static void make_segment(size_t payload)
{
    size_t i;
    memset(segment,0,8); put16(segment,32001); put16(segment+2,18081);
    put16(segment+4,payload+8);
    for (i=0; i<payload; ++i) segment[8+i]=(uint8_t)(i*37+(i>>8)*13+19);
    { uint16_t checksum=udp_checksum(segment,payload+8,0);
      put16(segment+6, checksum?checksum:65535); }
    expected_length=payload+8;
}
static void on_complete(void *ctx, const krtek_lwip_transport *t, const uint8_t *p, size_t n)
{
    assert(ctx==&checks); assert(t->scope==expected_scope);
    assert(t->family==family && t->protocol==protocol);
    assert(memcmp(t->source,family==4?app4:app6,16)==0);
    assert(memcmp(t->destination,family==4?peer4:peer6,16)==0);
    assert(n==expected_length && memcmp(p,segment,n)==0);
    ++completes;
}
static void on_output(void *ctx, const uint8_t *p, size_t n)
{
    size_t header, offset, length, i;
    int more;
    assert(ctx==&checks); assert(n<=expected_mtu && (p[0]>>4)==family);
    if (family==4) {
        assert((p[0]&15)==5 && p[9]==17 && get16(p+2)==n);
        assert(finish(sum_bytes(0,p,20))==0);
        assert(memcmp(p+12,peer4,4)==0 && memcmp(p+16,app4,4)==0);
        header=20; offset=(get16(p+6)&8191)*8; more=(get16(p+6)&8192)!=0;
    } else {
        assert((size_t)get16(p+4)+40==n);
        assert(memcmp(p+8,peer6,16)==0 && memcmp(p+24,app6,16)==0);
        if (p[6]==44) {
            assert(p[40]==17 && p[41]==0);
            header=48; offset=get16(p+42)&65528; more=get16(p+42)&1;
        } else { assert(p[6]==17); header=40; offset=0; more=0; }
    }
    length=n-header;
    assert(offset+length<=expected_length);
    if (more) assert(length && length%8==0);
    else assert(offset+length==expected_length);
    for (i=0;i<length;++i) { assert(!covered[offset+i]); covered[offset+i]=1; }
    memcpy(received+offset,p+header,length);
    received_length+=length; ++output_count;
}
static const krtek_lwip_callbacks callbacks={on_complete,on_output};

/* Independent test-only fragmentation, never used by production or as its
 * output oracle. Each call emits exactly one prescribed wire range. */
static size_t piece(size_t offset, size_t length, int more, uint32_t id, int fragmented)
{
    size_t h=family==4?20:(fragmented?48:40);
    memset(packet,0,h);
    if (family==4) {
        packet[0]=0x45; put16(packet+2,h+length); put16(packet+4,id);
        put16(packet+6,offset/8+(more?8192:0)); packet[8]=64; packet[9]=protocol;
        memcpy(packet+12,app4,4); memcpy(packet+16,peer4,4);
        put16(packet+10,finish(sum_bytes(0,packet,20)));
    } else {
        packet[0]=0x60; put16(packet+4,h-40+length);
        packet[6]=fragmented?44:protocol; packet[7]=64;
        memcpy(packet+8,app6,16); memcpy(packet+24,peer6,16);
        if(fragmented) { packet[40]=protocol; put16(packet+42,offset+(more?1:0)); put32(packet+44,id); }
    }
    memcpy(packet+h,segment+offset,length);
    return h+length;
}
static krtek_lwip_handle open_client(void)
{ krtek_lwip_handle h; assert(krtek_lwip_open(&h)==0 && h); return h; }
static void ingest_message(krtek_lwip_handle h, size_t payload, uint16_t mtu, int reverse, int fragmented, uint32_t id)
{
    size_t count, index, cut, n, offset, length, before=completes;
    make_segment(payload);
    expected_scope=101;
    cut=fragmented?(((size_t)mtu-(family==4?20:48))/8)*8:expected_length;
    count=(expected_length+cut-1)/cut;
    if(count==1) fragmented=0;
    for(index=0;index<count;++index) {
        n=reverse?count-index-1:index; offset=n*cut;
        length=LWIP_MIN(cut,expected_length-offset);
        { size_t wire=piece(offset,length,n+1<count,id,fragmented);
          int32_t rc=krtek_lwip_ingest(h,expected_scope,packet,wire,&callbacks,&checks);
          if (rc!=(index+1==count?KRTEK_LWIP_OK:KRTEK_LWIP_PENDING))
              fprintf(stderr,"ingest family=%u payload=%zu mtu=%u reverse=%d fragmented=%d piece=%zu/%zu rc=%d refs=%u\n",
                  family,payload,mtu,reverse,fragmented,index,count,rc,krtek_lwip_scope_refs(h,expected_scope));
          assert(rc==(index+1==count?KRTEK_LWIP_OK:KRTEK_LWIP_PENDING)); }
        assert(completes==before+(index+1==count));
    }
    assert(krtek_lwip_scope_refs(h,expected_scope)==0); ++checks;
    assert(!current.callbacks && !current.context);
}
static void reply_message(krtek_lwip_handle h, size_t payload, uint16_t mtu)
{
    krtek_lwip_transport t={0};
    size_t i;
    make_segment(payload); memset(received,0,sizeof(received)); memset(covered,0,sizeof(covered));
    output_count=received_length=0; expected_mtu=mtu;
    t.family=family; t.protocol=17; t.scope=101;
    memcpy(t.source,family==4?peer4:peer6,16); memcpy(t.destination,family==4?app4:app6,16);
    assert(krtek_lwip_set_mtu(h,mtu)==0);
    assert(krtek_lwip_reply(h,&t,18081,32001,segment+8,payload,&callbacks,&checks)==0);
    assert(received_length==expected_length && output_count>0);
    for(i=0;i<expected_length;++i) assert(covered[i]);
    assert(get16(received)==18081 && get16(received+2)==32001);
    assert(get16(received+4)==expected_length && udp_checksum(received,received_length,1)==0);
    assert(memcmp(received+8,segment+8,payload)==0);
    assert(!current.callbacks && !current.context);
    if(family==4 && payload==65507 && mtu==68) assert(output_count==1365);
    ++checks;
}
static void mixed(krtek_lwip_handle h, int foreign_handle, int foreign_position)
{
    krtek_lwip_handle other=open_client();
    size_t index,before=completes;
    make_segment(64); expected_scope=101;
    for(index=0;index<3;++index) {
        size_t wire=piece(index*24,24,index!=2,901+foreign_position+foreign_handle*10,1);
        krtek_lwip_handle owner=foreign_handle && (int)index==foreign_position?other:h;
        uint64_t scope=!foreign_handle && (int)index==foreign_position?102:101;
        int32_t rc=krtek_lwip_ingest(owner,scope,packet,wire,&callbacks,&checks);
        assert(rc==(index==2?KRTEK_LWIP_STALE:KRTEK_LWIP_PENDING));
    }
    assert(completes==before);
    assert(!krtek_lwip_scope_refs(h,101) && !krtek_lwip_scope_refs(h,102));
    assert(!krtek_lwip_scope_refs(other,101));
    assert(krtek_lwip_close(other)==0); ++checks;
}
static void boundary(krtek_lwip_handle h)
{
    krtek_lwip_transport t={0}; size_t wire;
    t.family=family; t.protocol=17; t.scope=101;
    assert(krtek_lwip_reply(h,&t,1,2,segment,SIZE_MAX,&callbacks,NULL)==KRTEK_LWIP_OVERSIZED);
    assert(krtek_lwip_reply(h,&t,1,2,segment,family==4?65508:65488,&callbacks,NULL)==KRTEK_LWIP_OVERSIZED);
    make_segment(8); wire=piece(0,16,0,88,1);
    if(family==4) { put16(packet+6,8191); put16(packet+10,0); put16(packet+10,finish(sum_bytes(0,packet,20))); }
    else put16(packet+42,65528);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,NULL)==KRTEK_LWIP_OVERSIZED);
    assert(krtek_lwip_ingest(h,0,packet,wire,&callbacks,NULL)==KRTEK_LWIP_MALFORMED);
    assert(krtek_lwip_ingest(h,101,NULL,0,&callbacks,NULL)==KRTEK_LWIP_MALFORMED);
    assert(krtek_lwip_ingest(h,101,segment,65536,&callbacks,NULL)==KRTEK_LWIP_OVERSIZED);
    assert(krtek_lwip_ingest(h,101,segment,16,NULL,NULL)==KRTEK_LWIP_MALFORMED);
    assert(krtek_lwip_reply(h,&t,1,2,NULL,1,&callbacks,NULL)==KRTEK_LWIP_MALFORMED);
    assert(krtek_lwip_reply(h,&t,0,2,segment,1,&callbacks,NULL)==KRTEK_LWIP_UNSUPPORTED);
    if(family==6) {
        wire=piece(0,16,0,99,1);
        assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,NULL)==KRTEK_LWIP_UNSUPPORTED);
        packet[6]=60;
        assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,NULL)==KRTEK_LWIP_UNSUPPORTED);
        assert(!krtek_lwip_set_mtu(h,68));
        assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,NULL)==KRTEK_LWIP_UNSUPPORTED);
        assert(krtek_lwip_reply(h,&t,1,2,segment,8,&callbacks,NULL)==KRTEK_LWIP_UNSUPPORTED);
        assert(!krtek_lwip_set_mtu(h,1280));
    } else {
        t.source[15]=1;
        assert(krtek_lwip_reply(h,&t,1,2,segment,8,&callbacks,NULL)==KRTEK_LWIP_MALFORMED);
    }
    ++checks;
}
static void retained_behavior(krtek_lwip_handle h)
{
    size_t wire,before=completes;
    make_segment(64); expected_scope=101;
    wire=piece(0,24,1,1001,1);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==1);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==1);
    assert(krtek_lwip_scope_refs(h,101)==1); /* duplicate is discarded, assembly retained */
    wire=piece(16,16,1,1001,1);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==1);
    assert(krtek_lwip_scope_refs(h,101)==1); /* stock overlap keeps earlier work */
    assert(!krtek_lwip_set_mtu(h,1400));
    assert(krtek_lwip_scope_refs(h,101)==1);
    wire=piece(48,24,0,1001,1);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==1);
    wire=piece(24,24,1,1001,1);
    assert(!krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks));
    assert(completes==before+1 && !krtek_lwip_scope_refs(h,101)); ++checks;
}
static void tcp_ingress(krtek_lwip_handle h)
{
    size_t i,wire,before=completes;
    protocol=6; expected_length=48; expected_scope=101;
    memset(segment,0,expected_length);
    put16(segment,32001); put16(segment+2,18081); put32(segment+4,123456);
    segment[12]=0x50; segment[13]=2; put16(segment+14,4096);
    for(i=20;i<expected_length;++i) segment[i]=(uint8_t)i;
    put16(segment+16,udp_checksum(segment,expected_length,0));
    for(i=0;i<3;++i) {
        wire=piece(i*16,16,i!=2,4001,1);
        assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==(i==2?0:1));
        assert(completes==before+(i==2));
    }
    assert(!krtek_lwip_scope_refs(h,101)); protocol=17; ++checks;
}
static void every_node_provenance(krtek_lwip_handle h)
{
    size_t i,found=0,wire,before=completes;
    make_segment(4096); expected_scope=101;
    wire=piece(0,4096,1,5001,1);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==1);
    assert(krtek_lwip_scope_refs(h,101)==3);
    for(i=0;i<PBUF_POOL_SIZE;++i) if(nodes[i].backing && nodes[i].scope==101) {
        if(++found==2) { nodes[i].scope=102; break; }
    }
    assert(found==2);
    wire=piece(4096,8,0,5001,1);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==KRTEK_LWIP_STALE);
    assert(completes==before && !krtek_lwip_scope_refs(h,101) && !krtek_lwip_scope_refs(h,102));
    ++checks;
}
static void allocation_failures(krtek_lwip_handle h)
{
    static struct pbuf *held[PBUF_POOL_SIZE];
    size_t count=0,i,wire;
    void *heap;
    krtek_lwip_transport t={0};
    family=4; make_segment(4096);
    while(count<PBUF_POOL_SIZE && (held[count]=pbuf_alloc(PBUF_RAW,2048,PBUF_POOL))) ++count;
    assert(count==PBUF_POOL_SIZE);
    wire=piece(0,expected_length,0,600,0);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,NULL)==KRTEK_LWIP_FULL);
    pbuf_free(held[--count]);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,NULL)==KRTEK_LWIP_FULL);
    assert(!krtek_lwip_scope_refs(h,101));
    for(i=0;i<count;++i) pbuf_free(held[i]);
    for(i=0;i<PBUF_POOL_SIZE;++i) assert(!nodes[i].backing);
    ++checks;
    t.family=4; t.protocol=17; t.scope=101;
    memcpy(t.source,peer4,16); memcpy(t.destination,app4,16);
    heap=mem_malloc(MEM_SIZE-64); assert(heap);
    assert(krtek_lwip_reply(h,&t,18081,32001,segment+8,4096,&callbacks,NULL)==KRTEK_LWIP_FULL);
    mem_free(heap);
    reply_message(h,4096,1280); ++checks;
}
static void retired_completion(void)
{
    krtek_lwip_handle old=open_client(), next;
    size_t wire,before=completes;
    make_segment(64); expected_scope=101;
    wire=piece(0,24,1,2001,1);
    assert(krtek_lwip_ingest(old,101,packet,wire,&callbacks,&checks)==1);
    assert(!krtek_lwip_close(old) && krtek_lwip_scope_refs(old,101)==1);
    next=open_client(); assert(next!=old);
    wire=piece(24,24,1,2001,1);
    assert(krtek_lwip_ingest(next,101,packet,wire,&callbacks,&checks)==1);
    wire=piece(48,24,0,2001,1);
    assert(krtek_lwip_ingest(next,101,packet,wire,&callbacks,&checks)==KRTEK_LWIP_STALE);
    assert(completes==before && !krtek_lwip_scope_refs(old,101) && !krtek_lwip_scope_refs(next,101));
    assert(!krtek_lwip_close(next)); ++checks;
}
static void wrapping_clock(void)
{
    krtek_lwip_handle h;
    assert(!krtek_lwip_tick(0x7fffffff)); assert(!krtek_lwip_tick(0xfffffffe));
    h=open_client(); assert(sys_now()==0xfffffffe);
    assert(!krtek_lwip_tick(500)); assert(sys_now()==500);
    assert(krtek_lwip_tick(499)==KRTEK_LWIP_MALFORMED);
    assert(sys_now()==500 && krtek_lwip_next_timeout_ms()<=1000);
    assert(!krtek_lwip_close(h)); ++checks;
}
static void expiry(void)
{
    krtek_lwip_handle h=open_client(), other;
    uint32_t now;
    for(family=4;family<=6;family+=2) {
        size_t wire;
        make_segment(4096); wire=piece(0,1232,1,family,1);
        assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,NULL)==1);
        assert(krtek_lwip_scope_refs(h,101)==1);
        assert(krtek_lwip_close(h)==0);
        assert(krtek_lwip_scope_refs(h,101)==1);
        other=open_client(); assert(other!=h);
        for(now=family==4?1000:18000;now<=(family==4?17000:80000);now+=1000) {
            assert(krtek_lwip_next_timeout_ms()<=1000);
            assert(krtek_lwip_tick(now)==0);
        }
        assert(!krtek_lwip_scope_refs(h,101));
        h=other; ++checks;
    }
    assert(!completes && !output_count); assert(krtek_lwip_close(h)==0);
}
static void pressure(void)
{
    krtek_lwip_handle h=open_client();
    size_t j,i,wire;
    family=4; make_segment(65507);
    for(j=0;j<6;++j) {
        wire=piece(0,48,1,(uint32_t)j,1);
        assert(krtek_lwip_ingest(h,101+j,packet,wire,&callbacks,NULL)==1);
    }
    assert(!krtek_lwip_scope_refs(h,101)); ++checks;
    for(j=0;j<2;++j) for(i=0;i<1364;++i) {
        wire=piece(i*48,48,1,100+(uint32_t)j,1);
        assert(krtek_lwip_ingest(h,201+j,packet,wire,&callbacks,NULL)==1);
    }
    assert(!krtek_lwip_scope_refs(h,201));
    assert(krtek_lwip_scope_refs(h,202)==1364); ++checks;
    for(i=1000;i<=17000;i+=1000) assert(!krtek_lwip_tick((uint32_t)i));
    assert(!krtek_lwip_scope_refs(h,202));
    for(i=0;i<PBUF_POOL_SIZE;++i) assert(!nodes[i].backing);
    assert(!completes && !output_count); assert(!krtek_lwip_close(h)); ++checks;
}
int main(int argc, char **argv)
{
    krtek_lwip_handle h;
    size_t i;
    if(argc>1) {
        if(!strcmp(argv[1],"expiry")) expiry();
        else if(!strcmp(argv[1],"clock")) wrapping_clock();
        else { assert(!strcmp(argv[1],"pressure")); pressure(); }
    } else {
        const size_t sizes[]={0,1,31,1232,1233,1252,1253,4096,4097};
        h=open_client(); assert(krtek_lwip_abi_version()==1);
        assert(krtek_lwip_open(NULL)==KRTEK_LWIP_MALFORMED);
        for(family=4;family<=6;family+=2) {
            assert(!krtek_lwip_set_mtu(h,1280));
            for(i=0;i<sizeof(sizes)/sizeof(sizes[0]);++i) {
                ingest_message(h,sizes[i],1280,0,1,(uint32_t)i+10);
                ingest_message(h,sizes[i],1280,1,1,(uint32_t)i+30);
                reply_message(h,sizes[i],1280);
            }
            ingest_message(h,family==4?65507:65487,1280,1,1,200);
            ingest_message(h,family==4?65507:65487,65535,0,0,201);
            reply_message(h,family==4?65507:65487,1280);
            reply_message(h,family==4?65507:65487,65535);
            for(i=0;i<3;++i) { mixed(h,0,(int)i); mixed(h,1,(int)i); }
            boundary(h);
            retained_behavior(h); retired_completion();
            tcp_ingress(h);
            every_node_provenance(h);
        }
        family=4; reply_message(h,65507,68);
        ingest_message(h,65507,68,1,1,700);
        allocation_failures(h);
        assert(krtek_lwip_set_mtu(h,67)==KRTEK_LWIP_UNSUPPORTED);
        assert(krtek_lwip_close(h)==0);
        assert(krtek_lwip_ingest(h,101,packet,20,&callbacks,NULL)==KRTEK_LWIP_STALE);
        for(i=0;i<1000;++i) { krtek_lwip_handle next=open_client(); assert(next>h); h=next; assert(!krtek_lwip_close(h)); }
        for(i=0;i<PBUF_POOL_SIZE;++i) assert(!nodes[i].backing);
        ++checks;
    }
    printf("stock_lwip_native: %u checks passed; nodes=%zu contexts=%zu heap=%u timers=%d\n",
        checks,sizeof(nodes),sizeof(clients),(unsigned)MEM_SIZE,lwip_num_cyclic_timers);
    return 0;
}
