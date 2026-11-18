/* C4 stock behavior fixtures. Reuse the independent C1 wire builder and byte
 * oracle, not production packetization. Each clock case runs in a NEW process. */
#define main bridge_baseline_main
#include "bridge_test.c"
#undef main

static int32_t input(krtek_lwip_handle h, uint64_t scope, size_t offset,
    size_t length, int more, uint32_t id)
{
    size_t wire=piece(offset,length,more,id,1);
    return krtek_lwip_ingest(h,scope,packet,wire,&callbacks,&checks);
}

static void first_arrival_clock(uint8_t version)
{
    krtek_lwip_handle h=open_client(), next=0;
    uint32_t tick, last=version==4?16000:61000;
    family=version; expected_scope=101; make_segment(64);
    assert(input(h,101,48,24,0,9101)==KRTEK_LWIP_PENDING); /* final first */
    assert(!krtek_lwip_tick(999));
    assert(krtek_lwip_scope_refs(h,101)==1);
    for(tick=1000;tick<last;tick+=1000) {
        assert(!krtek_lwip_tick(tick));
        assert(krtek_lwip_scope_refs(h,101)==1);
        if(tick==5000) { /* duplicate/overlap never refresh original countdown */
            assert(input(h,101,48,24,0,9101)==KRTEK_LWIP_PENDING);
            assert(input(h,101,56,8,0,9101)==KRTEK_LWIP_PENDING);
            assert(krtek_lwip_scope_refs(h,101)==1);
            assert(!krtek_lwip_close(h));
            next=open_client(); assert(next!=h);
        }
    }
    assert(!krtek_lwip_tick(last-1));
    assert(krtek_lwip_scope_refs(h,101)==1);
    assert(!krtek_lwip_tick(last));
    assert(!krtek_lwip_scope_refs(h,101));
    assert(!krtek_lwip_tick(last+1));
    assert(!completes && !output_count);
    assert(!krtek_lwip_close(next));
    ++checks;
}

static void family_pressure(uint8_t version)
{
    krtek_lwip_handle h=open_client();
    size_t i,j;
    family=version; make_segment(version==4?65507:65487);
    for(j=0;j<6;++j) {
        assert(input(h,101+j,0,24,1,9200+(uint32_t)j)==KRTEK_LWIP_PENDING);
        assert(!krtek_lwip_tick((uint32_t)(j+1)*1000));
    }
    assert(!krtek_lwip_scope_refs(h,101));
    for(j=1;j<6;++j) assert(krtek_lwip_scope_refs(h,101+j)==1);
    ++checks;
    for(j=0;j<2;++j) for(i=0;i<1200;++i) {
        assert(input(h,201+j,i*24,24,1,9300+(uint32_t)j)==KRTEK_LWIP_PENDING);
    }
    assert(!krtek_lwip_scope_refs(h,201));
    assert(krtek_lwip_scope_refs(h,202)==1200);
    assert(!completes && !output_count);
    ++checks;
    for(i=7000;i<=69000;i+=1000) assert(!krtek_lwip_tick((uint32_t)i));
    for(i=0;i<PBUF_POOL_SIZE;++i) assert(!nodes[i].backing);
    assert(!krtek_lwip_close(h)); ++checks;
}

static void corners(void)
{
    krtek_lwip_handle h=open_client();
    size_t wire,before;
    for(family=4;family<=6;family+=2) {
        uint32_t id=9400+family;
        make_segment(64); expected_scope=101; before=completes;
        assert(input(h,101,24,24,1,id)==1);
        /* Prefix/subset/partial overlap and altered duplicate: stock discards
         * the arriving piece, retaining the earlier correct bytes. */
        assert(input(h,101,32,8,1,id)==1);
        assert(input(h,101,16,16,1,id)==1);
        wire=piece(24,24,1,id,1); packet[wire-1]^=0xff;
        assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==1);
        assert(krtek_lwip_scope_refs(h,101)==1 && completes==before);
        assert(input(h,101,48,24,0,id)==1);
        assert(input(h,101,0,24,1,id)==0);
        assert(completes==before+1 && !krtek_lwip_scope_refs(h,101)); ++checks;
    }
    /* IPv4 protocol is omitted from the stock key. A TCP-labelled tail can
     * join UDP zero. This native seam grants no transport authorization. */
    family=4; make_segment(64); before=completes;
    assert(input(h,101,0,24,1,9501)==1);
    protocol=6; assert(input(h,101,24,24,1,9501)==1); protocol=17;
    assert(input(h,101,48,24,0,9501)==0);
    assert(completes==before+1); ++checks;
    /* Fragmented IPv4 options are refused by upstream and retain no node. */
    wire=piece(0,24,1,9502,1);
    memmove(packet+24,packet+20,24); memset(packet+20,1,4); packet[0]=0x46;
    put16(packet+2,wire+4); put16(packet+10,0);
    put16(packet+10,finish(sum_bytes(0,packet,24)));
    assert(krtek_lwip_ingest(h,101,packet,wire+4,&callbacks,&checks)==1);
    assert(!krtek_lwip_scope_refs(h,101)); ++checks;
    /* Atomic and extension-prefixed IPv6 stay explicitly unsupported. */
    family=6; make_segment(64); before=completes;
    wire=piece(0,expected_length,0,9503,1);
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==KRTEK_LWIP_UNSUPPORTED);
    packet[6]=60;
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==KRTEK_LWIP_UNSUPPORTED);
    assert(completes==before && !krtek_lwip_scope_refs(h,101)); ++checks;
    /* Tail-first Next Header is inherited from the first arriving tail, not
     * zero. UDP bytes are misread as extension syntax and dropped before raw
     * completion. PENDING here means no completion, not retained storage. */
    wire=piece(48,24,0,9504,1); packet[40]=60;
    assert(krtek_lwip_ingest(h,101,packet,wire,&callbacks,&checks)==1);
    assert(input(h,101,0,24,1,9504)==1);
    assert(input(h,101,24,24,1,9504)==KRTEK_LWIP_PENDING);
    assert(completes==before && !krtek_lwip_scope_refs(h,101)); ++checks;
    assert(!krtek_lwip_close(h));
}

int main(int argc, char **argv)
{
    assert(argc==2);
    if(!strcmp(argv[1],"clock4")) first_arrival_clock(4);
    else if(!strcmp(argv[1],"clock6")) first_arrival_clock(6);
    else if(!strcmp(argv[1],"pressure4")) family_pressure(4);
    else if(!strcmp(argv[1],"pressure6")) family_pressure(6);
    else { assert(!strcmp(argv[1],"corners")); corners(); }
    printf("stock_lwip_matrix: %s: %u checks passed\n",argv[1],checks);
    return 0;
}
