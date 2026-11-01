# ISP strategy parameters adapted from SplitWire-Turkey (MIT).
# See LICENSE.SplitWire-Turkey. This hook uses blockcheck2's native test runner;
# reported successes, not a preset's name, determine what can be installed.
pktws_check_https_tls12()
{
    local strategy
    for strategy in \
        '--lua-desync=multidisorder:pos=2:seqovl=1' \
        '--lua-desync=multisplit:blob=fake_default_tls:ip_ttl=5:pos=2:nodrop:repeats=1' \
        '--lua-desync=fake:blob=0x00000000:ip_ttl=5:repeats=1'
    do
        if pktws_curl_test_update "$1" "$2" --payload=tls_client_hello "$strategy"; then
            [ "$SCANLEVEL" = force ] || return
        fi
    done
}
