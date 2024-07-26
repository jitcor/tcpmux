package io.tcpmux;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class NettyProxyServerTest {

    @Test
    void testLoadConfig() {
        NettyProxyServer.Config config = NettyProxyServer.loadConfig("config_test.yml");
        assertNotNull(config);
        assertFalse(config.tcpRules.isEmpty());
    }

}