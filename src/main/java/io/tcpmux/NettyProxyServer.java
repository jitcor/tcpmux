package io.tcpmux;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * config.yml default
 * tcpRules:
 *   - pattern: AB CD ?? 12 7? 89 ?8
 *     targetHost: 127.0.0.1
 *     targetPort: 5002
 *   - pattern: 78 12 45 a8 90
 *     targetHost: 127.0.0.1
 *     targetPort: 5003
 *   - pattern: 00 00 00 00
 *     targetHost: 127.0.0.1
 *     targetPort: 5001
 *
 * httpRules:
 *   - pattern: /mock
 *     targetHost: 127.0.0.1
 *     targetPort: 5005
 *     path: /anything
 *   - pattern: /getid
 *     targetHost: httpbin.org
 *     targetPort: 80
 *     path: /anything
 *   - pattern: /
 *     targetHost: 127.0.0.1
 *     targetPort: 5007
 *     path: /home/admin
 */

public class NettyProxyServer {
    private static final Logger logger = LoggerFactory.getLogger(NettyProxyServer.class);

    public static void main(String[] args) {
        String configPath = args.length > 0 ? args[0] : ""; // 使用外部传入的路径或默认路径
        new NettyProxyServer(configPath).start();
    }

    private Config config;

    public NettyProxyServer(String configPath) {
        this.config = configPath.isEmpty() ? loadConfigInternal() : loadConfig(configPath);
        if(!configPath.isEmpty()){
            new Thread(() -> new ConfigWatcher().watchConfigFile(Paths.get(configPath), this::updateConfig)).start();
        }
    }

    public void start() {
        EventLoopGroup bossGroup = new NioEventLoopGroup(1);  // 适用于接受连接
        EventLoopGroup workerGroup = new NioEventLoopGroup(Math.max(4, Runtime.getRuntime().availableProcessors() * 2));  // 根据CPU核心数设置

        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) throws Exception {
                            ch.pipeline().addLast(new ProtocolDetectHandler(config));
                        }
                    });

            ChannelFuture f = b.bind(this.config.port).sync();
            f.channel().closeFuture().sync();
        }catch (Throwable e){
            logger.error("Failed to start the Netty server", e);
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }


    protected static Config loadConfig(String fileName) {
        Yaml yaml = new Yaml(new Constructor(Config.class, new LoaderOptions()));
        try (InputStream in = new FileInputStream(fileName)) {
            return yaml.load(in);
        } catch (Exception e) {
            logger.error("Failed to load config file", e);
            throw new RuntimeException("Failed to load config file", e);
        }
    }

    private static Config loadConfigInternal() {
        Yaml yaml = new Yaml(new Constructor(Config.class, new LoaderOptions()));
        try (InputStream in = NettyProxyServer.class.getClassLoader().getResourceAsStream("config.yml")) {
            return yaml.load(in);
        } catch (Exception e) {
            logger.error("Failed to load internal config file", e);
            throw new RuntimeException("Failed to load config file", e);
        }
    }

    private void updateConfig(Config newConfig) {
        this.config = newConfig;
        logger.info("Configuration updated");
    }

    public static class Config {
        public int port; // 端口配置
        public List<Map<String, Object>> tcpRules;
        public List<Map<String, Object>> httpRules;
    }
}

class ConfigWatcher {
    private static final Logger logger = LoggerFactory.getLogger(ConfigWatcher.class);

    public void watchConfigFile(Path path, Consumer<NettyProxyServer.Config> configConsumer) {
        try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
            path.getParent().register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
            while (true) {
                WatchKey key = watchService.take();
                for (WatchEvent<?> event : key.pollEvents()) {
                    Path changed = (Path) event.context();
                    if (changed.endsWith(path.getFileName())) {
                        logger.info("Config file changed: " + changed);
                        NettyProxyServer.Config newConfig = NettyProxyServer.loadConfig(path.toString());
                        configConsumer.accept(newConfig);
                    }
                }
                key.reset();
            }
        } catch (IOException | InterruptedException e) {
            logger.error("Error watching config file", e);
        }
    }
}

class PatternMatcher {
    private final byte[] pattern;
    private final byte[] mask;

    PatternMatcher(String hexPattern) {
        // 解析规则字符串并生成模式和掩码
        PatternMask result = parseRule(hexPattern);
        this.pattern = result.pattern;
        this.mask = result.mask;
    }

    boolean matchPattern(ByteBuf buffer) {
        if (buffer.readableBytes() < pattern.length) {
            return false;
        }
        buffer.markReaderIndex();
        for (int i = 0; i < pattern.length; i++) {
            if ((buffer.readByte() & mask[i]) != (pattern[i] & mask[i])) {
                buffer.resetReaderIndex();
                return false;
            }
        }
        buffer.resetReaderIndex();
        return true;
    }

    private static PatternMask parseRule(String rule) {
        String[] tokens = rule.split("\\s+");
        List<Byte> patternList = new ArrayList<>();
        List<Byte> maskList = new ArrayList<>();

        for (String token : tokens) {
            if (token.contains("?")) {
                // 对每个字符进行检查
                byte patternByte = 0x00;
                byte maskByte = 0x00;
                for (int i = 0; i < 2; i++) {
                    char c = token.charAt(i);
                    if (c == '?') {
                        patternByte = (byte) (patternByte << 4);
                        maskByte = (byte) (maskByte << 4);
                    } else {
                        patternByte = (byte) (patternByte << 4 | Character.digit(c, 16));
                        maskByte = (byte) (maskByte << 4 | 0xF);
                    }
                }
                patternList.add(patternByte);
                maskList.add(maskByte);
            } else {
                byte patternByte = (byte) Integer.parseInt(token, 16);
                byte maskByte = (byte) 0xFF;
                patternList.add(patternByte);
                maskList.add(maskByte);
            }
        }

        byte[] pattern = new byte[patternList.size()];
        byte[] mask = new byte[maskList.size()];
        for (int i = 0; i < pattern.length; i++) {
            pattern[i] = patternList.get(i);
            mask[i] = maskList.get(i);
        }

        return new PatternMask(pattern, mask);
    }

    static class PatternMask {
        byte[] pattern;
        byte[] mask;

        PatternMask(byte[] pattern, byte[] mask) {
            this.pattern = pattern;
            this.mask = mask;
        }
    }
}


class ProtocolDetectHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(ProtocolDetectHandler.class);
    private final NettyProxyServer.Config config;

    public ProtocolDetectHandler(NettyProxyServer.Config config) {
        this.config = config;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf in = (ByteBuf) msg;
        boolean isMatch = false;
        for (Map<String, Object> rule : config.tcpRules) {
            PatternMatcher matcher = new PatternMatcher((String) rule.get("pattern"));
            if (matcher.matchPattern(in)) {
                isMatch = true;
                break;
            }
        }

        if (isMatch) {
            ctx.pipeline().addLast(new ProtocolBasedRouterHandler(config));
        } else if (isHttp(in)) {
            ctx.pipeline().addLast(new HttpServerCodec());
            ctx.pipeline().addLast(new HttpObjectAggregator(65536));
            ctx.pipeline().addLast(new HttpBasedRouterHandler(config));
        } else {
            log.warn("Protocol detect failed");
        }

        ctx.pipeline().remove(this);
        ctx.fireChannelRead(msg);
    }

    private boolean isHttp(ByteBuf in) {
        if (in.readableBytes() < 8) {
            return false;
        }

        int firstFourBytes = in.getUnsignedByte(0) << 24 | in.getUnsignedByte(1) << 16 | in.getUnsignedByte(2) << 8 | in.getUnsignedByte(3);
        int secondFourBytes = in.getUnsignedByte(4) << 24 | in.getUnsignedByte(5) << 16 | in.getUnsignedByte(6) << 8 | in.getUnsignedByte(7);

        switch (firstFourBytes) {
            case 0x47455420: // "GET "
                return true;
            case 0x504f5354: // "POST"
                if (in.getUnsignedByte(4) == 0x20) { // " "
                    return true;
                }
                break;
            case 0x50555420: // "PUT "
                return true;
            case 0x44454c45: // "DELE"
                if (secondFourBytes == 0x54452020) { // "TE  "
                    return true;
                }
                break;
            case 0x48454144: // "HEAD"
                if (in.getUnsignedByte(4) == 0x20) { // " "
                    return true;
                }
                break;
            case 0x434f4e4e: // "CONN"
                if (secondFourBytes == 0x45435420) { // "ECT "
                    return true;
                }
                break;
            case 0x50415443: // "PATC"
                if (secondFourBytes == 0x48202020) { // "H   "
                    return true;
                }
                break;
            case 0x4f505449: // "OPTI"
                if (secondFourBytes == 0x4f4e5320) { // "ONS "
                    return true;
                }
                break;
        }

        return false;
    }

}

class ProtocolBasedRouterHandler extends ChannelInboundHandlerAdapter {

    private static final Logger logger = LoggerFactory.getLogger(ProtocolBasedRouterHandler.class);

    private final NettyProxyServer.Config config;

    public ProtocolBasedRouterHandler(NettyProxyServer.Config config) {
        this.config = config;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf in = (ByteBuf) msg;
        for (Map<String, Object> rule : config.tcpRules) {
            PatternMatcher matcher = new PatternMatcher((String) rule.get("pattern"));
            if (matcher.matchPattern(in)) {
                forwardTraffic(ctx, (String) rule.get("targetHost"), (Integer) rule.get("targetPort"), in);
                return;
            }
        }
    }

    private void forwardTraffic(ChannelHandlerContext ctx, String targetHost, int targetPort, ByteBuf initialData) {
        final Channel inboundChannel = ctx.channel();
        Bootstrap b = new Bootstrap();
        b.group(inboundChannel.eventLoop())
                .channel(inboundChannel.getClass())
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        ch.pipeline().addLast(new TcpRelayHandler(inboundChannel));
                    }
                });

        b.connect(targetHost, targetPort).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                future.channel().writeAndFlush(initialData);
            } else {
                inboundChannel.close();
            }
        });
    }
}

class HttpBasedRouterHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

    private final NettyProxyServer.Config config;

    public HttpBasedRouterHandler(NettyProxyServer.Config config) {
        this.config = config;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) throws Exception {
        String uri = request.uri();
        String targetHost = "127.0.0.1";
        int targetPort = 80; // default values
        String newUri = uri;

        for (Map<String, Object> rule : config.httpRules) {
            if (uri.startsWith((String) rule.get("pattern")) || rule.get("pattern").equals("default")) {
                targetHost = (String) rule.get("targetHost");
                targetPort = (int) rule.get("targetPort");
                newUri = rule.get("path") + uri.substring(((String) rule.get("pattern")).length());
                break;
            }
        }

        FullHttpRequest newRequest = new DefaultFullHttpRequest(
                request.protocolVersion(), request.method(), newUri, request.content());
        newRequest.headers().setAll(request.headers());

        forwardTraffic(ctx, targetHost, targetPort, newRequest);
    }

    private void forwardTraffic(ChannelHandlerContext ctx, String targetHost, int targetPort, FullHttpRequest initialRequest) {
        final Channel inboundChannel = ctx.channel();
        Bootstrap b = new Bootstrap();
        b.group(inboundChannel.eventLoop())
                .channel(inboundChannel.getClass())
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) throws Exception {
                        ch.pipeline().addLast(new HttpClientCodec());
                        ch.pipeline().addLast(new HttpObjectAggregator(65536));
                        ch.pipeline().addLast(new RelayHandler(inboundChannel));
                    }
                });

        // Retain the request to ensure reference count is correct
        initialRequest.retain();

        b.connect(targetHost, targetPort).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                Channel outboundChannel = future.channel();
                outboundChannel.writeAndFlush(initialRequest);
            } else {
                inboundChannel.close();
            }
        });
    }
}

class RelayHandler extends SimpleChannelInboundHandler<FullHttpResponse> {

    private static final Logger logger = LoggerFactory.getLogger(RelayHandler.class);

    private final Channel clientChannel;

    public RelayHandler(Channel clientChannel) {
        this.clientChannel = clientChannel;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse response) throws Exception {
        response.retain(); // Ensure the response is retained before forwarding
        clientChannel.writeAndFlush(response);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        Common.closeOnFlush(clientChannel);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        logger.error("Unhandled exception in pipeline.", cause);
        ctx.close();
    }
}

class TcpRelayHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private static final Logger logger = LoggerFactory.getLogger(RelayHandler.class);

    private final Channel clientChannel;

    public TcpRelayHandler(Channel clientChannel) {
        this.clientChannel = clientChannel;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        msg.retain(); // Ensure the response is retained before forwarding
        clientChannel.writeAndFlush(msg);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        Common.closeOnFlush(clientChannel);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        logger.error("Unhandled exception in pipeline.", cause);
        ctx.close();
    }
}

class Common {
    public static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }
}