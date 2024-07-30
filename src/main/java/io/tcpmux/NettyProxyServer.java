package io.tcpmux;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import org.apache.commons.io.monitor.FileAlterationListenerAdaptor;
import org.apache.commons.io.monitor.FileAlterationMonitor;
import org.apache.commons.io.monitor.FileAlterationObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * port: 55280
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
    private EchoServer echoServer;

    public static void main(String[] args) {
        String configPath = args.length > 0 ? args[0] : ""; // 使用外部传入的路径或默认路径
        new NettyProxyServer(configPath).start();
    }

    private final Config config;

    public NettyProxyServer(String configPath) {
        this.config = configPath.isEmpty() ? loadConfigInternal() : loadConfig(configPath);
        logger.info("logPath:{}", this.config.logPath);
        if (this.config.logEnable) {
            try {
                Common.setupConsoleLog(this.config.logPath);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        if (config.tcpBinTest) {
            echoServer = new EchoServer(config.tcpBinTestPort);
            new Thread(() -> {
                try {
                    echoServer.start();
                    logger.info("tcpBinTest start...Port:{}", config.tcpBinTestPort);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).start();
        }
        if(!configPath.isEmpty()){
            logger.info("configPath:{}", Paths.get(configPath));
            try {
                new ConfigFileMonitor(Paths.get(new File(configPath).getAbsolutePath()), 5000, this).start();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
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

    void updateConfig(Config newConfig) {
        if (newConfig.logEnable != config.logEnable) {
            if (newConfig.logEnable) {
                try {
                    Common.setupConsoleLog(newConfig.logPath);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                }
            } else {
                Common.restoreOriginalStreams();
            }
        }

        if (newConfig.tcpBinTest != config.tcpBinTest) {
            if (newConfig.tcpBinTest) {
                echoServer = new EchoServer(newConfig.tcpBinTestPort);
                new Thread(() -> {
                    try {
                        echoServer.start();
                        logger.info("tcpBinTest start...Port:{}", config.tcpBinTestPort);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }).start();
            } else {
                if (echoServer != null) {
                    echoServer.shutdown();
                }
            }
        }
        this.config.copyFrom(newConfig);

        logger.info("Configuration updated");
    }

    public static class Config {
        public int port; // 端口配置
        public boolean logEnable = true;
        public String logPath = System.getProperty("java.io.tmpdir") + "/tcpmux.log";
        public boolean tcpBinTest = false;
        public int tcpBinTestPort = 55281;
        public List<Map<String, Object>> tcpRules;
        public List<Map<String, Object>> httpRules;

        public void copyFrom(Config config) {
            this.port = config.port;
            this.logEnable = config.logEnable;
            this.logPath = config.logPath;
            this.tcpRules = config.tcpRules;
            this.httpRules = config.httpRules;
        }
    }
}

class ConfigWatcher {
    private static final Logger logger = LoggerFactory.getLogger(ConfigWatcher.class);

    private static long sLastModifyTime = 0;


    public void watchConfigFile(Path path, Consumer<NettyProxyServer.Config> configConsumer) {
        try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
            path.getParent().register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
            while (true) {
                WatchKey key = watchService.take();
                if (key == null) {
                    break;
                }
                for (WatchEvent<?> event : key.pollEvents()) {
                    Path changed = (Path) event.context();
                    long lastModified = path.toFile().lastModified();
                    logger.info("file: {},sLastModifyTime:{}", path.getFileName(), sLastModifyTime);
                    if (changed.endsWith(path.getFileName()) && lastModified != sLastModifyTime && path.toFile().length() > 0) {
                        logger.info("Config file changed: " + changed);
                        sLastModifyTime = lastModified;
//                        NettyProxyServer.Config newConfig = NettyProxyServer.loadConfig(path.toString());
//                        configConsumer.accept(newConfig);
                    }
                }
//                boolean valid=key.reset();
//                if (!valid) {
//                    logger.error("Config file changed, but not valid");
//                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
            logger.error("Error watching config file", e);
            System.out.printf("error: %s%n", e.getMessage());
        } finally {
            logger.error("watchService is stopping");
            watchConfigFile(path, configConsumer);
        }
    }

    public static void main(String[] args) {
//        new Thread(() -> new ConfigWatcher().watchConfigFile(Paths.get(new File("").getAbsolutePath()), this::updateConfig)).start();
    }
}


class ConfigFileMonitor {
    private static final Logger logger = LoggerFactory.getLogger(ConfigFileMonitor.class);
    private final FileAlterationMonitor monitor;

    public ConfigFileMonitor(Path configFile, long pollingInterval, NettyProxyServer server) {
        // 创建观察器
        FileAlterationObserver observer = new FileAlterationObserver(configFile.getParent().toFile());

        // 配置文件监听器
        observer.addListener(new FileAlterationListenerAdaptor() {
            @Override
            public void onFileChange(File file) {
                logger.info("onFileChange: " + file);
                if (file.getName().equals(configFile.getFileName().toString())) {
                    logger.info("Configuration file changed: {}", file.getName());
                    try {
                        // 重新加载配置
                        server.updateConfig(NettyProxyServer.loadConfig(file.getAbsolutePath()));
                    } catch (Exception e) {
                        logger.error("Error reloading configuration: {}", e.getMessage());
                    }
                }
            }
        });

        // 创建并配置监控器
        monitor = new FileAlterationMonitor(pollingInterval, observer);
    }

    public void start() throws Exception {
        monitor.start(); // 开始监控
        logger.info("Started configuration file monitor.");
    }

    public void stop() throws Exception {
        monitor.stop(); // 停止监控
        logger.info("Stopped configuration file monitor.");
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

class EchoServer {
    private final int port;
    private Channel serverChannel;
    private EventLoopGroup group;

    public EchoServer(int port) {
        this.port = port;
    }

    public void start() throws Exception {
        group = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(group)
                    .channel(NioServerSocketChannel.class)
                    .localAddress(port)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {
                            ch.pipeline().addLast(new EchoServerHandler());
                        }
                    });

            ChannelFuture f = b.bind().sync(); // 绑定服务器
            serverChannel = f.channel();
            serverChannel.closeFuture().sync(); // 阻塞当前线程，直到服务器关闭
        } finally {
            shutdown();
        }
    }

    public void shutdown() {
        if (serverChannel != null) {
            serverChannel.close();
        }
        if (group != null) {
            try {
                group.shutdownGracefully().sync();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: " + EchoServer.class.getSimpleName() + " <port>");
            return;
        }
        int port = Integer.parseInt(args[0]);
        new EchoServer(port).start();
    }
}


class EchoServerHandler extends ChannelInboundHandlerAdapter {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ByteBuf in = (ByteBuf) msg;
        try {
            byte[] dataBytes;
            int length = in.readableBytes();
            if (in.hasArray()) {
                dataBytes = in.array();
            } else {
                dataBytes = new byte[length];
                in.getBytes(in.readerIndex(), dataBytes);
            }

            String received = new String(dataBytes, CharsetUtil.UTF_8);
            String hexData = bytesToHex(dataBytes); // 转换字节到十六进制字符串
            Map<String, Object> response = new HashMap<>();
            response.put("client-ip", ctx.channel().remoteAddress().toString());
            response.put("data", hexData);
            response.put("text-data", received);
            response.put("size", length);

            String jsonResponse = mapper.writeValueAsString(response);
            ByteBuf responseBuf = ctx.alloc().buffer();
            responseBuf.writeBytes(jsonResponse.getBytes(CharsetUtil.UTF_8));
            ctx.write(responseBuf);
            ctx.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            in.release();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString().trim(); // 用空格隔开每个十六进制数
    }
}

class Common {
    public static void closeOnFlush(Channel ch) {
        if (ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }

    private static PrintStream originalOut;
    private static PrintStream originalErr;
    private static PrintStream filePrintStream; // 引用文件流，以便可以关闭它

    public synchronized static void setupConsoleLog(String logFilePath) throws FileNotFoundException {
        if (filePrintStream != null) return;
        // 保存原始的控制台输出流
        originalOut = System.out;
        originalErr = System.err;

        // 设置文件输出流
        FileOutputStream fos = new FileOutputStream(logFilePath, true);
        filePrintStream = new PrintStream(fos);

        // 创建一个新的PrintStream，用于写入文件和控制台
        PrintStream dualPrintStream = new PrintStream(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                originalOut.write(b);  // 假设所有输出都通过System.out复制
                filePrintStream.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) {
                originalOut.write(b, off, len); // 假设所有输出都通过System.out复制
                filePrintStream.write(b, off, len);
            }

            @Override
            public void flush() {
                originalOut.flush();
                originalErr.flush();
                filePrintStream.flush();
            }

            @Override
            public void close() {
                originalOut.close();
                originalErr.close();
                filePrintStream.close();
            }
        });

        // 重新设置标准输出和错误输出
        System.setOut(dualPrintStream);
        System.setErr(dualPrintStream);
    }

    public synchronized static void restoreOriginalStreams() {
        // 关闭当前的PrintStream
        System.out.flush();
        System.err.flush();
        System.setOut(originalOut);
        System.setErr(originalErr);
        filePrintStream.close(); // 关闭文件输出流
        filePrintStream = null;
        originalErr = null;
        originalOut = null;
    }

}