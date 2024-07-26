This tool is a proxy server based on the Netty framework, also referred to as a Server RPC Central Gateway, or TCP Port Multiplexing and Forwarding utility, exposing only one HOST and port externally. It can forward various types of network requests to designated target servers based on predefined rules. By editing the `config.yml` configuration file, users can set specific forwarding rules, including the handling of TCP and HTTP requests. This design makes the tool highly suitable for complex network environments, such as load balancing, network request routing, or serving as middleware for protocol conversion.

### Main Features:
- **Dynamic Port Configuration**: Set the listening port through the configuration file, facilitating easy adjustment and adaptation to different environments.
- **Multi-Protocol Support**: Supports multiple network protocols including TCP and HTTP, capable of automatically identifying and applying the appropriate processing rules based on the content of the data stream.
- **Flexible Rule Definition**: Users can define various forwarding rules in the configuration file, including matching patterns, target server addresses, and ports.
- **Real-Time Configuration Updates**: Supports real-time updates to the configuration file; the server can automatically reload new configurations when the file is modified, without the need for a restart.

This proxy server tool is ideal for developers and system administrators who require high-performance network operations and precise traffic control. It offers powerful capabilities for handling network traffic and simplifies management tasks through configuration files.
