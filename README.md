# MITM Server

A TypeScript-based Man-in-the-Middle (MITM) proxy server that can intercept and inspect unencrypted HTTPS traffic on your machine. It achieves this by dynamically creating SSL certificates for each domains it intercepts, completing a TLS handshake with the client, establishing a connection to the destination server, and tunneling the client request to the destination server, and the server response back to the client. For more information on proxies and tunneling see MDN's article: [Proxy servers and tunneling](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling).

Note: The proxy currently only supports HTTP/1.1.

## Features

- Dynamic SSL certificate generation
- HTTPS interception
- Automatic certificate caching
- Event-based architecture
- TypeScript support
- Custom request handling

## Prerequisites

The following sections define prerquisites for running the proxy. See the installation section for more details.

### System Requirements
- Node.js 16.x or higher
- OpenSSL installed on your system
- tsx (TypeScript execution engine)
- A valid root CA certificate and private key

### Proxy Configuration
Before using the proxy, you need to configure either your browser or system to use it. See the installation section for more information.

### Root Certificate Configuration
You must install and trust the CA certificate used by the proxy in your system's trust store. Otherwise, browsers will show security warnings. Run `create_root_cert` to create a root CA credentials.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/anthnyalxndr/node_mitm_proxy.git
cd node_mitm_proxy
```

2. Install dependencies:
```bash
npm install
```

3. Create your root certificate (if you haven't already):
```bash
./create_root_cert
```

4. Install and trust the root certificate on your system:

   **macOS**: 
     ```bash
     # Double-click the ca-cert.pem file created by `create_root_cert` and 
     # add it to the System keychain. 
     # Or use the command line:
     sudo security add-trusted-cert -d -r \
       trustRoot -k /Library/Keychains/System.keychain ca-cert.pem
     ```
   **Windows**: 
     ```bash
     # Double-click the ca-cert.pem file and install it in the "Trusted Root Certification Authorities" store
     # Or use PowerShell:
     Import-Certificate -FilePath ca-cert.pem -CertStoreLocation Cert:\LocalMachine\Root
     ```
   **Linux**: 
     ```bash
     # Copy the certificate to the system store
     sudo cp ca-cert.pem /usr/local/share/ca-certificates/
     sudo update-ca-certificates
     ```

5. Configure your system or browser to use the proxy:
   - **Browser Configuration**:
     - **Firefox**:
       1. Open Settings
       2. Search for "proxy"
       3. Under "Network Settings", click "Settings"
       4. Select "Manual proxy configuration"
       5. Enter your proxy address and port
       6. Click "OK"
     - **Chrome/Edge**:
       1. Open Settings
       2. Search for "proxy"
       3. Click "Open your computer's proxy settings"
       4.  Under "Manual proxy setup", enable "Use a proxy server" OR follow the directions in the next section to automate the manual process.
       5.  Enter your proxy address (e.g., `localhost`) and port (e.g., `8080`)
       6.  Click "Save"
   
   - **System Configuration**:

       **macOS**:
       ```bash
       # Set HTTP proxy
       networksetup -setwebproxy "Wi-Fi" localhost 8080
       # Set HTTPS proxy
       networksetup -setsecurewebproxy "Wi-Fi" localhost 8080
       # To disable the proxy
       networksetup -setwebproxystate "Wi-Fi" off
       networksetup -setsecurewebproxystate "Wi-Fi" off
       ```
       **Linux**:
       ```bash
       # Set HTTP proxy
       export http_proxy=http://localhost:8080
       export HTTP_PROXY=http://localhost:8080
       # Set HTTPS proxy
       export https_proxy=http://localhost:8080
       export HTTPS_PROXY=http://localhost:8080
       # To disable the proxy
       unset http_proxy HTTP_PROXY https_proxy HTTPS_PROXY
       ```
       **Windows** (PowerShell):
       ```powershell
       # Set HTTP proxy
       Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value "localhost:8080"
       Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
       # To disable the proxy
       Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0
       ```

## Usage

### Basic Usage

*example.ts*
```typescript
import MitmProxy from './mitm_proxy';

const proxy = new MitmProxy({
  caCertPath: './ca-cert.pem',
  caKeyPath: './ca-key.pem',
  certCache: './cert-cache'
});

// Start the proxy
await proxy.listen(8080, 'localhost');
```

Run your code using `tsx`.
```bash
npx tsx example.ts
```

### Custom Request Handling

You can provide a custom request handler to inspect or modify requests and responses:

*example.ts*
```typescript
import MitmProxy from './mitm_proxy';
import type { IncomingMessage, ServerResponse } from 'http';

const proxy = new MitmProxy({
  caCertPath: './ca-cert.pem',
  caKeyPath: './ca-key.pem',
  certCache: './cert-cache',
  requestHandler: async (req: IncomingMessage, res: ServerResponse) => {
    // Log request details
    console.log(`Intercepted request to: ${req.url}`);
    
    // Modify request headers
    req.headers['x-custom-header'] = 'modified';
    
    // You can also modify the response
    res.on('finish', () => {
      console.log(`Response status: ${res.statusCode}`);
    });
  }
});

proxy.listen(8080, 'localhost');
```

### Troubleshooting
If you're having issues:
   - Verify the proxy is running and accessible
   - Check that the port isn't blocked by a firewall
   - Ensure the root CA certificate is properly installed and trusted
   - Try clearing your browser's cache in its privacy settings.

## Configuration

The proxy accepts the following configuration options:

- `caCertPath`: Path to your CA certificate file
- `caKeyPath`: Path to your CA private key file
- `certCache`: Directory where generated certificates will be stored
- `serverTimeout`: Optional timeout for inactive servers (default: 60000ms)
- `requestHandler`: Optional function to handle requests before they are proxied

## API Reference

### `new MitmProxy(options: Options)`

Creates a new MITM proxy instance.

#### Options

```typescript
interface Options {
  caCertPath: string;
  caKeyPath: string;
  certCache: string;
  serverTimeout?: number;
  requestHandler?: (req: IncomingMessage, res: ServerResponse) => Promise<void> | void;
}
```

### `proxy.listen(port: number, hostname: string, cb?: () => void)`

Starts the proxy server listening on the specified port and hostname.

### `proxy.shutdown()`

Gracefully shuts down the proxy server and all its child servers. This function is automatically called upon a SIGINT or SIGTERM signal being sent to the process.

## Security Considerations

⚠️ **Important**: This proxy is intended for personal use only. Using it in production or on untrusted networks could expose sensitive information.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
