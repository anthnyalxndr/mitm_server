import { EventEmitter } from "events";
EventEmitter.captureRejections = true;
import { dirname } from "path";
import child_process from "node:child_process";
import { fileURLToPath } from "url";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import events from "node:events";
import net from "node:net";
import path from "node:path";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const execSync = child_process.execSync;

type PromiseWithResolvers<T> = ReturnType<typeof Promise.withResolvers<T>>;

/**
 * Data passed to createTunnel and the callbacks it composes.
 * If an error is passed, it is assumed that the tunnel creation failed.
 */
export interface TunnelData {
    /** The hostname for which the tunnel is being created */
    hostname: string;
    /** The client socket connection */
    clientSock: net.Socket;
    /** The server instance or promise resolving to a server */
    server: Server | Promise<Server>;
    /** Optional secure context for TLS connections */
    context?: SecureContext;
    /** Optional error that occurred during tunnel creation */
    error?: Error;
    /** Optional server socket connection */
    serverSock?: net.Socket;
    /** Optional promise resolvers for the server */
    serverPromise?: PromiseWithResolvers<Server>;
}

/**
 * Function type for handling HTTP requests in middleware pattern
 */
export type RequestHandler = (
    req: http.IncomingMessage,
    res: Response,
    next: RequestHandler
) => void;

/**
 * Configuration options for initializing the CachingProxy
 */
export interface Options {
    /** Timeout in milliseconds of inactivity to wait for server shutdown */
    serverTimeout?: number;
    /** Path to certificate cache directory to store TLS certificates */
    certCache: string;
    /** Path to root CA certificate file */
    caCertPath: string;
    /** Path to CA private key file */
    caKeyPath: string;
    /** Path to OpenSSL configuration file */
    openSSLConfigPath: string;
    /** Optional custom request handler function */
    requestHandler?: (req: http.IncomingMessage, res: Response) => void;
}

/**
 * Extended HTTP server interface with additional properties
 */
export interface Server extends http.Server {
    /** Port number the server is listening on */
    port?: number;
    /** Hostname the server is bound to */
    hostname?: string;
    /** https.Server.setSecureContext method */
    setSecureContext?(context: SecureContext): void;
}

/**
 * Alias for the node's standard response type within a request listener.
 */
export type Response = http.ServerResponse & {
    req: http.IncomingMessage;
};

/**
 * Interface for node https secure context configuration
 */
export interface SecureContext {
    /** Private key buffer */
    key: Buffer;
    /** Certificate buffer */
    cert: Buffer;
}

/**
 * Type alias for hostname strings
 */
type Hostname = string;

/**
 * Main MITM (Man-in-the-Middle) proxy class that handles HTTP/HTTPS tunneling
 * with certificate generation and caching capabilities
 */
export default class MitmServer extends events.EventEmitter {
    /** Root CA certificate file content */
    caCert: string;
    /** Root CA private key file content */
    caKey: string;
    /** Asynchronous cache of TLS certificates by hostname */
    certCacheAsync: Map<Hostname, Promise<SecureContext>>;
    /** Directory for storing TLS certificates */
    certCache: string;
    /** Hostname the proxy is bound to */
    hostname?: string;
    /** Main HTTP server instance */
    httpServer: Server;
    /** Path to OpenSSL configuration file */
    openSSLConfigPath: string;
    /** Path to private key file */
    privateKeyPath: string;
    /** Port the proxy is listening on */
    port: number | null = null;
    /** Optional custom request handler function */
    requestHandler?: ((
        req: http.IncomingMessage,
        res: Response,
        next?: RequestHandler
    ) => void) | undefined;
    /** Map of hostname to server instances. Each hostname has its own server instance such that new requests to the same hostname are handled by the same server instance. */
    servers: Map<string, Server>;
    /** Map of hostname to server instances. Each hostname has its own server instance such that new requests to the same hostname are handled by the same server instance. */
    serverMapAsync: Map<string, Promise<Server>>;
    /** Timeout in milliseconds of activity to wait for server shutdown */
    serverTimeout?: number;
    /** Promise tracking shutdown operation */
    shutdownPromise: Promise<void> | null = null;
    /** Timeout in milliseconds of activity to wait for proxy shutdown */
    shutdownTimeout?: NodeJS.Timeout;
    /** Default timeout for requests in milliseconds */
    static RequestTimeout = 3000;

    /**
     * Creates a new CachingProxy instance
     * @param options - Configuration options for the proxy
     */
    constructor(options: Options) {
        super();
        this.caCert = options.caCertPath;
        this.caKey = options.caKeyPath;
        this.certCacheAsync = new Map();
        this.certCache = options.certCache;
        this.httpServer = http.createServer();
        this.openSSLConfigPath = options.openSSLConfigPath;
        this.privateKeyPath = path.resolve(this.certCache, "key.pem");
        this.requestHandler = options.requestHandler;
        this.servers = new Map();
        this.serverMapAsync = new Map();
        this.serverTimeout = options.serverTimeout ?? 60000;
        this.#bindListeners();
        fs.mkdirSync(this.certCache, { recursive: true, mode: 0o755 });
        const { size: keySize } = fs.statSync(this.privateKeyPath);
        if (keySize === 0)
            execSync(`openssl genrsa -out ${this.privateKeyPath} 2048`);
    }

    /**
     * Initiates the shutdown process for the proxy
     * @returns Promise that resolves when shutdown is complete
     */
    shutdown() {
        if (this.shutdownTimeout) return;
        this.shutdownTimeout = setTimeout(() => {
            if (this.servers.size === 0 && !this.httpServer.listening) {
                console.log("Proxy shutdown successfully.");
                process.exit(0);
            } else {
                console.error(
                    "Forced shutdown of proxy occured b/c shutdown took too long (+30s)."
                );
                process.exit(1);
            }
        }, 30000);
        this.#shutdown();
        return;
    }

    /**
     * Binds event listeners for process signals to ensure graceful shutdown.
     * @private
     */
    private bindListeners() {
        process.on("SIGINT", this.shutdown.bind(this));
        process.on("SIGTERM", this.shutdown.bind(this));
    }

    /**
     * Gracefully shuts down a specific server instance
     * @param server - Server instance to shutdown
     * @private
     */
    private shutdownServer(server: Promise<Server>) {
        try {
            server.then((s) => {
                s.close(); // Stop incoming connections
                const hostname = s.hostname;
                if (hostname) this.serverMapAsync.delete(hostname);
                s.closeAllConnections(); // Close remaining connections
            });
        } catch (e) {
            const cause = e instanceof Error ? e : new Error(String(e));
            console.error(new Error("Unable to shutdown server.", { cause }));
        }
    }

    /**
     * Performs the main shutdown sequence
     * @private
     */
    #shutdown() {
        try {
            const serverPromises = [
                ...this.serverMapAsync.values(),
                Promise.resolve(this.httpServer),
            ];

            serverPromises.forEach((p) => this.#shutdownServer(p));
        } catch (e) {
            const cause = e instanceof Error ? e : new Error(String(e));
            console.error(new Error("Unable to shutdown proxy.", { cause }));
            process.exit(1);
        }
    }

    /**
     * Starts the proxy server listening on specified port and hostname
     * @param port - Port number to listen on
     * @param hostname - Hostname to bind to
     * @param cb - Optional callback function
     */
    listen(port: number, hostname: string, cb?: () => void) {
        this.httpServer.listen({ port, hostname }, () => {
            try {
                this.hostname = hostname;
                this.httpServer.port = port;
                this.httpServer.hostname = hostname;
                this.httpServer.on("connect", this.onConnect.bind(this));
                this.httpServer.on("request", this.onRequest.bind(this));
                if (cb) cb();
            } catch (e) {
                const cause = e instanceof Error ? e : new Error(String(e));
                throw new Error("Unable to listen on port and hostname.", {
                    cause,
                });
            }
        });
    }

    /**
     * Handles the listening event for a server instance
     * @param data - Tunnel data containing server information
     * @param cb - Callback function to execute after setup
     */
    onListening(data: TunnelData, cb: (err?: unknown) => void) {
        try {
            if (data.error instanceof Error) return cb();
            if (data.server instanceof Promise) return;
            const hostname = this.hostname ?? "localhost";
            const addr = data.server.address() as net.AddressInfo;
            data.server.port = addr.port;
            data.server.hostname = hostname;
            data.server.on(
                "clientError",
                (err: NodeJS.ErrnoException, socket: net.Socket) => {
                    if (err.code === "ECONNRESET" || !socket.writable) return;
                    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
                }
            );

            this.#watchServer(data.server);
            data.server.on("request", (req, res) => {
                if (this.requestHandler) {
                    this.requestHandler(
                        req,
                        res,
                        this.onRequest.bind(this, req, res)
                    );
                } else {
                    this.onRequest(req, res);
                }
            });

            return cb();
        } catch (e) {
            const cause = e instanceof Error ? e : new Error(String(e));
            data.error ??= new Error("Listening handler failed.", { cause });
            cb();
        }
    }
    /**
     * Handles incoming HTTP requests
     * @param req - HTTP request object
     * @param res - HTTP response object
     * @private
     */
    onRequest(req: http.IncomingMessage, res: Response) {
        try {
            const { method, headers, url: path } = req;
            const { hostname, port } = this.splitHost(headers.host);
            const module = port === 80 ? http : https;

            if (!hostname || !path) {
                res.writeHead(400, http.STATUS_CODES[400]);
                return res.end("Invalid request.");
            }
            if (hostname === this.httpServer.hostname) {
                res.writeHead(400, http.STATUS_CODES[400]);
                return res.end(
                    "This proxy only supports CONNECT tunneling not direct HTTP requests"
                );
            }
            // Tunnel with the origin server.
            const options = { method, port, hostname, headers, path };
            req.pipe(
                module
                    .request(options, (proxyRes: http.IncomingMessage) => {
                        if (!proxyRes.statusCode)
                            throw new Error(
                                "Malformed response missing status code."
                            );
                        if (!res.writable) return;
                        if (res.headersSent) return res.end();
                        res.writeHead(proxyRes.statusCode, proxyRes.headers);
                        proxyRes.pipe(res);
                    })
                    .on("error", (err: NodeJS.ErrnoException) => {
                        if (err.code === "ENOTFOUND") {
                            if (res.writable) {
                                if (!res.headersSent)
                                    res.writeHead(500, http.STATUS_CODES[500]);
                                res.write("The proxy appears to be offline.");
                            }
                            res.end();
                        }
                    })
            );
        } catch (err) {
            const cause = err instanceof Error ? err : new Error(String(err));
            console.error(
                new Error("An error occured while handling a request.", {
                    cause,
                })
            );
            res.writeHead(500, http.STATUS_CODES[500]);
            res.end();
        }
    }

    /**
     * Splits a request's host header into a hostname and port pair.
     * @param reqUrl - Request URL string
     * @returns Object containing hostname and port
     * @private
     */
    splitHost(reqUrl: string | undefined): { hostname: string; port: number } {
        if (!reqUrl) throw new Error("Request URL is undefined");
        const parts = reqUrl.split(":", 2);
        const [hostname, port] = parts;
        if (!hostname)
            throw new Error(`Host header missing from request for ${reqUrl}`);
        const portNum = port ? parseInt(port, 10) : 443;
        return { hostname, port: portNum };
    }

    /**
     * Creates a server instance with the provided secure context
     * @param data - Tunnel data containing server and context information
     * @param cb - Callback function to execute after server creation
     */
    createServer(data: TunnelData, cb: (val?: unknown) => void) {
        try {
            if (data.server instanceof Promise) return;
            if (data.error instanceof Error) return cb();
            if (!data.context) {
                data.error = new Error(
                    "Unable to create server. No context provided."
                );
                return cb();
            }
            const { server, context } = data;
            data.server.setSecureContext?.(context);
            const hostname = this.hostname ?? "localhost";
            server.listen(0, hostname, cb);
        } catch (err) {
            const cause = err instanceof Error ? err : new Error(String(err));
            data.error ??= new Error("Unable to create server.", { cause });
            cb();
        }
    }

    /**
     * Composes multiple functions into a single function that executes them in sequence
     * @param functions - Array of functions to compose
     * @returns Composed function that executes all functions in sequence
     */
    compose(...functions: ((...args: unknown[]) => void)[]) {
        return (initialArg: unknown, callback = () => {}) => {
            const composition = functions.reduceRight((prev, next) => {
                return () => next(initialArg, prev);
            }, callback);

            return composition(initialArg);
        };
    }

    /**
     * Retrieves SSL certificate for a hostname from the cache or filesystem
     * @param data - Tunnel data containing hostname information
     * @param cb - Callback function to execute after certificate retrieval
     */
    getCert(data: TunnelData, cb: () => void) {
        if (data.error instanceof Error) return cb();
        try {
            const { hostname } = data;
            const certPath = path.resolve(this.certCache, hostname + "-cert.pem");
            const keyPath = this.privateKeyPath;
            fs.readFile(keyPath, (err, key) => {
                if (err) {
                    data.error = err;
                    return cb();
                }
                fs.readFile(certPath, (err, cert) => {
                    if (err) data.error = err;
                    else data.context = { key, cert };
                    cb();
                });
            });
        } catch (err) {
            const cause = err instanceof Error ? err : new Error(String(err));
            data.error ??= new Error("Unable to get certificate.", { cause });
            cb();
        }
    }

    /**
     * Generates SSL certificate for a hostname using OpenSSL
     * @param data - Tunnel data containing hostname information
     * @param cb - Callback function to execute after certificate generation
     */
    makeCert(data: TunnelData, cb: (val?: unknown) => void) {
        if (data.error instanceof Error) return cb();
        try {
            const { hostname } = data;
            // TODO: Make sure I check for cert existence in the cache first.
            const opensslConfig = path.join(__dirname, this.openSSLConfigPath);
            const keyPath = this.privateKeyPath;
            const csrPath = path.resolve(this.certCache, hostname + ".csr");
            const certPath = path.resolve(this.certCache, hostname + "-cert.pem");
            const csrCmd =
                'ALTNAME="DNS:' +
                hostname +
                '" openssl req -new -key ' +
                keyPath +
                " -out " +
                csrPath +
                ' -nodes -subj "/C=US/ST=OR/L=PDX/O=NR/CN=' +
                hostname +
                '"' +
                " -extensions v3_req -config " +
                opensslConfig;
            const certCmd =
                'ALTNAME="DNS:' +
                hostname +
                '" openssl x509 -sha256 -req -days 3650  -CA ' +
                this.caCert +
                " -CAkey " +
                this.caKey +
                " -in " +
                csrPath +
                " -out " +
                certPath +
                " -set_serial " +
                String(Math.floor(Number.MAX_SAFE_INTEGER * Math.random())) +
                " -extensions v3_req -extfile " +
                opensslConfig;
            const exec = child_process.exec;
            exec(csrCmd, (err) => {
                if (err) {
                    data.error = err;
                    return cb();
                }
                exec(certCmd, (err) => {
                    if (err) data.error = err;
                    cb();
                });
            });
        } catch (err) {
            const cause = err instanceof Error ? err : new Error(String(err));
            data.error ??= new Error("Unable to make certificate.", { cause });
            cb();
        }
    }

    /**
     * Creates a tunnel between client and server sockets
     * @param data - Tunnel data containing client and server socket information
     */
    tunnel(data: TunnelData) {
        try {
            if (data.error instanceof Error) throw data.error;
            const server = data.server as Server;
            const { clientSock } = data;
            if (!server.port || !server.hostname) {
                throw new Error(
                    "Unable to create tunnel. " +
                        "Server missing port, hostname, or both."
                );
            }
            const serverSock = net.connect(server.port, server.hostname, () => {
                data.serverSock = serverSock;
                clientSock.write("HTTP/1.1 200 OK\r\n\r\n");
                clientSock.pipe(serverSock);
                serverSock.pipe(clientSock);
                data.serverPromise?.resolve(server);
            });
            clientSock.on("error", () => clientSock.unpipe(serverSock));
            serverSock.on("error", () => serverSock.unpipe(clientSock));
        } catch (err) {
            const e = err instanceof Error ? err : new Error(String(err));
            process.nextTick(() => {
                const server = data.server as Server;
                data.serverPromise?.reject(e);
                server.emit("error", e);
            });
        }
    }

    /**
     * Creates a tunnel between client and server
     * @param data - An object containing the server and client socket making up the tunnel.
     * @private
     */
    createTunnel(data: TunnelData) {
        if (data.server instanceof Promise) {
            data.server
                .then((server) => void this.createTunnel({ ...data, server }))
                .catch((err: unknown) => {
                    const e =
                        err instanceof Error ? err : new Error(String(err));
                    if (data.server instanceof Promise) {
                        data.server.then((s) => s.emit("error", e));
                    } else {
                        data.server.emit("error", e);
                    }
                });
            return;
        }
        const fns = [];
        if (data.server !== this.httpServer && !data.server.listening) {
            fns.push(
                this.makeCert.bind(this),
                this.getCert.bind(this),
                this.createServer.bind(this),
                this.onListening.bind(this)
            );
        }
        fns.push(this.tunnel.bind(this));
        return this.compose(...fns as ((...args: unknown[]) => void)[])(data);
    }

    /**
     * Handles HTTP CONNECT requests
     * @param req - HTTP request object
     * @param clientSock - Network socket
     * @private
     */
    onConnect(req: http.IncomingMessage, clientSock: net.Socket) {
        const { hostname, port } = this.splitHost(req.headers.host);
        const cachedServer = this.serverMapAsync.get(hostname);
        const server =
            port !== 443
                ? this.httpServer
                : cachedServer ?? https.createServer();
        let serverPromise;
        if (!this.serverMapAsync.has(hostname) && port === 443) {
            serverPromise = Promise.withResolvers<Server>();
            this.serverMapAsync.set(hostname, serverPromise.promise);
        }
        const data = { hostname, clientSock, server, serverPromise };
        this.createTunnel(data);
    }

    /**
     * Sets up server connection monitoring for automatic server shutdown on inactivity.
     * @param server - Server to monitor
     * @private
     */
    #watchServer(server: Server) {
        try {
            const timer = setTimeout(
                () => this.#shutdownServer(Promise.resolve(server)),
                this.serverTimeout
            );
            const debounce = () => {
                clearTimeout(timer);
                this.#watchServer(server);
            };

            server.once("connection", debounce);
        } catch (err) {
            throw new Error("Unable to create server connection watcher.", {
                cause: err,
            });
        }
    }
}
