
import { Socket } from "node:net"
import { createSocket } from "node:dgram"
import async from "async"

export default function(verbose=false) {
    let VERBOSE = verbose

    function scanner (host, port) {
        return new Promise((resolve, reject) => {    
            function udp(){
                const socket = createSocket("udp4")

                socket.on('connect', () => {
                    if (VERBOSE) console.log(` *** portscanner<udp> // hit // ${host}[:${port}] ***`)
                    socket.close()
                    resolve(true);
                });
                socket.on('error', () => {
                    if (VERBOSE) console.log(` --- p___sc_____<udp> .. ___ .. ${host}[:${port}] ---`)
                    socket.close();
                    tcp();
                });

                socket.connect(port, host);
            }    

            function tcp() {
                const socket = new Socket();
                socket.setTimeout(15000)
                socket.on('connect', () => {
                    if (VERBOSE) console.log(` *** portscanner<tcp> // hit // ${host}[:${port}] ***`)
                    socket.destroy();
                    resolve(true);
                });
                socket.on('timeout', () => {
                    if (VERBOSE) console.log(` --- p___sc_____<tcp> .. ___ .. ${host}[:${port}] ---`)
                    socket.destroy();
                    resolve(false);
                });
                socket.on('error', () => {
                    if (VERBOSE) console.log(` --- p___sc_____<tcp> .. ___ .. ${host}[:${port}] ---`)
                    socket.destroy();
                    resolve(false);
                });
                socket.connect(port, host);
            }

            if ([143, 993, 995].includes(port)) {
                udp();
            } else {
                tcp();
            }
        });
    };

    function pop3(dom, source){
        return new Promise(async resolve=>{
            if (typeof dom === "object" && dom instanceof Array) {
                for (let d of dom) {
                    let p = await pop3(d, source);
                    if (p) return resolve(p);
                }
                resolve();
            } else {
                let q = queueMaker();
                q.pop3(dom, source);               

                async.parallel(q.queue(), function(){
                    let servers = q.servers();
                    sortServers(servers,resolve);
                });
            }
        })
    }

    function imap(dom, source){
        return new Promise(async resolve=>{
            if (typeof dom === "object" && dom instanceof Array) {
                for (let d of dom) {
                    let p = await imap(d, source);
                    if (p) return resolve(p);
                }
                resolve();
            } else {
                let q = queueMaker();
                q.imap(dom, source);                

                async.parallel(q.queue(), function(){
                    let servers = q.servers();
                    sortServers(servers,resolve);
                });
            }
        })
    }

    function portscan(dom, source){
        return new Promise(async resolve=>{
            if (typeof dom === "object" && dom instanceof Array) {
                for (let d of dom) {
                    let p = await imap(d, source);
                    if (!p) p = await webmail(d, source);
                    if (!p) p = await pop3(d, source);
                    if (p) return resolve(p);
                }
                resolve();
            } else {
                let q = queueMaker();
                q.imap(dom, source);
                q.pop3(dom, source);
                q.webmail(dom, source);                

                async.parallel(q.queue(), function(){
                    let servers = q.servers();
                    sortServers(servers,resolve);
                });
            }
        })
    }

    function queueMaker() {
        let queue = [];
        let servers = []

        function pusher(hostname, port, type, ssl, source) {
            queue.push(function(cb){
                (async()=>{
                    let result = await scanner(hostname, port);
                    if (result) {
                        servers.push({ hostname, port, type, ssl, source })
                    }
                    cb();
                })()
            })
        }

        function imap(hostname, source) {
            pusher(hostname, 993, "imap", true, source)
            pusher(hostname, 143, "imap", false, source)
        }

        function pop3(hostname, source) {
            pusher(hostname, 995, "pop3", true, source)
            pusher(hostname, 110, "pop3", false, source)
        }

        function webmail(hostname, source) {
            pusher(hostname, 2096, "webmail", true, source)
            pusher(hostname, 2095, "webmail", false, source)
        }

        return {
            imap,
            pop3,
            webmail,
            queue() { return queue },
            servers() { return servers }
        }
    }
    
    function sortServers(servers, resolve){
        if (servers.length > 1) {
            servers.sort(function(a,b){
                return a.port > b.port ? -1 : 1
            })
            servers.sort(function(a,b){
                if (a.type !== b.type) {
                    return a.type === "imap" ? -1 : a.type === "webmail" ? 1 : -1
                } else {
                    return 0;
                }
            })
        }

        if (servers.length > 0) {
            resolve(servers[0])
        } else {
            resolve()
        }
    }

    return {
        imap,
        pop3,
        portscan,
        sortServers
    }
}