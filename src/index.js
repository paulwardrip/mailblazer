
import dns from 'node:dns'

import scanner from './portscan.js'
import factory from './autoconf.js'
import domainiac from 'domainiac'

import NS from './nsroot.js'

const { Resolver } = dns.promises;

export default function mailblazer(verbose=false){
	const { portscan, imap, pop3, sortServers } = scanner(verbose);
	const { config, discover } = factory(verbose);

	const resolver = new Resolver();
	resolver.setServers([
		NS.Quad9.v4[0],
		NS.Level3.v4[0],
		NS.FreeNom.v4[0],
		NS.OpenDNS.v4[0],
		NS.OpenNIC.v4[0],
		NS.SafeDNS.v4[0],
		NS.DynDNS.v4[0],
		NS.Yandex.v4[0],
		NS.GermanPrivacyFeV.v4[0],
		NS.VeriSign.v4[0],
		NS.Xiala.v4[0],
		NS.Cloudflare.v4[0],
		NS.Google.v4[0]
	]);

	let VERBOSE = verbose;

	async function record(type, domain){
		return new Promise(async resolve=>{
			try {
				const items = await resolver.resolve(domain,type);
				resolve(items);
			} catch(ex) {
				resolve();
			}
		})
	}

	async function cname(domain){
		return new Promise(async resolve=>{
			let items = await record("CNAME", domain);
			items?.forEach(item=>{if (VERBOSE) console.log("[CNAME]", domain, item)});
			resolve(items?.length===1 ? items[0]: items?.length>1 ? items : null);
		})
	}

	async function srv(domain){
		return new Promise(async resolve=>{
			let output = [];
			let items = await record("SRV", domain);
			items?.forEach(item=>{
				if (item.port > 0 && item.name?.trim() !== "") {
					if (VERBOSE) console.log("[SRV]", domain, item);
					output.push(item);
				}
			});
			resolve(output);
		})
	}

	async function a(domain){
		return new Promise(async resolve=>{
			let items = await record("A", domain);
			items?.forEach(item=>{if (VERBOSE) console.log("[A]", domain, item)});
			resolve(items?.length > 0 ? domain: items);
		})
	}

	function add(data, results, srv) {
		if (results) {
			if (results instanceof Array) {
				for (let a of results) {
					if (srv) {
						if (!data.includes(a.name)) data.push(a.name);
					} else {
						if (!data.includes(a)) data.push(a);
					}
				}
			} else {
				if (!data.includes(results)) data.push(results);
			}
		}
		return data;
	}

	function autodisco(domain, email) {
		return new Promise(async resolve=>{

			// [SRV] autodiscover (Microsoft standard)
			//
			let automs=[ domain ];
			let autodisco = await srv("_autodiscover._tcp."+domain);
			automs = add(automs, autodisco, true);
			
			autodisco = await a("autodiscover."+domain);
			automs = add(automs, autodisco);
			
			autodisco = await cname("autodiscover."+domain);
			automs = add(automs, autodisco);
				
			if (automs.length > 0) {
				for (let conf of automs) {
					let servers = await discover(conf, email);
					if (servers) {
						return sortServers(servers,resolve);
					}
				}
			}
			resolve()
		})
	}

	function autoconf(domain) {
		return new Promise(async resolve=>{

			// [SRV] autoconfig (Mozilla standard)
			//
			let autoconf=[ domain ];
			let autosrv = await srv("_autoconfig._tcp."+domain);
			autoconf = add(autoconf, autosrv, true);
			
			autosrv = await a("autoconfig."+domain);
			autoconf = add(autoconf, autosrv);
			
			autosrv = await cname("autoconfig."+domain);
			autoconf = add(autoconf, autosrv);
				
			if (autoconf.length > 0) {
				for (let conf of autoconf) {
					let servers = await config(conf);
					if (servers) {
						return sortServers(servers,resolve);
					}
				}
			}
			resolve()
		})
	}

	function dnsdetector(domain) {
		return new Promise(async resolve=>{
			if (!domain) return resolve();
			if (domain.trim() === "") return resolve();

			if (VERBOSE) console.log("\n\nDNSdetector", domain);

			// Check for dns service entries for email.
			//
			// [SRV] IMAP
			//
			let srvr = await srv("_imap._tcp."+domain);
			if (srvr.length > 0) {
				srvr.sort(function(a,b){
					return (a.priority < b.priority) ? -1 : 1
				})
				srvr = srvr[0];

				return resolve({ hostname: srvr.name,
					port: srvr.port,
					type: "imap",
					ssl: (srvr.port > 900),
					source: "SRV" });
			}


			// Perform Mozilla autoconfig ...
			let server = await autoconf(domain);
			if (server) return resolve(server);
			
			// ... and failing that, Microsoft autodiscover
			server = await autodisco(domain, `info@${domain}`);
			if (server) return resolve(server);


			// Check for [A] or [CNAME] records for imap(4).domain.com
			// Followed by port scanning these subdomains.
			//
			let scan, imapr = await a("imap."+domain);
			if (!imapr) imapr = await cname("imap."+domain);
			if (!imapr) imapr = await a("imap4."+domain);
			if (!imapr) imapr = await cname("imap4."+domain);
			if (imapr) {
				server = await imap(imapr, "dns");
			} else {
				server = await imap([ "imap."+domain, "imap4."+domain ], "portscan");
			}
			if (server) return resolve(server);
			

			// [A] or [CNAME] mail.domain.com
			// 
			let mailr = await a("mail."+domain);
			if (!mailr) mailr = await cname("mail."+domain);
			if (mailr) {
				server = await portscan(mailr, "dns");
			} else {
				server = await portscan([ domain, "mail."+domain ], "portscan");
			}
			if (server) return resolve(server);
					

			// [A] or [CNAME] pop(3).domain.com
			// 
			let pop3r = await a("pop3."+domain);
			if (!pop3r) pop3r = await cname("pop3."+domain);
			if (!pop3r) pop3r = await a("pop."+domain);
			if (!pop3r) pop3r = await cname("pop."+domain);
			if (pop3r) {
				server = await pop3(pop3r, "dns");
			} else {
				server = await pop3([ "pop3."+domain, "pop."+domain ], "portscan");
			}

			if (!server) {
				let root = domainiac.extract(domain);
				if (root.subdomains.length > 0) {
					server = await dnsdetector(root.domain);
					if (!server && root.subdomains.length === 1) {
						server = await dnsdetector(`${root.subdomains[0]}.mail.${root.domain}`)
					}
				}
				if (!server && root.sld) {
					function fixso(alternate){
						server.source = "alternate";
						server.comment = domain + " produced no results, but this server was found under \""+
							alternate + "\" it's possible they're related.";
					}

					if (/org?/.test(root.sld)) {
						server = await dnsdetector(root.name+".org");
						if (server) fixso(root.name+".org");
					} else if (/net?/.test(root.sld)) {
						server = await dnsdetector(root.name+".net");
						if (server) fixso(root.name+".net");
					} else {
						server = await dnsdetector(root.name+".com");
						if (server) fixso(root.name+".com");
					}
				} 
			}

			resolve (server);
		})
	}

	return {
		resolve: dnsdetector
	}
}