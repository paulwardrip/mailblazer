
	import index from './index.js'

	let params = process.argv;	
	params.splice(0, /\/node/.test(params[0]) ? 2 : 1);
	
	let verbose = (params.includes("--verbose") || params.includes("-v"));
	if (verbose) {
		let index = params.indexOf("--verbose");
		if (index === -1) index = params.indexOf("-v");
		if (index > -1) params.splice(index, 1);
	}

	if (params.length === 0) {
		console.log("usage: mailblazer <domain> [--v,--verbose]: returns JSON\n"+
			" - find (imap/pop3) servers for an email domain, using: a) dns b) mozilla autoconfig c) microsoft autodiscover d) port scanning.")
	} else {
		let dom;
		while (dom = params.pop()) {
			console.log("Mail servers for domain:", dom);

			index(verbose).resolve(dom).then(server=>{
				console.log(server?server:"Not Found.")
			})
		}
	}
