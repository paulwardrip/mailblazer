
	import fs from 'fs';
	import path from 'path';

	if (fs.existsSync(path.resolve("gen"))) fs.rmSync(path.resolve("gen"), { recursive: true });
	if (fs.existsSync(path.resolve("dist"))) fs.rmSync(path.resolve("dist"), { recursive: true });

	fs.mkdirSync(path.resolve("gen/linux"), { recursive: true });
	fs.mkdirSync(path.resolve("gen/win"), { recursive: true });
	
	fs.mkdirSync(path.resolve("dist"));
