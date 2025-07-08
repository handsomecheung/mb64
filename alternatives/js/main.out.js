import * as mb64 from "./mb64.js";

const filepath = process.argv[2];
const output = process.argv[3];
const key = process.env.MBKEY;
mb64.RenderOutFile(key, filepath, output);
