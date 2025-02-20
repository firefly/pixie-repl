import { nodeResolve } from '@rollup/plugin-node-resolve';

export default [
  {
    input: "./lib.esm/index-browser.js",
    output: {
      file: "./web/dist/pixie-repl.js",
      format: "esm",
      sourcemap: true
    },
    treeshake: true,
    context: "this",
    plugins: [
      nodeResolve({ browser: true })
    ]
  }
];
