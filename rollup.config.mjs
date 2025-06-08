
import terser from '@rollup/plugin-terser';
import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import json from '@rollup/plugin-json';

export default {
  input: 'src/cli.js',
  output: {
    format: 'esm',
    file: 'gen/bundle.min.js'
  },
  plugins: [
    commonjs(),
    resolve({
      preferBuiltins: true
    }),
    json(),
    terser({
      format: {
        comments: false
      }
    })
  ]
};