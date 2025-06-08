
import terser from '@rollup/plugin-terser';
import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import replace from '@rollup/plugin-replace';
import json from '@rollup/plugin-json';

export default {
  input: 'src/ui/server.js',
  output: {
    format: 'esm',
    file: 'gen/bundle.min.js'
  },
  plugins: [
    replace({
      "import dev from '../development.js'", "import dev from '../../gen/static.js'"
    }),
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