import { lib, typeChecked } from "@mslmio/eslint-config";

export default [
  { ignores: ["dist/**", "node_modules/**", ".wrangler/**"] },
  ...lib,
  typeChecked(import.meta.dirname),
];
