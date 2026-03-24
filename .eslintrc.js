module.exports = {
  root: true,
  extends: ['universe/native', 'universe/web'],
  ignorePatterns: ['build'],
  rules: {
    'node/handle-callback-err': 'off',
  },
};
