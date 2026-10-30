// Runs the Express app (server.js) as a Netlify Function.
// netlify.toml rewrites /api/*, /auth/* and /admin/* to this function.
const serverless = require('serverless-http');
const app = require('../../server');

const PREFIX = '/.netlify/functions/api';

// Netlify usually passes the original path; strip the function prefix if it doesn't.
const handler = serverless((req, res) => {
  if (req.url.startsWith(PREFIX)) req.url = req.url.slice(PREFIX.length) || '/';
  return app(req, res);
});

exports.handler = handler;
