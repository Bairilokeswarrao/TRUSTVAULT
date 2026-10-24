'use strict';
const { isId, HttpError } = require('../util');

/**
 * Route guard for anything that touches a document. app.js refuses to boot if a route with an :id parameter
 * does not include one of these, so "forgot the check on one endpoint" is a startup failure, not a hole.
 *
 *   authorizeDocument('download')  -> ctx.doc, ctx.level are set only if the server says yes.
 */
module.exports = ({ permissions }) => (action) => {
  const guard = (ctx) => {
    if (!isId(ctx.params.id)) throw new HttpError(404, 'not_found', 'Document not found');
    const { doc, level } = permissions.authorize(ctx, ctx.params.id, action);
    ctx.doc = doc;
    ctx.level = level;
  };
  guard.guards = 'document';
  guard.action = action;
  return guard;
};
