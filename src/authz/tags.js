/* System-defined object tags used for authorization.
 *
 * The Symbol descriptions are the intended values to use for
 * stringification/serialization, if we ever need to do that.
 *
 * In the future, we may also allow user-defined object tags as ~arbitrary
 * strings to enable group-specific authz rules (in combination with
 * user-defined group membership roles).
 */

/* Map from exported property names → symbols that are passed around and used
 * for comparison.  This is sort of like a set of enums, but without
 * compile-time checks.  Would need TypeScript for true enum support.
 */
const tags = {
  Type: {
    Source: Symbol("type:source"),
    Dataset: Symbol("type:dataset"),
    Narrative: Symbol("type:narrative"),
  },
  Visibility: {
    Public: Symbol("visibility:public"),
  },
};

// Freeze for export so this "can't" be modified by callers.
module.exports = Object.freeze(tags);
