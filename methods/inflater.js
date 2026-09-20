const nodeVersion = (process.versions ? process.versions.node : "") || "";
const version = +nodeVersion.split(".")[0] || 0;
const versionMinor = +nodeVersion.split(".")[1] || 0;
const kMaxLength = require("buffer").constants.MAX_LENGTH;
const Errors = require("../util/errors");

// zlib's "maxOutputLength" option landed in node 12.19 and 14.0, so it can be used
// on every runtime this package supports and not only on node >= 15.
const supportsMaxOutputLength = version >= 14 || (version === 12 && versionMinor >= 19);

module.exports = function (/*Buffer*/ inbuf, /*number*/ expectedLength) {
    var zlib = require("zlib");
    // Cap decompression output at the entry's declared uncompressed size to bound
    // decompression bombs (CVE-2026-39244). A declared size of 0 must not disable
    // the cap: a genuinely empty entry inflates to 0 bytes, so a 1-byte floor
    // still lets it through while stopping a bomb that lies about its size.
    // zlib requires 1 <= maxOutputLength <= buffer.constants.MAX_LENGTH.
    const maxOutputLength = Math.min(expectedLength > 0 ? expectedLength : 1, kMaxLength);
    const option = supportsMaxOutputLength ? { maxOutputLength } : {};

    return {
        inflate: function () {
            return zlib.inflateRawSync(inbuf, option);
        },

        inflateAsync: function (/*Function*/ callback) {
            var tmp = zlib.createInflateRaw(option),
                parts = [],
                total = 0,
                done = false;
            const fail = function (err) {
                if (done) return;
                done = true;
                parts = [];
                tmp.destroy();
                callback && callback(Buffer.alloc(0), err);
            };
            // Route stream errors (e.g. Z_DATA_ERROR on malformed input, or the
            // maxOutputLength cap being exceeded) through the callback. Without an
            // "error" listener zlib re-throws the event as an uncaught exception on
            // a later tick, crashing the host process instead of failing the call.
            tmp.on("error", function (err) {
                fail(err);
            });
            tmp.on("data", function (data) {
                if (done) return;
                total += data.length;
                // The streaming API ignores maxOutputLength, so enforce the cap by
                // hand; otherwise the async path decompresses without limit while the
                // sync path is capped.
                if (total > maxOutputLength) {
                    return fail(Errors.MAX_OUTPUT_EXCEEDED());
                }
                parts.push(data);
            });
            tmp.on("end", function () {
                if (done) return;
                done = true;
                var buf = Buffer.alloc(total),
                    written = 0;
                buf.fill(0);
                for (var i = 0; i < parts.length; i++) {
                    var part = parts[i];
                    part.copy(buf, written);
                    written += part.length;
                }
                callback && callback(buf);
            });
            tmp.end(inbuf);
        }
    };
};
