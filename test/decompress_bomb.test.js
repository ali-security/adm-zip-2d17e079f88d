"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.
//
// The same advisory also covers the mirror case: an entry that under-declares
// its size and then inflates without limit. Decompression must be capped by the
// declared size on both the sync and the async (streaming) code paths.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// Records the largest single Buffer.alloc request made while `fn` runs. This is
// the deterministic form of the exploit check: the vulnerable code called
// Buffer.alloc(declaredSize) up front, so the peak request tracked the header
// field instead of the bytes actually present in the archive.
function largestAllocationDuring(fn) {
    const original = Buffer.alloc;
    let largest = 0;
    Buffer.alloc = function (size) {
        if (typeof size === "number" && size > largest) largest = size;
        return original.apply(Buffer, arguments);
    };
    try {
        fn();
    } catch (error) {
        // the crafted archives are invalid on purpose - the throw is expected,
        // what matters is how much was allocated on the way there
    } finally {
        Buffer.alloc = original;
    }
    return largest;
}

const MB = 1024 * 1024;

describe("zip decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / MB;
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / MB;
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("never requests a buffer sized from the declared size (STORED)", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const entry = zip.getEntries()[0];
        const largest = largestAllocationDuring(() => entry.getData());
        expect(largest, "peak Buffer.alloc must follow the real payload, not the header field").to.be.below(MB);
    });

    it("never requests a buffer sized from the declared size (DEFLATED)", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const entry = zip.getEntries()[0];
        const largest = largestAllocationDuring(() => entry.getData());
        expect(largest, "peak Buffer.alloc must follow the real payload, not the header field").to.be.below(MB);
    });

    it("never requests a buffer sized from the declared size via readFile/readAsText/test", () => {
        const buf = craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A"));
        for (const call of [(z) => z.readFile("a"), (z) => z.readAsText("a"), (z) => z.test()]) {
            const largest = largestAllocationDuring(() => call(new Zip(buf)));
            expect(largest, "peak Buffer.alloc must follow the real payload, not the header field").to.be.below(MB);
        }
    });

    describe("output limit", () => {
        // 32 MB of zeros deflates down to a few kilobytes: the classic ratio bomb.
        const HUGE = 32 * MB;
        const deflated = zlib.deflateRawSync(Buffer.alloc(HUGE));

        it("stops the sync inflate once the declared uncompressed size is passed", () => {
            // declares 1 KB but expands to 32 MB
            const zip = new Zip(craftBomb(1024, 8 /* DEFLATED */, deflated));
            let thrown;
            try {
                zip.getEntries()[0].getData();
            } catch (error) {
                thrown = error;
            }
            expect(thrown, "inflating past the declared size must fail").to.be.an("error");
            // a crc complaint would mean the 32 MB were produced first and only the
            // checksum rejected them - the cap has to stop the inflate itself
            expect(thrown.message, "the cap must stop the inflate, not the checksum").to.not.match(/CRC32/);
        });

        it("stops the sync inflate for an entry declaring a zero uncompressed size", () => {
            // a declared size of 0 must not be read as "no limit"
            const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, deflated));
            expect(() => zip.getEntries()[0].getData()).to.throw();
        });

        it("stops the async inflate once the declared uncompressed size is passed", function (done) {
            this.timeout(20000);
            const zip = new Zip(craftBomb(1024, 8 /* DEFLATED */, deflated));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                try {
                    expect(err, "the streaming path must be capped too, not only the sync one").to.be.an("error");
                    expect(err.message).to.match(/exceeds the declared uncompressed size/);
                    expect(data.length).to.equal(0);
                    done();
                } catch (assertion) {
                    done(assertion);
                }
            });
        });

        it("stops the async inflate for an entry declaring a zero uncompressed size", function (done) {
            this.timeout(20000);
            const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, deflated));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(/exceeds the declared uncompressed size/);
                    expect(data.length).to.equal(0);
                    done();
                } catch (assertion) {
                    done(assertion);
                }
            });
        });

        it("reports a malformed deflate stream through the async callback instead of crashing", function (done) {
            this.timeout(20000);
            const zip = new Zip(craftBomb(1024, 8 /* DEFLATED */, Buffer.from([0xff, 0xff, 0xff, 0xff])));
            zip.getEntries()[0].getDataAsync(function (data, err) {
                try {
                    expect(err, "zlib stream errors must reach the callback, not the process").to.be.an("error");
                    expect(data.length).to.equal(0);
                    done();
                } catch (assertion) {
                    done(assertion);
                }
            });
        });
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });

    it("still reads a legitimate DEFLATED entry asynchronously", function (done) {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        round.readFileAsync("d.txt", function (data, err) {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (assertion) {
                done(assertion);
            }
        });
    });

    it("still reads a legitimate empty DEFLATED entry", () => {
        // an entry that really is empty inflates to 0 bytes and must survive the
        // 1-byte floor the zero-size cap uses
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.alloc(0))));
        expect(zip.getEntries()[0].getData().length).to.equal(0);
    });
});
