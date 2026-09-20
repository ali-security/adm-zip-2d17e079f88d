"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

describe("zip64", () => {
    it("writes and reads archives with more than 65535 entries", function () {
        this.timeout(60000);

        const entryCount = 0x10000;
        const zip = new Zip({ noSort: true });

        for (let i = 0; i < entryCount; i++) {
            zip.addFile(`file-${i}.txt`, "");
        }

        const buffer = zip.toBuffer();
        const readZip = new Zip(buffer);

        expect(readZip.getEntries()).to.have.lengthOf(entryCount);
    });

    it("keeps the archive comment readable next to the zip64 end records", function () {
        this.timeout(60000);

        const zip = new Zip({ noSort: true });
        zip.addFile("only.txt", Buffer.from("x"));
        zip.addZipComment("hello comment");

        const buffer = zip.toBuffer();
        // the comment is the very last thing in the file, right after the EOCD
        expect(buffer.slice(buffer.length - "hello comment".length).toString()).to.equal("hello comment");
        expect(new Zip(buffer).getZipComment()).to.equal("hello comment");
    });
});
