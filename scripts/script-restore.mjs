
import { Signature } from "ethers";

import { verify } from "./attest.mjs";
import { FireflyRepl } from "./repl.mjs";
import { Log } from "./log.mjs";

(async function() {
    const repl = new FireflyRepl();
    await repl.connect();
    await repl.waitReady();

    const { version } = await repl.sendCommand(`VERSION`);
    if (version !== 1) {
        throw new Error(`unsupported version: ${ version }`);
    }

    const dump = await repl.sendCommand(`DUMP`);
    if (!dump.ready) { throw new Error("device not provisioned"); }

    const log = Log.getLog(parseInt(dump["efuse.model"]),
      parseInt(dump["efuse.serial"]));
    // @TODO: if log is missing throw device not found in database error

    const attest = Signature.from(log.get("attest")).compactSerialized.substring(2);
    const pubkeyN = log.get("pubkeyN").substring(2);
    const cipherData = log.get("cipherData").substring(2);

    console.log({ attest, pubkeyN, cipherData });

    await repl.sendCommand(`SET-ATTEST=${ attest }`);
    await repl.sendCommand(`SET-PUBKEYN=${ pubkeyN }`);
    await repl.sendCommand(`SET-CIPHERDATA=${ cipherData }`);

    //console.log(await repl.sendCommand(`DUMP`, true));
    await repl.sendCommand(`WRITE`);

    //console.log(await repl.sendCommand(`RESET`));

    console.log(await repl.sendCommand(`LOAD-EFUSE`));
    //console.log(await repl.sendCommand(`LOAD-NVS`));

    const proof = await repl.sendCommand(`ATTEST=0123456789abcdef`);
    console.log(proof, verify(proof.attest));

    await repl.sendCommand("RESET");

})().catch((error) => {
    console.log({ error });
});
