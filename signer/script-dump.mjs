
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
    console.log(dump);
    if (!dump.ready) { throw new Error("device not provisioned"); }

    console.log(await repl.sendCommand(`LOAD-EFUSE`));
    console.log(await repl.sendCommand(`LOAD-NVS`));

    const proof = await repl.sendCommand(`ATTEST=0123456789abcdef`);
    console.log(proof, verify(proof.attest));

})().catch((error) => {
    console.log({ error });
});
