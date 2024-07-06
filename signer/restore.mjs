
import { Signature } from "ethers";

import { FireflyRepl } from "./repl.mjs";
import { Log } from "./log.mjs";


(async function() {
    const repl = new FireflyRepl();
    await repl.connect();
    await repl.waitReady();

    const { version } = await repl.sendCommand(`VERSION`);
    if (version !== "1") {
        throw new Error(`unsupported version: ${ version }`);
    }

    const dump = await repl.sendCommand(`DUMP`, true);
    console.log(dump);

    const log = Log.getLog(parseInt(dump["efuse.model"]),
      parseInt(dump["efuse.serial"]));
    console.log(log);

    const attest = Signature.from(log.get("attest")).compactSerialized.substring(2);
    const pubkeyN = log.get("pubkeyN");
    const cipherData = log.get("cipherData");

    await repl.sendCommand(`SET-ATTEST=${ attest }`);
    await repl.sendCommand(`SET-PUBKEYN=${ pubkeyN }`);
    await repl.sendCommand(`SET-CIPHERDATA=${ cipherData }`);

    console.log(await repl.sendCommand(`DUMP`, true));

    console.log("DONE");

})().catch((error) => {
    console.log({ error });
});
