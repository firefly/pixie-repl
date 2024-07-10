Pixie REPL
==========

A simple firmware used to diagnose and configure a Firefly Pixie.

The firmware runs a Run-Eval-Print-Loop over the USB Serial so
that client-side scripts can be used to perform operations such as:

- Provision new devices, generating DS private keys, burning eFuses, etc.
- Dump device configuration (serial number, model number, etc)
- Create device attestations for arbitrary data
- Restore a device attest partition is damaged


Commands
--------

### ATTEST=[ 16 bytes; 32 nibbles ]

Use the Digital Signing (DS) Peripheral to attest to the data,
providing the signed payload, random nonce and attested signature.

### BURN

Burns the eFuses in BLK3 with:
  - [reg=0x00] version = 1
  - [reg=0x01] model number  (see SET-MODEL)
  - [reg=0x02] serial number (see SET-SERIAL)
  - [reg=0x04] random marker; for future use

### DUMP

Dumps all infomation available from the device, including NVS,
eFuse state and any pending values configured for BURN or WRITE.

**Note:** Only public data is exposed, not private keys or pending
encryption parameters are displayed.

### GEN-KEY

Generates a new 3072-bit RSA keypair internally, stored as pending
values, which can be burned.

### LOAD-EFUSE

Load the eFuses for the model and serial number. These parameters
are necessary for the ATTEST= operation, in the event the SET-MODEL
and SET-SERIAL were not used during this session.

## LOAD-NVS

Load the NVS `attest` partition, which includes the:

- RSA public key N
- encrypted cipherdata used by the DS Peripheral
- attestation signature

### NOP

No operation. This can be used to force the device to response with `OK`.

### PING

Triggers the device to restart its READY loop. This can be used to recover
from reconnection issues.

### RESET

Restarts the device.

### SET-ATTEST=[ 64 bytes; 128 nibbles ]

Set the attestation signature. This is provided by a signing authority
to prove the manufacturer assigned the model number and serial number
and that the correct public key is used.

### SET-CIPHERDATA=[ 1220 bytes; 2440 nibbles ]

Sets the `cipherdata`, which is the encryped private key for the DS
Peripheral to use. This is useful to re-write the NVS storage in the
event it was deleted. Otherwise the `cipherdata` is usually created
as part of the `GEN-KEY` opeation.

### SET-MODEL=[ number ]

Sets the model number of the device.

### SET-PUBKEYN=[ 384 bytes; 768 nibbles ]

Sets the `pubkeyn`. This is useful to rewrite the NVS storage in the
event it was delete. Otherwise the `pubkeyn` is usually created as
part of the `GEN-KEY` operation.

### SET-SERIAL=[ number ]

Sets the serial of the device.

### STIR-ENTROPY=[ any length of data; up to maximum buffer size ]

Send additional entropy to be stired with the `GEN-KEY` operation.

The data is hashed along with any current value and additional
random entropy (from device thermal noise) to create the updated
value.

### STIR-IV=[ any length of data; up to maximum buffer size ]

Send additional entropy to be stired with the initialization verctor
used during `GEN-KEY` operation when computing the `cipherdata`.

The data is hashed along with any current value and additional
random entropy (from device thermal noise) to create the updated
value.

### STIR-KEY=[ any length of data; up to maximum buffer size ]

Send additional entropy to be stired with the random key used
during `GEN-KEY` operation when computing the encryption key.

The data is hashed along with any current value and additional
random entropy (from device thermal noise) to create the updated
value.

### VERSION

Returns the version of the REPL.

### WRITE

Writes the attestation signature, `cipherdata` and RSA public key
to the NVS storage.


License
-------

MIT License.

