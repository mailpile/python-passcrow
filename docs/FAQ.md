# Frequently asked Questions about Passcrow

## What is Passcrow?

Passcrow is an attempt to bring "password reset" functionality to
applications using strong encryption, without sacrificing security.

It does this by encrypting sensitive data locally, but placing fragments
of a recovery key in escrow with servers who will only release the
fragments if the user proves their identity somehow.


## What is escrow?

noun:

   * A bond, deed, or other document kept in the custody of a third party
     and taking effect only when a specified condition has been fulfilled. 
   * The state of being kept in custody or trust until a specified condition
     has been fulfilled. "the board holds funds in escrow"

verb:

   * place in custody or trust until a specified condition has been fulfilled.
     "those funds are escrowed for the purpose of improving municipal services"

Definitions from [Google](https://www.google.com/search?q=define+escrow) and
[Oxford Languages](https://languages.oup.com/google-dictionary-en/).


## Where is the code?

The Python implementation of Passcrow, and the primary source for this
documentation, both live here: <https://github.com/mailpile/python-passcrow/>


## Where is the community?

There is a forum for general discussions here:
<https://community.mailpile.is/c/development/passcrow>

Bug reports regarding the Python code or this documentation should go here:
<https://github.com/mailpile/python-passcrow/issues>


## What is passcrow.org ?

Passcrow.org publishes a directory of public Passcrow servers, both in
human-readable and machine-readable form.

Passcrow.org will also take care of periodically testing the public servers
to verify they are functioning correctly, and publishing the results of
these tests so users can be informed if a server goes offline.


## What happens if the Passcrow Server goes offline?

When a Passcrow Server goes offline temporarily, it's no big deal.

If it goes offline permanently, then any Fragments entrusted to it will
be permanently lost, as well as any Ephemeral Recovery Packs.

For some policies (requiring N-of-M fragments) this may not pose an
immediate problem, for others it means recovery becomes impossible.

Periodically checking passcrow.org for server status could be used to
detect this problem and respond (by generating new Recovery Packs and
placing fragments in escrow with active servers).


## What happens if the Passcrow Server misbehaves?

The Passcrow Server does not know who you are and cannot target you
directly.

However, if someone has stolen both your encrypted data and the Recovery
Pack, they could coerce or hack the Passcrow Server so it reveals any
Recovery Key Fragments it is in posession of (skipping the verification
step), potentially gaining access to the stolen data that way.

To mitigate this threat, it is important that there be multiple Passcrow
servers involved in any policy, ideally run by different organizations and
hosted in different places.


## What happens if the local Recovery Pack is lost?

If the recovery pack is lost, recovery becomes impossible.

However, in most cases the recovery pack serves no purpose except to
regain access to a certain collection of encrypted data. This suggests that
recovery packs should "share fate" with the user's encrypted data: it is
recommended to store the Recovery Pack in the same place as the data it can
help recover access to.

If the user's data is lost, the recovery pack serves no purpose.

As always there is a trade-off; keeping the recovery pack separate from
the user's data may increase security in some cases, but at the cost of
reliability (by introducing new failure modes).


## What is Ephemeral Passcrow for?

Two examples:

One: You define a recovery policy which requires three out of four close
friends or family members cooperate to recover your personal data. The
protected data is the password you use to log in to your laptop.

Two: You define a recovery policy which requires all 2/3 of your boss, the
CTO and the CEO at your job to recover your work data. The protected data
is the passphrase used to encrypt your work laptop.

In both cses, Ephemeral Passcrow allows you then print a label with a
URL and a code that you can stick to your encrypted device. The URL will
provide instructions on how to initiate recovery, the code is sufficient
to start the recovery process. Both the URL and the code are short enough
to be correctly transcribed by a human.

So if you die or are incapacitated (or fired!), the people managing your
affairs can visit the URL and initiate recovery.


## Why not always use Ephemeral Passcrow?

It is less reliable; if the server storing the Recovery Pack goes offline,
recovery is impossible (this is the "new failure mode" introduced by not
ensuring shared fate for the recovery pack and the data itself).


## What Encryption does Passcrow use?

**Note:** *This may change once we get feedback from qualified experts.*

Keys are generated randomly using the operating system's `urandom()` or
equivalent, stretched using Scrypt.

Data is encrypted using AES-GCM-256.

Recovery Keys are split into Fragments using Shamir's Secret Sharing.

Ephemeral Recovery Packs are compressed before encryption.

Ephemeral Recovery Keys and the IDs identifying the packs on the servers
are derived from a single 96-bit key, using Scrypt and different salts.

The implementations used are those provided by the Python cryptography
project, and code copy-pasted from Wikipedia's page about Shamir's Secret
Sharing. The latter most definitely needs a review.


## Who pays for all of this?

Development and the passcrow.org infrastructure is currently funded by
the Mailpile project, as part of our mission to improve e-mail security.

If you would like to support this work, please donate:
<https://www.mailpile.is/donate/>

