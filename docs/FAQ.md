# Frequently asked Questions about Passcrow

## What is Passcrow?

Passcrow is an attempt to bring "password reset" functionality to
applications using strong encryption, without sacrificing security.

It does this by encrypting sensitive data locally, but placing fragments
of a recovery key in escrow with community-run servers, which only release
the fragments if the user proves their identity somehow.


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


## How does it work? Why?

The [Protocol documentation](PROTOCOL.md) starts with an explanation of:

   * What Passcrow does
   * Why we need Passcrow
   * How Passcrow looks to the user
   * What Passcrow does behind the scenes

... and then delves into nitty gritty technicalities which you may not be
interested in. But those first sections explain pretty well how things
work and why, so [reading them](PROTOCOL.md) isn't a bad idea!


## Where is the code?

The Python implementation of Passcrow, and the primary source for this
documentation, both live here: <https://github.com/mailpile/python-passcrow/>


## Where is the community?

There is a forum for general discussions here:
<https://community.mailpile.is/c/development/passcrow>

Bug reports regarding the Python code or this documentation should go here:
<https://github.com/mailpile/python-passcrow/issues>


## What is passcrow.org ?

**Note:** *this answer is aspirational, work is in progress*

[Passcrow.org](https://passcrow.org/) publishes a directory of public
Passcrow servers, both in human-readable and machine-readable form.

Passcrow.org will also take care of periodically testing the public servers
to verify they are functioning correctly, and publishing the results of
these tests so users can be informed if a server goes offline.


## What happens if a Passcrow Server goes offline?

When a Passcrow Server goes offline temporarily, it's no big deal.

If it goes offline permanently, then any Fragments entrusted to it will
be permanently lost, as well as any Ephemeral Recovery Packs.

For some policies (requiring N-of-M fragments) this may not pose an
immediate problem, for others it means recovery becomes impossible.

Periodically checking <https://passcrow.org/> for server status could be
used to detect this problem and respond (by generating new Recovery Packs
and placing fragments in escrow with active servers).


## What happens if a Passcrow Server misbehaves?

Passcrow Servers do not know who you are and cannot target you
directly.

However, if someone has stolen both your encrypted data and the Recovery
Pack, they could coerce or hack a Passcrow Server so it reveals any
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


## Why does Passcrow need Servers?

A previous iteration of this concept was serverless: it was based on
e-mailing (or printing and sneaker-netting) Recovery Key Fragments to
friends and family, and asking them to keep them safe until it was time
for recovery.

This idea was discarded because it:

1. Implied exposing the fragments as cleartext to e-mail server operators.
2. Required relying on people who may not be skilled techies to keep
   sensitive data safe and findable for a long period of time.
3. Required knowing *today*, who your friends will be *in the future*.
   Relationships change over time, making this depressingly unrealistic.

Introducing the Server role solved these issues, while also allowing most
of the complicated technical details to be hidden from the user; in
particular the too-long-to-type Recovery Key Fragments can be handled
behind the scenes, and users only need to copy-paste or retype short-lived
verification codes.

Adding a specialized server also allows us to keep the Recovery Key
Fragments encrypted and unreadable until the user actually initiates
recovery, which improves overall security significantly.


## What is Ephemeral Passcrow?

Ephemeral Passcrow is what you get when the Recovery Pack itself is very
carefully placed in escrow, linked to random ID on a known server.

Why would you do that? So glad you asked!

Two examples:

1. You define a recovery policy which requires three out of four close
   friends or family members cooperate to complete recovery. The protected
   data in the Recovery Pack is the password you use to log in to your
   personal laptop.

2. You define a recovery policy which requires all 2/3 of your manager,
   the CTO and the CEO at your job to complete recovery. The protected data
   in the Recovery Pack is the passphrase used to encrypt your work laptop.

In both cases, Ephemeral Passcrow allows you then print a label with a URL
and a code that you can stick to your encrypted device. The URL will
provide instructions on how to initiate recovery, the code is sufficient
to start the recovery process. Both the URL and the code are short enough
to be correctly transcribed by a human.

So if you die or are incapacitated (or fired!), the people managing your
affairs can visit the URL and initiate recovery, gaining access to your
otherwise secure devices.

A third example would be putting such a label on an encrypted backup
drive, so forgetting the passphrase doesn't prevent access years later.


## Why not always use Ephemeral Passcrow?

It is less reliable: if the server storing the Recovery Pack goes offline,
recovery is impossible (this is the "new failure mode" introduced by not
ensuring shared fate for the recovery pack and the data itself).

Recovery also requires two rounds of verification, instead of just one.
So it's less user friendly, too.


## What Encryption does Passcrow use?

**Note:** *This may change once we get feedback from qualified experts.*

Keys are generated randomly using the operating system's `urandom()` or
equivalent, stretched using Scrypt.

Data is encrypted using AES-GCM-256.

Recovery Keys are split into Fragments using Shamir's Secret Sharing.

Ephemeral Recovery Packs are compressed before encryption.

Ephemeral Recovery Keys and the IDs identifying the packs on the servers
are derived from a single approximately 96-bit key, using Scrypt and
different salts. The random distribution may be biased, due to code which
avoids bit sequences which may "look the same" when base64-encoded, such
as O and 0, or I and l. This needs a review.

The implementations used are those provided by the Python cryptography
project, and code copy-pasted from Wikipedia's page about Shamir's Secret
Sharing. The latter most definitely needs a review.


## Who pays for all of this?

Development and the passcrow.org infrastructure is currently funded by
the Mailpile project, as part of our mission to improve e-mail security.

If you would like to support this work, please donate:
<https://www.mailpile.is/donate/>

