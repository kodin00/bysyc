# bysyc

A self-hosted, end-to-end encrypted chat + calling app for a small group of friends. Single-tenant: one deployment serves one community.

## Language

**Instance**:
One deployment of the server software. Friends self-host one Instance for themselves.
_Avoid_: server (collides with the community sense — see Guild), deployment, host

**Account**:
A person's identity on an Instance, created with username + password. One Account signs in from exactly one device (v1).
_Avoid_: user, profile, member (a Member is an Account's participation in a Guild)

**Identity Key**:
The long-term encryption keypair belonging to an Account, identified by a fingerprint users can compare out-of-band to verify each other.

**Friend**:
A relationship between two Accounts, active only after both accept. The prerequisite for a direct chat and a private call.
_Avoid_: contact, connection

**Friend Request**:
A pending invitation to become Friends; requires acceptance by the recipient.

**Message**:
The ciphertext envelope clients exchange through the Instance. Plaintext exists only on devices; the Instance never sees it.
_Avoid_: encrypted message (all Messages are encrypted — the adjective is redundant)

**Guild**:
A community that an Account creates and owns; contains Channels; other Accounts join via an accepted Guild Invite.
_Avoid_: server (collides with the backend Instance), group

**Member**:
An Account's participation in a Guild.
_Avoid_: user, participant

**Owner**:
The Member who created the Guild; in v1 the only one who can create or delete Channels and Guild Invites.

**Channel**:
A conversation inside a Guild. Either a Text Channel (Messages) or a Voice Channel (hosts a Call).
_Avoid_: room, chat

**DM**:
A private conversation between exactly two Friends.
_Avoid_: PM, private chat, direct message (as a noun phrase)

**Guild Invite**:
An expiring, use-limited code that lets an Account join a Guild upon acceptance.

**Registration Invite**:
An admin-issued code required to create an Account on the Instance.

**Call**:
The audio session hosted by a Voice Channel; presence in the channel is presence in the Call.

**Private Call**:
A two-party Call started from a DM between Friends.
_Avoid_: direct call, 1:1 call
