@dp9ik
Feature: dp9ik runs in managed code and matches 9front
  Every primitive follows upstream 9front libauthsrv and libsec: passtokey.c, authpak.c
  with ed448/edwards/decaf/elligator2/spake2ee.mp, form1.c with ccpoly.c, and the dp9ik
  session secret of factotum p9sk1.c. The drawterm-derived dp9ik_native_tool is used only
  by these tests, as an independent reference; the library itself never starts a process.

  @DP9IK_KEY_001 @property
  Scenario: Password keys match the reference
    Given generated passwords, including empty, longer than 8 bytes and non-ASCII
    When each is turned into an Authkey by the library and by the reference
    Then the DES and AES keys are identical

  @DP9IK_KEY_002
  Scenario: The AES key is PBKDF2-HMAC-SHA1 over the 9front salt
    Given the password "testpassword"
    When the library derives its AES key
    Then it equals PBKDF2-HMAC-SHA1 with salt "Plan 9 key derivation", 9001 iterations and 16 bytes

  @DP9IK_KEY_004 @property
  Scenario: An Authkey built from stored DES and AES keys matches one from the password
    Given generated passwords and user names
    When the library builds each Authkey from the reference DES and AES keys and applies the AuthPAK hash
    Then its DES key, AES key and PAK hash equal the reference passtokey and authpak_hash

  @DP9IK_KEY_005
  Scenario Outline: Stored keys must have their exact sizes
    When an Authkey is built from a <des>-byte DES key and a <aes>-byte AES key
    Then it fails with an argument error starting "<message>"

    Examples:
      | des | aes | message                   |
      | 6   | 16  | A DES key is 7 bytes.     |
      | 8   | 16  | A DES key is 7 bytes.     |
      | 7   | 15  | An AES key is 16 bytes.   |
      | 7   | 17  | An AES key is 16 bytes.   |

  @DP9IK_PAK_001 @property
  Scenario: The AuthPAK hash matches the reference
    Given generated passwords and user names
    When the library and the reference apply the AuthPAK hash
    Then the 448-byte PM and PN point encodings are identical

  @DP9IK_PAK_002 @property
  Scenario Outline: A managed side and the reference agree on the PAK key
    Given a password and user shared by both sides
    When the <client> client and the <server> server exchange AuthPAK public values
    Then both derive the same 32-byte PAK key

    Examples:
      | client    | server    |
      | managed   | reference |
      | reference | managed   |
      | managed   | managed   |

  @DP9IK_PAK_003
  Scenario: Different passwords derive different PAK keys
    Given a client and a server whose passwords differ
    When they exchange AuthPAK public values
    Then their PAK keys differ

  @DP9IK_PAK_005 @property
  Scenario: A chosen scalar derives the same key as the reference
    Given chosen scalars including 1, p-1 and values with the top scalar bit set
    When the library and the reference each finish an exchange from the same scalar and peer value
    Then their PAK keys are identical

  @DP9IK_PAK_006
  Scenario Outline: Decaf boundary encodings are decided as the reference decides them
    Given a server that has sent its AuthPAK public value
    When it receives the encoding <value> as the client's public value
    Then the library accepts or rejects it as the reference does, with the same key when accepted

    Examples:
      | value   |
      | 0       |
      | 1       |
      | (p-1)/2 |
      | (p+1)/2 |

  @DP9IK_PAK_004
  Scenario Outline: A public value outside the Decaf encoding is rejected
    Given a server that has sent its AuthPAK public value
    When it receives <value> as the client's public value
    Then finishing the exchange fails without producing a key

    Examples:
      | value                               |
      | an encoding greater than (p-1)/2    |
      | a value that is not on the curve    |

  @DP9IK_FORM1_001 @property
  Scenario Outline: Form1 messages interoperate with the reference
    Given a generated <message> and a 32-byte key
    When the <sealer> seals it and the <opener> opens it
    Then the opened <message> equals the original

    Examples:
      | message       | sealer    | opener    |
      | ticket        | managed   | reference |
      | ticket        | reference | managed   |
      | authenticator | managed   | reference |
      | authenticator | reference | managed   |

  @DP9IK_FORM0_001 @property
  Scenario Outline: Form 0 (DES) messages still interoperate with the reference
    Given a generated form 0 <message> and a DES key
    When the <sealer> seals it and the <opener> opens it
    Then the opened <message> equals the original

    Examples:
      | message | sealer    | opener    |
      | ticket  | managed   | reference |
      | ticket  | reference | managed   |

  @DP9IK_FORM1_002 @property
  Scenario: Any change to a sealed form1 message is rejected
    Given a sealed ticket
    When any single byte of it is changed
    Then opening it fails

  @DP9IK_FORM1_003
  Scenario: The form1 nonce is the signature and a little-endian counter
    Given two tickets sealed in a row by the library
    Then each begins with the 8-byte signature "form1 Ts"
    And the second 4-byte little-endian counter is greater than the first

  @DP9IK_SEC_001
  Scenario: Both sides of a handshake derive the 9front session secret
    Given a completed dp9ik handshake between a managed server and a client
    Then the server's session secret is 256 bytes
    And it equals HKDF-SHA256 with the two nonces as salt, info "Plan 9 session secret" and the ticket key
    And the client derives the same secret

  @DP9IK_SEC_002
  Scenario: A dp9ik server refuses a form 0 ticket
    Given a client that presents a valid form 0 (DES) ticket and authenticator
    When it completes the dp9ik exchange with a managed server
    Then the server rejects the proof as factotum does for dp9ik
    And no session secret is produced

  @DP9IK_SEC_004
  Scenario Outline: A server rejects a proof whose <part> does not decode
    Given a client whose proof has one changed byte in its <part>
    When it completes the dp9ik exchange with a managed server
    Then the server fails with "<error>"
    And no session secret is produced

    Examples:
      | part          | error                                      |
      | ticket        | Unable to decode the client ticket.        |
      | authenticator | Unable to decode the client authenticator. |

  @DP9IK_SEC_005
  Scenario: A server without a configuration fails before any protocol I/O
    When a managed server is started with a null configuration
    Then it fails with an argument-null error for "config"
    And nothing has been written to the client

  @DP9IK_PROC_001
  Scenario: The library starts no process
    Given the Dp9ik, Dp9ik.P9Auth and Dp9ik.Tls assemblies
    Then none of them references System.Diagnostics.Process
    And a complete dp9ik handshake still succeeds

  @DP9IK_KEY_003
  Scenario Outline: Passwords at the 8-byte group boundaries of passtodeskey match the reference
    Given a generated password of <length> bytes
    When each is turned into an Authkey by the library and by the reference
    Then the DES and AES keys are identical

    Examples:
      | length |
      | 0      |
      | 7      |
      | 8      |
      | 9      |
      | 15     |
      | 16     |
      | 17     |
      | 24     |
      | 26     |
      | 27     |
      | 28     |
      | 40     |

  @DP9IK_PAK_007
  Scenario: An AuthPAK state finishes once and clears the scalar it was given
    Given a client state created from a chosen scalar
    When it finishes an exchange with the reference server
    Then the scalar buffer it was given is zeroed
    And finishing again fails because no public value has been created

  @DP9IK_PAK_008
  Scenario: Finishing a state that never created a public value fails
    Given a new AuthPAK state
    When it is finished with a peer public value
    Then finishing fails because no public value has been created

  @DP9IK_PAK_009
  Scenario: Scalars are drawn below p, read big-endian and unsigned
    Given a random source yielding p, then a value below p only when read little-endian or signed, then a valid scalar
    When the library draws an AuthPAK scalar
    Then it returns the third value

  @DP9IK_FIELD_001 @property
  Scenario: Field arithmetic agrees with integer arithmetic modulo p
    Given generated field elements including 0, 1, p-1 and encodings at or above p
    When each is added, subtracted, multiplied, squared, negated, inverted and raised to a power
    And each is doubled by addition 64 times in a row before being multiplied
    Then every result equals the same operation on integers modulo p

  @DP9IK_FIELD_002
  Scenario: 7 is the smallest non-square modulo p, as spake2ee_h2P finds it
    Then 2, 3, 4, 5 and 6 are squares modulo p
    And 7 is not a square modulo p
    And the library's Elligator non-square is 7

  @DP9IK_FIELD_003
  Scenario Outline: decaf_neg negates only when n is above (p-1)/2
    When decaf_neg is applied to a value with n = <n>
    Then the value is <outcome>

    Examples:
      | n       | outcome |
      | 0       | kept    |
      | (p-1)/2 | kept    |
      | (p+1)/2 | negated |
      | p-1     | negated |

  @DP9IK_FORM1_004
  Scenario: A bare 8-byte form1 signature is recognised, as form1check does
    Given the 8 bytes "form1 Ts"
    Then form1check reports a ticket from the server
    And the 7 bytes "form1 T" are not recognised

  @DP9IK_FORM1_005
  Scenario: A sealed message with an empty body is rejected, as form1M2B does
    Given a form1 message sealed from only its type byte
    Then opening the sealed message fails

  @DP9IK_FORM1_006
  Scenario: A message type without a form1 signature cannot be sealed
    Given a form 1 ticket of type AuthOk
    Then marshalling it fails with an argument error

  @DP9IK_MSG_001
  Scenario Outline: Truncated tickets and authenticators are rejected
    Given a marshalled form <form> <message>
    Then unmarshalling one byte less than it fails and consumes nothing
    And unmarshalling all of it consumes exactly its length

    Examples:
      | form | message       |
      | 0    | ticket        |
      | 1    | ticket        |
      | 0    | authenticator |
      | 1    | authenticator |

  @DP9IK_MSG_002
  Scenario: A 27-byte user name fills a ticket up to its terminator and round-trips
    Given a ticket whose client and server users are 27-byte names
    When it is sealed and opened by the library and by the reference
    Then both open the same 27-byte names

  @DP9IK_MSG_004
  Scenario Outline: Text fields leave room for the C terminator, as ANAMELEN and DOMLEN do
    When a <field> of <length> bytes is set
    Then it is <outcome>

    Examples:
      | field                       | length | outcome                                     |
      | ticket client user          | 27     | accepted                                    |
      | ticket client user          | 28     | refused with "Expected at most 27 bytes."   |
      | ticket server user          | 28     | refused with "Expected at most 27 bytes."   |
      | ticket request auth id      | 28     | refused with "Expected at most 27 bytes."   |
      | ticket request host id      | 28     | refused with "Expected at most 27 bytes."   |
      | ticket request user id      | 28     | refused with "Expected at most 27 bytes."   |
      | ticket request auth domain  | 47     | accepted                                    |
      | ticket request auth domain  | 48     | refused with "Expected at most 47 bytes."   |

  @DP9IK_MSG_005
  Scenario: A received ticket request has its names terminated, as convM2TR does
    Given a ticket request whose name and domain fields are filled with no terminator
    When the library unmarshals it
    Then the auth id, host id and user id read as their first 27 bytes
    And the auth domain reads as its first 47 bytes

  @DP9IK_MSG_006
  Scenario Outline: A received ticket has its names terminated, as convM2T does
    Given the reference seals a form <form> ticket whose user names fill all 28 bytes
    When the library and the reference open it
    Then both read the client and server users as their first 27 bytes

    Examples:
      | form |
      | 0    |
      | 1    |

  @DP9IK_MSG_003
  Scenario: Setting a shorter user name clears the longer one
    Given a ticket whose client user is set to "a-much-longer-user" and then to "glenda"
    Then its client user reads "glenda"

  @DP9IK_ARG_001
  Scenario Outline: Wrong lengths are refused with an error saying what was expected
    When <operation> is given <input>
    Then it fails with an argument error starting "<message>"

    Examples:
      | operation           | input                  | message                            |
      | the session secret  | a 31-byte client nonce | Each nonce is 32 bytes.            |
      | the session secret  | a 31-byte server nonce | Each nonce is 32 bytes.            |
      | the session secret  | a 31-byte ticket key   | The ticket key is 32 bytes.        |
      | Plan 9 DES          | a 7-byte buffer        | Plan 9 DES needs at least 8 bytes. |
      | an Authkey replace  | 502 bytes              | An Authkey is 503 bytes.           |
      | a ticket challenge  | 9 bytes                | Expected 8 bytes.                  |

  @DP9IK_ARG_002
  Scenario Outline: Required arguments are checked before any work
    When <operation> is called with a null <argument>
    Then it fails with an argument-null error for "<argument>"

    Examples:
      | operation                    | argument |
      | AuthKey.FromPassword         | password |
      | AuthKey.ApplyAuthPakHash     | user     |
      | AuthPakState.CreatePublicValue | key    |
      | AuthPakState.Finish          | key      |
      | Ticket.Marshal               | key      |
      | Ticket.TryUnmarshal          | key      |
      | Authenticator.Marshal        | ticket   |
      | Authenticator.TryUnmarshal   | ticket   |

  @DP9IK_SEC_003
  Scenario: Secret buffers are zeroed when released
    Given a secret buffer holding non-zero bytes
    When it is released
    Then every byte of it is zero
