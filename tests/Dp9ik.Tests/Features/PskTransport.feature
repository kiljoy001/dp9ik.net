@dp9ik_tls
Feature: The dp9ik session secret keys a TLS-PSK channel that 9front accepts
  9front tlssrv and tlsclient -a use TLS 1.2 with PSK identity "p9secret" and the dp9ik
  session secret as the key (cmd/tlssrv.c, cmd/tlsclient.c). Their PSK suites are
  TLS_PSK_WITH_CHACHA20_POLY1305 (0xCCAB), TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00AE) and
  TLS_PSK_WITH_AES_128_CBC_SHA (0x008C) (libsec/port/tlshand.c). The channel is built on
  BouncyCastle; it uses no certificates and no OpenSSL.

  @DP9IK_TLS_001
  Scenario Outline: A client with the session secret completes the handshake
    Given a PSK server keyed with a dp9ik session secret
    When a TLS 1.2 client offering only <suite> connects with identity "p9secret" and the same secret
    Then the handshake completes with <suite>
    And bytes written by either side are read by the other

    Examples:
      | suite                                 |
      | TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 |
      | TLS_PSK_WITH_AES_128_CBC_SHA256       |
      | TLS_PSK_WITH_AES_128_CBC_SHA          |

  @DP9IK_TLS_002
  Scenario: A client with a different secret is refused
    Given a PSK server keyed with a dp9ik session secret
    When a client connects with identity "p9secret" and a different secret
    Then the handshake fails and no application data is exchanged

  @DP9IK_TLS_003
  Scenario: A client with another identity is refused
    Given a PSK server keyed with a dp9ik session secret
    When a client connects with identity "someone" and the same secret
    Then the handshake fails and no application data is exchanged

  @DP9IK_TLS_004
  Scenario Outline: The server negotiates nothing outside 9front's PSK profile
    Given a PSK server keyed with a dp9ik session secret
    When a client offers only <offer>
    Then the handshake fails

    Examples:
      | offer                                      |
      | TLS 1.3                                    |
      | a certificate-based cipher suite            |
      | TLS_PSK_WITH_AES_256_GCM_SHA384            |

  @DP9IK_TLS_005
  Scenario: A dp9ik handshake followed by TLS-PSK carries data end to end
    Given a server that runs the dp9ik handshake and then TLS-PSK with its session secret
    When a client authenticates with dp9ik, derives the same secret and opens TLS-PSK
    Then the server reports the client's user
    And data crosses the encrypted channel in both directions

  @DP9IK_TLS_006
  Scenario Outline: The PSK channel checks its arguments before any handshake
    When the <side> is opened with <argument>
    Then it fails with <error> for "<parameter>"
    And nothing has been written to the transport

    Examples:
      | side   | argument          | error                  | parameter |
      | server | a null transport  | an argument-null error | transport |
      | server | a null secret     | an argument-null error | secret    |
      | server | an empty secret   | an argument error      | secret    |
      | client | a null transport  | an argument-null error | transport |
      | client | a null secret     | an argument-null error | secret    |
      | client | an empty secret   | an argument error      | secret    |
