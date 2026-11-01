@dp9ik_client
Feature: The client side of p9any and dp9ik gets tickets from the auth server and proves itself
  The client is drawterm's p9any (cpu.c), dp9ik only: it reads the server's offer, chooses dp9ik
  with the offer's domain, and reads "OK" after a v.2 offer. It writes its challenge, reads the
  server's ticket request and AuthPAK value, and gets the tickets from the domain's auth server,
  as getastickets does: AuthPAK with the server's value and its own, then AuthTreq. It sends the
  server's ticket, its authenticator and the auth server's value for the server, and reads the
  server's authenticator. Both sides then hold the same session secret. A password is asked for
  by the user, domain and protocol, and asked again when the auth server's ticket does not open
  with it. When the auth server cannot be had, a user who is the server's own authid makes the
  tickets itself, as mkservertickets does.

  Background:
    Given an auth server for the domain "fog" that knows "glenda" with "glenda-pw" and "bootes" with "bootes-pw"

  @DP9IK_CLIENT_001
  Scenario: The client authenticates to a dp9ik server and both hold the same secret
    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw"
    When "glenda" authenticates to it with the password "glenda-pw"
    Then the ticket names "glenda" as the client's and the server's user, as authsrv's mkticket does
    And the server reports the client "glenda"
    And the client and the server hold the same 256-byte secret
    And TLS-PSK keyed by that secret carries data both ways

  @DP9IK_CLIENT_002
  Scenario: The tickets are asked for as getastickets asks for them
    Given a scripted dp9ik server for "fog" whose authid is "bootes" with "bootes-pw"
    When "glenda" authenticates to it with the password "glenda-pw"
    Then the auth server was asked AuthPAK and then AuthTreq on one call
    And each request names the authid "bootes", the domain "fog", and "glenda" as hostid and uid
    And each request carries the server's challenge
    And the password was asked for once, as "glenda@fog dp9ik password"

  @DP9IK_CLIENT_003
  Scenario Outline: The client takes dp9ik from the offer and names its domain
    Given a scripted server that offers "<offer>"
    When "glenda" authenticates to it with the password "glenda-pw"
    Then the client chose "<choice>"
    And the client read "OK" after its choice: <ok>
    And the client wrote its challenge next

    Examples:
      | offer                        | choice      | ok  |
      | dp9ik@fog                    | dp9ik fog   | no  |
      | v.2 dp9ik@fog                | dp9ik fog   | yes |
      | v.2 p9sk1@fog dp9ik@fog      | dp9ik fog   | yes |
      | p9sk1@fog dp9ik@other        | dp9ik other | no  |
      | dp9ik@fog then-anything      | dp9ik fog   | no  |
      | @fog dp9ik@fog               | dp9ik fog   | no  |

  @DP9IK_CLIENT_004
  Scenario Outline: An offer the client cannot take ends it before its challenge
    Given a scripted server that offers "<offer>"
    When "glenda" authenticates to it with the password "glenda-pw"
    Then authentication fails with "<error>"
    And the client wrote no challenge

    Examples:
      | offer                   | error                              |
      | p9sk1@fog               | server did not offer dp9ik         |
      | v.2 p9sk1@fog           | server did not offer dp9ik         |
      | dp9ik                   | bad p9any domain                   |
      | p9sk1 dp9ik@fog         | bad p9any domain                   |

  @DP9IK_CLIENT_015
  Scenario Outline: An offer is read up to drawterm's 1024 bytes, its NUL among them
    Given a scripted server that offers "dp9ik@" and a domain making the offer <length> bytes
    When "glenda" authenticates to it with the password "glenda-pw"
    Then the client wrote its challenge: <challenge>
    And authentication fails with "<error>"

    Examples:
      | length | challenge | error                                         |
      | 1023   | yes       | cannot read ticket request                    |
      | 1024   | no        | cannot read p9any negotiation: too long       |

  @DP9IK_CLIENT_005
  Scenario: A v.2 offer must be answered with OK
    Given a scripted server that offers "v.2 dp9ik@fog" and answers the choice with "NO"
    When "glenda" authenticates to it with the password "glenda-pw"
    Then authentication fails with "did not get OK in p9any: got NO"
    And the client wrote no challenge

  @DP9IK_CLIENT_006
  Scenario: A server that hangs up during p9any ends the client
    Given a scripted server that hangs up after offering "v.2 dp9ik@fog"
    When "glenda" authenticates to it with the password "glenda-pw"
    Then authentication fails with "cannot read OK in p9any: hung up"

  @DP9IK_CLIENT_007
  Scenario: A wrong password is asked for again, and the right one then authenticates
    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw"
    When "glenda" authenticates to it with the passwords "wrong-pw" and then "glenda-pw"
    Then the ticket names "glenda" as the client's and the server's user, as authsrv's mkticket does
    And the client and the server hold the same 256-byte secret
    And the password was asked for twice, the second time after a mismatch

  @DP9IK_CLIENT_008
  Scenario: With no password the client ends
    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw"
    When "glenda" authenticates to it with no password
    Then authentication fails with "no password"

  @DP9IK_CLIENT_009
  Scenario: Without the auth server, the server's own authid makes the tickets itself
    Given a scripted dp9ik server for "fog" whose authid is "bootes" with "bootes-pw"
    And the auth server cannot be dialled
    When "bootes" authenticates to it with the password "bootes-pw"
    Then the ticket names "bootes" as the client's and the server's user, as authsrv's mkticket does
    And the server's ticket names "bootes" as both users and holds a key that is not all zeros
    And the client and the server hold the same 256-byte secret

  @DP9IK_CLIENT_010
  Scenario Outline: Without tickets from the auth server, any other user fails
    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw"
    And <trouble>
    When "glenda" authenticates to it with the password "glenda-pw"
    Then authentication fails with "<error>"

    Examples:
      | trouble                                          | error                                          |
      | the auth server cannot be dialled                | cannot get auth tickets: connection refused    |
      | the auth server refuses with "no such user"      | cannot get auth tickets: remote: no such user  |
      | the auth server hangs up on the ticket request   | cannot get auth tickets: AS protocol botch     |
      | the auth server hangs up halfway through its AuthPAK values | cannot get auth tickets: AS protocol botch |
      | the auth server hangs up halfway through the tickets | cannot get auth tickets: AS protocol botch |

  @DP9IK_CLIENT_016
  Scenario Outline: An AuthOKvar answer is read as _asrdresp reads it, its count as atoi reads it
    A count short of both values leaves the rest zero, so the client's key is not the auth
    server's, its ticket does not open, and the password is asked for again; there is no other.

    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw"
    And the auth server answers AuthPAK with AuthOKvar "<count>" and <sent> bytes of its values
    When "glenda" authenticates to it with the password "glenda-pw"
    Then the outcome is "<outcome>"

    Examples:
      | count  | sent | outcome                                              |
      | 00112  | 112  | authenticated                                        |
      | \u0020 112 | 112 | authenticated                                     |
      | \t0112 | 112  | authenticated                                        |
      | +0112  | 112  | authenticated                                        |
      | 112xy  | 112  | authenticated                                        |
      | -0112  | 0    | cannot get auth tickets: AS protocol botch           |
      | x0112  | 0    | cannot get auth tickets: AS protocol botch           |
      | \u0020\u0020\u0020\u0020\u0020 | 0 | cannot get auth tickets: AS protocol botch |
      | 00000  | 0    | cannot get auth tickets: AS protocol botch           |
      | 00113  | 0    | cannot get auth tickets: AS protocol botch           |
      | 00112  | 50   | cannot get auth tickets: AS protocol botch           |
      | 0011   | 0    | cannot get auth tickets: AS protocol botch           |
      | 0009x  | 9    | no password                                          |
      | 00056  | 56   | no password                                          |

  @DP9IK_CLIENT_011
  Scenario Outline: A server that answers with its error rather than its authenticator is reported
    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw" that answers the proof with "<answer>"
    When "glenda" authenticates to it with the password "glenda-pw"
    Then authentication fails with "<error>"

    Examples:
      | answer                       | error                                         |
      | cpu: no such user            | server says: cpu: no such user                |
      | cpu: followed by 70 y        | server says: cpu: followed by 70 y            |
      | cpu: followed by 2000 y      | server says: cpu: followed by 1019 y          |
      | cpu:                         | cannot read authenticator                     |
      |                              | cannot read authenticator                     |

  @DP9IK_CLIENT_012
  Scenario: A server whose authenticator is not of the client's challenge lies
    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw" that answers with an authenticator of another challenge
    When "glenda" authenticates to it with the password "glenda-pw"
    Then authentication fails with "server lies"

  @DP9IK_CLIENT_017
  Scenario: A server whose reply is not an authenticator under the ticket lies
    Given a dp9ik server for "fog" whose authid is "bootes" with "bootes-pw" that answers with 68 bytes that are not an authenticator
    When "glenda" authenticates to it with the password "glenda-pw"
    Then authentication fails with "server lies"

  @DP9IK_CLIENT_013
  Scenario Outline: The client checks its arguments before anything is written
    When the client is started with <argument>
    Then it fails with <error> for "<parameter>"
    And nothing has been written to the server

    Examples:
      | argument                         | error                  | parameter |
      | a null stream                    | an argument-null error | stream    |
      | a null configuration             | an argument-null error | config    |
      | a blank user                     | an argument error      | User      |
      | a user of 28 bytes               | an argument error      | User      |
      | no password source               | an argument-null error | Password  |
      | no way to dial the auth server   | an argument-null error | DialAuthServer |

  @DP9IK_CLIENT_014
  Scenario: A user name a ticket cannot hold is refused with the most it holds
    When the client is started with a user of 28 bytes
    Then it fails with an argument error for "User"
    And its message starts "A user name holds at most 27 bytes."
